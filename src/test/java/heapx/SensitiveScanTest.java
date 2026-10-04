package heapx;

import heapx.http.Api;
import heapx.service.AnalysisService;
import io.javalin.Javalin;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SensitiveScanTest {
    static final String SECRET = "SECRET-VALUE-1234";   // 17 chars, in byte[] 20 + unreachable 22
    static final String PIN = "ABCD1234";               // 8 chars, in char[] 21

    /** Dump with reachable/unreachable byte[] and char[] secrets, an
     *  overlapping-match array and two adjacent arrays for the
     *  no-cross-array rule. */
    static Path buildDump(Path dir, int idSize, boolean segmented) throws Exception {
        HprofWriter w = new HprofWriter();
        w.idSize = idSize;
        w.segmented = segmented;
        w.defineClass(200, "demo.Secrets", 0)
                .staticRef("box", 31);
        w.defineClass(210, "byte[]", 0);
        w.defineClass(211, "char[]", 0);
        w.defineClass(212, "demo.Anchor", 0);
        w.defineClass(213, "demo.Box", 0)
                .field("data", HprofWriter.T_OBJECT)
                .field("chars", HprofWriter.T_OBJECT)
                .field("rep", HprofWriter.T_OBJECT)
                .field("left", HprofWriter.T_OBJECT)
                .field("right", HprofWriter.T_OBJECT);
        w.instance(30, 212);            // the reader requires at least one instance dump
        w.jniGlobalRoot(30);
        w.instance(31, 213, 20, 21, 23, 24, 25);
        w.byteArray(20, ("xx" + SECRET + "yy").getBytes(StandardCharsets.US_ASCII));
        w.charArray(21, "code=ABCD1234".toCharArray());
        w.byteArray(22, ("unreachable:" + SECRET).getBytes(StandardCharsets.US_ASCII));
        w.byteArray(23, "aaaaaa".getBytes(StandardCharsets.US_ASCII));
        w.byteArray(24, "abc".getBytes(StandardCharsets.US_ASCII));
        w.byteArray(25, "def".getBytes(StandardCharsets.US_ASCII));
        return w.write(dir.resolve("scan.hprof"));
    }

    static final String RULES = """
            {"rules":[
              {"id":"r1","text":"SECRET-VALUE-1234"},
              {"id":"r2","text":"ABCD1234"},
              {"id":"r3","text":"aaaa"},
              {"id":"r4","text":"cdef"}]}
            """;

    private static HttpResponse<String> post(HttpClient http, String url, String json) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String upload(HttpClient http, String base, Path dump) throws Exception {
        HttpResponse<String> up = http.send(HttpRequest.newBuilder(URI.create(base + "/api/analyses"))
                .header("Content-Type", "application/octet-stream")
                .POST(HttpRequest.BodyPublishers.ofFile(dump)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(201, up.statusCode(), up.body());
        return up.body().replaceAll(".*\"analysisId\"\s*:\s*\"([^\"]+)\".*", "$1");
    }

    @Test
    void scanFindsAllPositionsAndMasksCopy() throws Exception {
        Path dir = Files.createTempDirectory("heapx-scan");
        Path dump = buildDump(dir, 4, false);
        Javalin app = Api.create(new AnalysisService(), 0);
        String base = "http://localhost:" + app.port();
        HttpClient http = HttpClient.newHttpClient();
        try {
            String id = upload(http, base, dump);

            HttpResponse<String> scan = post(http, base + "/api/analyses/" + id + "/scans", RULES);
            assertEquals(201, scan.statusCode(), scan.body());
            String body = scan.body();
            // plaintext never echoed
            assertFalse(body.contains("SECRET"), body);
            assertFalse(body.contains("ABCD"), body);
            String scanId = body.replaceAll(".*\"scanId\"\s*:\s*\"([^\"]+)\".*", "$1");

            // r1: byte[] 0x14 (reachable, element 2) and unreachable 0x16 (element 12)
            assertTrue(body.contains("\"ruleId\":\"r1\""), body);
            assertTrue(body.contains("\"arrayId\":\"0x14\""), body);
            assertTrue(body.contains("\"arrayId\":\"0x16\""), body);
            assertTrue(body.contains("\"reachable\":false"), body);
            // reachable hit carries a root path through demo.Secrets#data
            assertTrue(body.contains("demo.Box#data"), body);
            // r2: char[] 0x15 at element 5, length 8
            assertTrue(body.contains("\"arrayType\":\"char[]\""), body);
            assertTrue(body.contains("\"elementStart\":5"), body);
            // r3: 3 overlapping hits in 0x17 (aaaaaa / aaaa)
            int hits = body.split("\"ruleId\":\"r3\"", -1).length - 1;
            assertEquals(3, hits, body);
            // r4: cdef spans arrays 0x18/0x19 -> never matches across arrays
            assertFalse(body.contains("\"ruleId\":\"r4\""), body);

            // scan result is retrievable and immutable under its scanId
            HttpResponse<String> again = http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + id + "/scans/" + scanId)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, again.statusCode());
            assertEquals(body, again.body());

            // export: masked copy, counts in headers
            HttpResponse<byte[]> exp = http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + id + "/scans/" + scanId + "/export")).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, exp.statusCode());
            // arrays 0x14, 0x15, 0x16, 0x17 -> 4 deduped arrays
            assertEquals("4", exp.headers().firstValue("X-Masked-Arrays").orElseThrow());
            // 17 + 8*2 + 17 + union([0..3],[1..4],[2..5],[3..6])=6 -> 56 bytes
            assertEquals("56", exp.headers().firstValue("X-Masked-Bytes").orElseThrow());
            byte[] masked = exp.body();
            byte[] original = Files.readAllBytes(dump);
            assertEquals(original.length, masked.length);
            assertFalse(new String(masked, StandardCharsets.US_ASCII).contains(SECRET));
            // original dump untouched
            assertTrue(new String(original, StandardCharsets.US_ASCII).contains(SECRET));

            // masked copy re-analyses cleanly: same object count and ranking ids
            Path maskedFile = dir.resolve("masked.hprof");
            Files.write(maskedFile, masked);
            String id2 = upload(http, base, maskedFile);
            HttpResponse<String> rank1 = http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + id + "/retained")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            HttpResponse<String> rank2 = http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + id2 + "/retained")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(rank1.body().replace(id, "AID"), rank2.body().replace(id2, "AID"));
            // rescanning the masked copy finds nothing
            HttpResponse<String> rescan = post(http, base + "/api/analyses/" + id2 + "/scans", RULES);
            assertEquals(201, rescan.statusCode(), rescan.body());
            assertTrue(rescan.body().contains("\"hitCount\":0"), rescan.body());

            // delete removes analysis, scans and the retained source file
            http.send(HttpRequest.newBuilder(URI.create(base + "/api/analyses/" + id))
                    .DELETE().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(404, post(http, base + "/api/analyses/" + id + "/scans", RULES).statusCode());
            assertEquals(404, http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + id + "/scans/" + scanId)).GET().build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(404, http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + id + "/scans/" + scanId + "/export")).GET().build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
        } finally {
            app.stop();
        }
    }

    @Test
    void ruleValidationRejectsBadInput() throws Exception {
        Path dump = buildDump(Files.createTempDirectory("heapx-scanval"), 4, false);
        Javalin app = Api.create(new AnalysisService(), 0);
        String base = "http://localhost:" + app.port();
        HttpClient http = HttpClient.newHttpClient();
        try {
            String id = upload(http, base, dump);
            String url = base + "/api/analyses/" + id + "/scans";
            assertEquals(400, post(http, url, "{}").statusCode());
            assertEquals(400, post(http, url, "{\"rules\":[]}").statusCode());
            StringBuilder many = new StringBuilder("{\"rules\":[");
            for (int i = 0; i < 17; i++) {
                many.append(i > 0 ? "," : "").append("{\"id\":\"r").append(i)
                        .append("\",\"text\":\"text").append(i).append("\"}");
            }
            assertEquals(400, post(http, url, many + "]}").statusCode());
            assertEquals(400, post(http, url,
                    "{\"rules\":[{\"id\":\"a\",\"text\":\"abcd\"},{\"id\":\"a\",\"text\":\"wxyz\"}]}").statusCode());
            assertEquals(400, post(http, url,
                    "{\"rules\":[{\"id\":\"a\",\"text\":\"same\"},{\"id\":\"b\",\"text\":\"same\"}]}").statusCode());
            assertEquals(400, post(http, url, "{\"rules\":[{\"id\":\"a\",\"text\":\"abc\"}]}").statusCode());
            assertEquals(400, post(http, url,
                    "{\"rules\":[{\"id\":\"a\",\"text\":\"" + "x".repeat(129) + "\"}]}").statusCode());
            assertEquals(400, post(http, url, "{\"rules\":[{\"id\":\"a\",\"text\":\"ab\tcd\"}]}").statusCode());
            assertEquals(400, post(http, url, "{\"rules\":[{\"id\":\"a\"}]}").statusCode());
            // rejections publish no scan
            HttpResponse<String> ok = post(http, url,
                    "{\"rules\":[{\"id\":\"a\",\"text\":\"abcd\"}]}");
            assertEquals(201, ok.statusCode(), ok.body());
        } finally {
            app.stop();
        }
    }

    @Test
    void longIdsAndSegmentedDumps() throws Exception {
        Path dir = Files.createTempDirectory("heapx-scan8");
        Javalin app = Api.create(new AnalysisService(), 0);
        String base = "http://localhost:" + app.port();
        HttpClient http = HttpClient.newHttpClient();
        try {
            for (boolean segmented : new boolean[]{false, true}) {
                Path dump = buildDump(dir, 8, segmented);
                String id = upload(http, base, dump);
                HttpResponse<String> scan = post(http, base + "/api/analyses/" + id + "/scans", RULES);
                assertEquals(201, scan.statusCode(), scan.body());
                assertTrue(scan.body().contains("\"arrayId\":\"0x14\""), scan.body());
                assertTrue(scan.body().contains("\"arrayType\":\"char[]\""), scan.body());
                assertTrue(scan.body().contains("\"reachable\":false"), scan.body());
                String scanId = scan.body().replaceAll(".*\"scanId\"\s*:\s*\"([^\"]+)\".*", "$1");
                HttpResponse<byte[]> exp = http.send(HttpRequest.newBuilder(URI.create(
                        base + "/api/analyses/" + id + "/scans/" + scanId + "/export")).GET().build(),
                        HttpResponse.BodyHandlers.ofByteArray());
                assertEquals(200, exp.statusCode());
                assertEquals("4", exp.headers().firstValue("X-Masked-Arrays").orElseThrow());
                assertEquals("56", exp.headers().firstValue("X-Masked-Bytes").orElseThrow());
                http.send(HttpRequest.newBuilder(URI.create(base + "/api/analyses/" + id))
                        .DELETE().build(), HttpResponse.BodyHandlers.ofString());
            }
        } finally {
            app.stop();
        }
    }
}
