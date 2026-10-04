package heapx;

import heapx.http.Api;
import heapx.service.AnalysisService;
import io.javalin.Javalin;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Sensitive-value scans and scrubbed exports over real HPROF files:
 * overlapping/multi-rule hits, char[] and unreachable arrays, union
 * zeroing with exact byte counts, 8-byte ids, segmented heaps,
 * re-analysis of the scrubbed copy and delete cleanup.
 */
class ScrubTest {

    private static final String SECRET = "s3cret-token";          // 12 chars
    private static final String OVERLAP = "ababa";                // hits at 2 and 4 below

    /** Dump with reachable/unreachable byte[] and char[] payloads. */
    static Path buildDump(Path dir, int idSize, boolean segmented) throws Exception {
        HprofWriter w = new HprofWriter(idSize);
        w.defineClass(100, "demo.Holder", 0)
                .staticRef("cache", 1)
                .staticRef("shared", 20);
        w.defineClass(101, "demo.Box", 0)
                .field("data", HprofWriter.T_OBJECT)
                .field("more", HprofWriter.T_OBJECT);
        w.defineClass(110, "byte[]", 0);
        w.defineClass(111, "char[]", 0);

        w.instance(1, 101, 20, 21);                 // static root; holds two arrays
        // byte[]: overlapping hits of "ababa" at elements 2 and 4, secret at 12
        w.byteArray(20, ("xxabababaxxx" + SECRET + "zz").getBytes("US-ASCII"));
        w.charArray(21, ("pin=" + SECRET + ";;").toCharArray());  // shared: two holders
        w.byteArray(22, ("dead:" + SECRET).getBytes("US-ASCII")); // unreachable
        w.charArray(23, "nothing-here-but-us-chars".toCharArray()); // unreachable, no hit
        return w.write(dir.resolve("scrub.hprof"), segmented);
    }

    // ---------- service-level ----------

    @Test
    void scanFindsOverlappingMultiRuleAndUnreachableHits() throws Exception {
        Path dir = Files.createTempDirectory("heapx-scrub");
        Path dump = buildDump(dir, 4, false);
        AnalysisService svc = new AnalysisService();
        heapx.service.Analysis a;
        try (var in = Files.newInputStream(dump)) { a = svc.analyze(in); }

        var rules = heapx.scrub.ScrubRule.validateAll(java.util.List.of(
                new heapx.scrub.ScrubRule.RawRule("tok", SECRET),
                new heapx.scrub.ScrubRule.RawRule("ovl", OVERLAP)));
        var rec = svc.scan(a, rules);
        assertEquals(2, rec.ruleCount());
        // secret: array 20 @12, array 21 (char) @4, array 22 (unreachable) @5
        // overlap: array 20 @2 and @4
        assertEquals(5, rec.hits().size(), rec.hits().toString());

        var byArrayAndOffset = rec.hits().stream().map(h ->
                h.ruleId() + "@" + h.arrayObjectId() + ":" + h.elementOffset()
                        + (h.charArray() ? "c" : "b") + (h.reachable() ? "R" : "U"))
                .sorted().toList();
        assertEquals(java.util.List.of(
                "ovl@20:2bR", "ovl@20:4bR",
                "tok@20:12bR", "tok@21:4cR", "tok@22:5bU"), byArrayAndOffset);

        // reachable hits carry a root path ending at the array
        for (var h : rec.hits()) {
            if (!h.reachable()) { assertNull(h.path()); continue; }
            assertNotNull(h.path());
            long lastTo = h.path().isEmpty() ? h.arrayObjectId()
                    : h.path().get(h.path().size() - 1).toId();
            assertEquals(h.arrayObjectId(), lastTo);
        }
        // secret lengths in elements
        for (var h : rec.hits()) {
            assertEquals(h.ruleId().equals("tok") ? SECRET.length() : OVERLAP.length(),
                    h.elementLength());
        }
        svc.delete(a.id);
        assertFalse(Files.exists(a.sourceFile), "delete removes the kept source dump");
        assertFalse(Files.exists(a.workDir));
    }

    @Test
    void invalidRulesRejectedWithoutEchoingValues() throws Exception {
        // duplicate id
        expectRuleError(400,
                new heapx.scrub.ScrubRule.RawRule("a", "abcd"),
                new heapx.scrub.ScrubRule.RawRule("a", "wxyz"));
        // too short / too long / non-printable
        expectRuleError(400, new heapx.scrub.ScrubRule.RawRule("a", "abc"));
        expectRuleError(400, new heapx.scrub.ScrubRule.RawRule("a", "x".repeat(129)));
        expectRuleError(400, new heapx.scrub.ScrubRule.RawRule("a", "ab	cdef"));
        expectRuleError(400, new heapx.scrub.ScrubRule.RawRule("a", "secreté"));
        // too few / too many
        expectRuleError(400);
        var many = new heapx.scrub.ScrubRule.RawRule[17];
        for (int i = 0; i < 17; i++) {
            many[i] = new heapx.scrub.ScrubRule.RawRule("r" + i, "value" + i);
        }
        expectRuleError(400, many);
    }

    private static void expectRuleError(int status, heapx.scrub.ScrubRule.RawRule... raw) {
        var e = assertThrows(heapx.parse.AnalysisException.class, () ->
                heapx.scrub.ScrubRule.validateAll(Arrays.asList(raw)));
        assertEquals(status, e.status);
        for (var r : raw) {
            if (r.value() != null) {
                assertFalse(e.getMessage().contains(r.value()),
                        "error must not echo the rule literal");
            }
        }
    }

    @Test
    void exportZeroesUnionOnlyAndStaysReanalyzable() throws Exception {
        Path dir = Files.createTempDirectory("heapx-export");
        Path dump = buildDump(dir, 4, false);
        byte[] original = Files.readAllBytes(dump);
        AnalysisService svc = new AnalysisService();
        heapx.service.Analysis a;
        try (var in = Files.newInputStream(dump)) { a = svc.analyze(in); }
        var rec = svc.scan(a, heapx.scrub.ScrubRule.validateAll(java.util.List.of(
                new heapx.scrub.ScrubRule.RawRule("tok", SECRET),
                new heapx.scrub.ScrubRule.RawRule("ovl", OVERLAP))));

        var export = svc.export(a, rec);
        // arrays 20, 21, 22 modified once each; bytes = union per array:
        // 20: [2,7)+[4,9) merge to [2,9) = 7, plus [12,24) = 12 -> 19;
        // 21: 12 chars = 24 bytes; 22: 12 bytes
        assertEquals(3, export.stats().modifiedArrays());
        assertEquals(19 + 24 + 12, export.stats().scrubbedBytes());

        byte[] scrubbed = Files.readAllBytes(export.file());
        assertEquals(original.length, scrubbed.length);
        boolean[] inRange = new boolean[original.length];
        for (var h : rec.hits()) {
            var region = a.arrayRegions.stream()
                    .filter(r -> r.objectId() == h.arrayObjectId()).findFirst().orElseThrow();
            int elem = region.elementSize();
            long s = region.dataOffset() + (long) h.elementOffset() * elem;
            long e = s + (long) h.elementLength() * elem;
            for (long i = s; i < e; i++) inRange[(int) i] = true;
        }
        for (int i = 0; i < original.length; i++) {
            if (inRange[i]) {
                assertEquals(0, scrubbed[i], "hit ranges must be zeroed");
            } else {
                assertEquals(original[i], scrubbed[i],
                        "bytes outside hit ranges must be untouched at " + i);
            }
        }
        // the secret is gone everywhere, including the unreachable array
        String asLatin1 = new String(scrubbed, "ISO-8859-1");
        assertFalse(asLatin1.contains(SECRET));
        assertFalse(asLatin1.contains("ababa"));
        // untouched payload survives: char[] 23 kept its big-endian chars
        assertTrue(asLatin1.contains("n\0o\0t\0h\0i\0n\0g"));

        // the scrubbed copy re-analyzes with identical shape
        heapx.service.Analysis b;
        try (var in = Files.newInputStream(export.file())) { b = svc.analyze(in); }
        assertEquals(a.model.nodeCount(), b.model.nodeCount());
        assertEquals(a.model.edgeCount(), b.model.edgeCount());
        assertArrayEquals(a.dominators.retained, b.dominators.retained);
        // and a fresh scan on the copy finds nothing
        var rec2 = svc.scan(b, heapx.scrub.ScrubRule.validateAll(java.util.List.of(
                new heapx.scrub.ScrubRule.RawRule("tok", SECRET))));
        assertEquals(0, rec2.hits().size());
        svc.cleanup(export);
        assertFalse(Files.exists(export.file()));
        svc.delete(a.id);
        svc.delete(b.id);
    }

    @Test
    void eightByteIdsAndSegmentedHeap() throws Exception {
        Path dir = Files.createTempDirectory("heapx-seg");
        Path dump = buildDump(dir, 8, true);
        AnalysisService svc = new AnalysisService();
        heapx.service.Analysis a;
        try (var in = Files.newInputStream(dump)) { a = svc.analyze(in); }
        assertEquals(5, a.model.nodeCount());
        var rec = svc.scan(a, heapx.scrub.ScrubRule.validateAll(java.util.List.of(
                new heapx.scrub.ScrubRule.RawRule("tok", SECRET))));
        assertEquals(3, rec.hits().size());
        var export = svc.export(a, rec);
        assertEquals(3, export.stats().modifiedArrays());
        heapx.service.Analysis b;
        try (var in = Files.newInputStream(export.file())) { b = svc.analyze(in); }
        assertEquals(5, b.model.nodeCount());
        svc.cleanup(export);
        svc.delete(a.id);
        svc.delete(b.id);
    }

    // ---------- HTTP ----------

    @Test
    void httpScanExportReanalyzeAndDelete() throws Exception {
        Path dump = buildDump(Files.createTempDirectory("heapx-scrub-http"), 4, false);
        Javalin app = Api.create(new AnalysisService(), 0);
        String base = "http://localhost:" + app.port();
        HttpClient http = HttpClient.newHttpClient();
        try {
            String analysisId = upload(http, base, dump);

            // invalid rule: value too short, response must not echo the value
            HttpResponse<String> bad = post(http, base + "/api/analyses/" + analysisId + "/scans",
                    "{\"rules\":[{\"id\":\"x\",\"value\":\"abc\"}]}");
            assertEquals(400, bad.statusCode(), bad.body());
            assertFalse(bad.body().contains("abc"), bad.body());

            // duplicate rule id rejected
            HttpResponse<String> dup = post(http, base + "/api/analyses/" + analysisId + "/scans",
                    "{\"rules\":[{\"id\":\"x\",\"value\":\"abcd\"},"
                            + "{\"id\":\"x\",\"value\":\"wxyz\"}]}");
            assertEquals(400, dup.statusCode(), dup.body());

            // valid scan: never echoes the literal
            HttpResponse<String> scan = post(http, base + "/api/analyses/" + analysisId + "/scans",
                    "{\"rules\":[{\"id\":\"tok\",\"value\":\"" + SECRET + "\"}]}");
            assertEquals(201, scan.statusCode(), scan.body());
            assertFalse(scan.body().contains(SECRET), scan.body());
            assertTrue(scan.body().contains("\"hitCount\":3"), scan.body());
            assertTrue(scan.body().contains("\"arrayType\":\"char[]\""), scan.body());
            assertTrue(scan.body().contains("\"reachable\":false"), scan.body());
            assertTrue(scan.body().contains("demo.Box#more"), scan.body()); // root path
            String scanId = scan.body().replaceAll(".*\"scanId\":\"([^\"]+)\".*", "$1");

            // scan result is re-fetchable and immutable
            HttpResponse<String> again = http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + analysisId + "/scans/" + scanId)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, again.statusCode());
            assertEquals(scan.body(), again.body());

            // export the scrubbed copy
            HttpResponse<byte[]> exp = http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + analysisId + "/scans/" + scanId + "/export"))
                    .GET().build(), HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, exp.statusCode());
            assertEquals("3", exp.headers().firstValue("X-Scrubbed-Arrays").orElseThrow());
            assertEquals("48", exp.headers().firstValue("X-Scrubbed-Bytes").orElseThrow());
            Path copy = Files.createTempDirectory("heapx-dl").resolve("copy.hprof");
            Files.write(copy, exp.body());

            // the copy re-uploads: same ranking shape, secret gone
            String id2 = upload(http, base, copy);
            HttpResponse<String> rank = http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + id2 + "/retained?limit=5")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, rank.statusCode(), rank.body());
            HttpResponse<String> rescan = post(http,
                    base + "/api/analyses/" + id2 + "/scans",
                    "{\"rules\":[{\"id\":\"tok\",\"value\":\"" + SECRET + "\"}]}");
            assertEquals(201, rescan.statusCode(), rescan.body());
            assertTrue(rescan.body().contains("\"hitCount\":0"), rescan.body());

            // delete removes everything; scan and export are then rejected
            assertEquals(200, http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + analysisId)).DELETE().build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode());
            HttpResponse<String> gone = post(http,
                    base + "/api/analyses/" + analysisId + "/scans",
                    "{\"rules\":[{\"id\":\"tok\",\"value\":\"" + SECRET + "\"}]}");
            assertEquals(404, gone.statusCode());
            HttpResponse<String> goneExport = http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + analysisId + "/scans/" + scanId + "/export"))
                    .GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(404, goneExport.statusCode());
            // unknown scan id on a live analysis -> 404
            HttpResponse<String> noScan = http.send(HttpRequest.newBuilder(URI.create(
                    base + "/api/analyses/" + id2 + "/scans/nope")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(404, noScan.statusCode());
        } finally {
            app.stop();
        }
    }

    private static String upload(HttpClient http, String base, Path dump) throws Exception {
        HttpResponse<String> up = http.send(HttpRequest.newBuilder(URI.create(base + "/api/analyses"))
                .header("Content-Type", "application/octet-stream")
                .POST(HttpRequest.BodyPublishers.ofFile(dump)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(201, up.statusCode(), up.body());
        return up.body().replaceAll(".*\"analysisId\":\"([^\"]+)\".*", "$1");
    }

    private static HttpResponse<String> post(HttpClient http, String url, String json)
            throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json)).build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
