package heapx.service;

import heapx.graph.DominatorAnalysis;
import heapx.graph.PathFinder;
import heapx.model.HeapModel;
import heapx.parse.AnalysisException;
import heapx.parse.HprofParser;
import heapx.scrub.ArrayRegion;
import heapx.scrub.HprofLayout;
import heapx.scrub.PayloadScanner;
import heapx.scrub.ScanHit;
import heapx.scrub.ScanRecord;
import heapx.scrub.ScrubExporter;
import heapx.scrub.ScrubRule;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Parses uploads, runs dominator analysis and hands out independent
 * analysis ids. Failed or over-limit uploads publish nothing. Concurrent
 * uploads/queries are isolated; delete frees all resources. No persistence.
 */
public final class AnalysisService {
    public static final long MAX_BYTES = 100L * 1024 * 1024;
    public static final long MAX_OBJECTS =
            Long.parseLong(System.getenv().getOrDefault("HEAPX_MAX_OBJECTS", "50000"));
    public static final long MAX_EDGES =
            Long.parseLong(System.getenv().getOrDefault("HEAPX_MAX_EDGES", "200000"));

    private static final class TooLargeException extends RuntimeException {}

    private final Map<String, Analysis> analyses = new ConcurrentHashMap<>();
    private final HprofParser parser = new HprofParser(MAX_OBJECTS, MAX_EDGES);

    public Analysis analyze(InputStream in) throws AnalysisException {
        Path dir = null;
        boolean published = false;
        try {
            dir = Files.createTempDirectory("heapx-analysis-");
            Path dump = dir.resolve("dump.hprof");
            copyBounded(in, dump);
            HeapModel model = parser.parse(dump.toFile());
            DominatorAnalysis da = DominatorAnalysis.compute(model);
            List<ArrayRegion> arrays = HprofLayout.locateArrays(dump);
            Analysis a = new Analysis(UUID.randomUUID().toString(), model, da,
                    dir, dump, List.copyOf(arrays));
            analyses.put(a.id, a);
            published = true;
            return a;
        } catch (TooLargeException e) {
            throw new AnalysisException(422,
                    "file limit exceeded: upload is larger than " + MAX_BYTES + " bytes (100 MiB)");
        } catch (IOException e) {
            throw new AnalysisException(400, "failed to store upload: " + e.getMessage());
        } finally {
            if (!published && dir != null) {
                deleteTree(dir);
            }
        }
    }

    private static void copyBounded(InputStream in, Path target) throws IOException {
        long total = 0;
        byte[] buf = new byte[1 << 16];
        try (var out = Files.newOutputStream(target)) {
            int r;
            while ((r = in.read(buf)) != -1) {
                total += r;
                if (total > MAX_BYTES) throw new TooLargeException();
                out.write(buf, 0, r);
            }
        }
    }

    public Analysis get(String id) { return analyses.get(id); }

    public boolean delete(String id) {
        Analysis a = analyses.remove(id);
        if (a == null) return false;
        deleteTree(a.workDir);
        return true;
    }

    public int count() { return analyses.size(); }

    /**
     * Runs a sensitive-value scan over the byte[]/char[] payloads of the
     * kept dump and publishes the immutable result under a new scanId.
     * Rule literals are never logged or echoed.
     */
    public ScanRecord scan(Analysis a, List<ScrubRule> rules) throws AnalysisException {
        List<PayloadScanner.RawMatch> raw =
                PayloadScanner.scan(a.sourceFile, a.arrayRegions, rules);
        HeapModel g = a.model;
        List<ScanHit> hits = new ArrayList<>(raw.size());
        for (PayloadScanner.RawMatch m : raw) {
            Integer idx = g.indexOf(m.objectId());
            boolean reachable = idx != null && !a.dominators.unreachable[idx];
            List<PathFinder.Step> path = reachable
                    ? PathFinder.shortestPathFromRoot(g, a.dominators, idx)
                    : null;
            hits.add(new ScanHit(m.ruleId(), m.objectId(), m.charArray(),
                    m.elementOffset(), m.elementLength(), reachable, path));
        }
        ScanRecord record = new ScanRecord(UUID.randomUUID().toString(),
                rules.size(), hits, System.currentTimeMillis());
        a.scans.put(record.scanId(), record);
        return record;
    }

    public ScanRecord scanOf(Analysis a, String scanId) {
        return a.scans.get(scanId);
    }

    /**
     * Builds the scrubbed copy for a scan inside the analysis work dir.
     * On any failure the partial copy is removed and nothing is published.
     */
    public Export export(Analysis a, ScanRecord scan) throws AnalysisException {
        Path out = a.workDir.resolve("export-" + scan.scanId() + ".hprof");
        ScrubExporter.Stats stats =
                ScrubExporter.export(a.sourceFile, out, a.arrayRegions, scan.hits());
        return new Export(out, stats);
    }

    /** Removes a previously built export copy (called after it is served). */
    public void cleanup(Export export) {
        try { Files.deleteIfExists(export.file()); } catch (IOException ignored) {}
    }

    public record Export(Path file, ScrubExporter.Stats stats) {}

    private static void deleteTree(Path dir) {
        try (var stream = Files.walk(dir)) {
            stream.sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {}
    }
}
