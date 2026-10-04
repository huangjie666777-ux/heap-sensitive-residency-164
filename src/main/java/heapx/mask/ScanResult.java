package heapx.mask;

import heapx.graph.PathFinder;

import java.util.List;

/**
 * Immutable outcome of one sensitive-value scan, bound to a scanId.
 * Holds every hit (all positions, overlaps, multi-rule, unreachable
 * arrays included) plus the array payload locations needed to mask a
 * copy later. Rule plaintext is never stored here.
 */
public final class ScanResult {
    public record Hit(String ruleId, long arrayId, String arrayType,
                      int elementStart, int length, boolean reachable,
                      List<PathFinder.Step> path) {}

    public final String scanId;
    public final String analysisId;
    public final int ruleCount;
    public final List<Hit> hits;
    public final List<HprofArrays.ArrayPayload> arrays;
    public final long createdAtMillis;

    public ScanResult(String scanId, String analysisId, int ruleCount,
                      List<Hit> hits, List<HprofArrays.ArrayPayload> arrays) {
        this.scanId = scanId;
        this.analysisId = analysisId;
        this.ruleCount = ruleCount;
        this.hits = List.copyOf(hits);
        this.arrays = List.copyOf(arrays);
        this.createdAtMillis = System.currentTimeMillis();
    }

    public int hitCount() { return hits.size(); }
}
