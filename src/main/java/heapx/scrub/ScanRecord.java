package heapx.scrub;

import java.util.List;

/** Immutable, id-bound result of one sensitive-value scan. */
public record ScanRecord(String scanId, int ruleCount, List<ScanHit> hits,
                         long createdAtMillis) {
    public ScanRecord {
        hits = List.copyOf(hits);
    }
}
