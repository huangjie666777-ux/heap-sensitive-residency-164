package heapx.mask;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Produces a masked copy of the original HPROF bytes: the union of all
 * hit intervals inside byte[]/char[] payloads is zeroed, everything else
 * (object ids, roots, references, types, lengths, class names, all other
 * records) is copied byte-for-byte. Shared arrays are zeroed once; every
 * holder then reads the masked value. Overlapping intervals are merged,
 * so rewritten bytes are never double counted.
 */
public final class MaskExporter {
    private MaskExporter() {}

    public record Masked(byte[] data, int arraysModified, long bytesMasked) {}

    public static Masked apply(byte[] source, ScanResult scan) {
        Map<Long, HprofArrays.ArrayPayload> byId = new HashMap<>();
        for (HprofArrays.ArrayPayload ap : scan.arrays) byId.put(ap.objectId(), ap);

        Map<Long, List<long[]>> intervals = new HashMap<>();   // array id -> [start, end) elements
        for (ScanResult.Hit h : scan.hits) {
            intervals.computeIfAbsent(h.arrayId(), k -> new ArrayList<>())
                    .add(new long[]{h.elementStart(), h.elementStart() + h.length()});
        }

        byte[] out = source.clone();
        int arraysModified = 0;
        long bytesMasked = 0;
        for (Map.Entry<Long, List<long[]>> e : intervals.entrySet()) {
            HprofArrays.ArrayPayload ap = byId.get(e.getKey());
            if (ap == null) continue;   // array vanished from the file: nothing to mask
            int elementSize = ap.charArray() ? 2 : 1;
            List<long[]> merged = merge(e.getValue());
            for (long[] iv : merged) {
                long from = ap.dataOffset() + iv[0] * elementSize;
                long to = ap.dataOffset() + iv[1] * elementSize;
                Arrays.fill(out, (int) from, (int) to, (byte) 0);
                bytesMasked += to - from;
            }
            arraysModified++;
        }
        return new Masked(out, arraysModified, bytesMasked);
    }

    private static List<long[]> merge(List<long[]> intervals) {
        intervals.sort((a, b) -> Long.compare(a[0], b[0]));
        List<long[]> merged = new ArrayList<>();
        for (long[] iv : intervals) {
            if (!merged.isEmpty() && iv[0] <= merged.get(merged.size() - 1)[1]) {
                long[] last = merged.get(merged.size() - 1);
                last[1] = Math.max(last[1], iv[1]);
            } else {
                merged.add(new long[]{iv[0], iv[1]});
            }
        }
        return merged;
    }
}
