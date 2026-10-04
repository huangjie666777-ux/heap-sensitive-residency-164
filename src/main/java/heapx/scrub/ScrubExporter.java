package heapx.scrub;

import heapx.parse.AnalysisException;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Produces a scrubbed copy of the original dump: the file is copied
 * byte-for-byte first, then only the hit payload ranges are zeroed in
 * place. Ranges are merged per array, so a shared array is rewritten
 * exactly once (every holder then reads the scrubbed value) and
 * overlapping hits are never counted twice. Object ids, roots,
 * references, types, lengths and all other records keep their bytes.
 */
public final class ScrubExporter {
    private ScrubExporter() {}

    public record Stats(int modifiedArrays, long scrubbedBytes) {}

    public static Stats export(Path source, Path target, List<ArrayRegion> regions,
                               List<ScanHit> hits) throws AnalysisException {
        Map<Long, ArrayRegion> byId = new HashMap<>();
        for (ArrayRegion r : regions) byId.put(r.objectId(), r);
        Map<ArrayRegion, List<long[]>> rangesPerArray = new HashMap<>();
        for (ScanHit hit : hits) {
            ArrayRegion region = byId.get(hit.arrayObjectId());
            if (region == null) continue;
            int elemSize = region.elementSize();
            long start = region.dataOffset() + (long) hit.elementOffset() * elemSize;
            long end = start + (long) hit.elementLength() * elemSize;
            rangesPerArray.computeIfAbsent(region, k -> new ArrayList<>())
                    .add(new long[]{start, end});
        }
        try {
            Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
            long scrubbed = 0;
            try (RandomAccessFile raf = new RandomAccessFile(target.toFile(), "rw")) {
                byte[] zeros = new byte[1 << 16];
                for (List<long[]> ranges : rangesPerArray.values()) {
                    for (long[] merged : merge(ranges)) {
                        raf.seek(merged[0]);
                        long remaining = merged[1] - merged[0];
                        scrubbed += remaining;
                        while (remaining > 0) {
                            int chunk = (int) Math.min(remaining, zeros.length);
                            raf.write(zeros, 0, chunk);
                            remaining -= chunk;
                        }
                    }
                }
            }
            return new Stats(rangesPerArray.size(), scrubbed);
        } catch (IOException e) {
            try { Files.deleteIfExists(target); } catch (IOException ignored) {}
            throw new AnalysisException(500, "failed to build scrubbed copy: " + e.getMessage());
        }
    }

    /** Union of [start, end) byte ranges; overlapping or adjacent ranges merge. */
    static List<long[]> merge(List<long[]> ranges) {
        List<long[]> sorted = new ArrayList<>(ranges);
        sorted.sort(Comparator.comparingLong(r -> r[0]));
        List<long[]> merged = new ArrayList<>();
        for (long[] r : sorted) {
            if (!merged.isEmpty() && r[0] <= merged.get(merged.size() - 1)[1]) {
                long[] last = merged.get(merged.size() - 1);
                last[1] = Math.max(last[1], r[1]);
            } else {
                merged.add(new long[]{r[0], r[1]});
            }
        }
        return merged;
    }
}
