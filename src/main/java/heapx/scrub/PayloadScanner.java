package heapx.scrub;

import heapx.parse.AnalysisException;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Exact ASCII matching inside byte[] and char[] payloads only. Every
 * occurrence is enumerated, including overlapping ones and several rules
 * hitting the same array. Matching never crosses array boundaries and
 * no other encoding is recognised: a char element matches only when its
 * 16-bit value equals the ASCII byte (big-endian, high byte zero).
 */
public final class PayloadScanner {
    private PayloadScanner() {}

    public record RawMatch(String ruleId, long objectId, boolean charArray,
                           int elementOffset, int elementLength) {}

    public static List<RawMatch> scan(Path file, List<ArrayRegion> regions,
                                      List<ScrubRule> rules) throws AnalysisException {
        List<RawMatch> matches = new ArrayList<>();
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            for (ArrayRegion region : regions) {
                int byteLen = region.elementCount() * region.elementSize();
                if (byteLen == 0) continue;
                byte[] data = new byte[byteLen];
                raf.seek(region.dataOffset());
                raf.readFully(data);
                for (ScrubRule rule : rules) {
                    byte[] p = rule.pattern();
                    if (p.length > region.elementCount()) continue;
                    if (region.charArray()) {
                        scanChars(data, p, region, rule, matches);
                    } else {
                        scanBytes(data, p, region, rule, matches);
                    }
                }
            }
        } catch (IOException e) {
            throw new AnalysisException(500, "failed to scan dump: " + e.getMessage());
        }
        return matches;
    }

    private static void scanBytes(byte[] data, byte[] p, ArrayRegion region,
                                  ScrubRule rule, List<RawMatch> out) {
        int last = data.length - p.length;
        for (int i = 0; i <= last; i++) {
            if (data[i] != p[0]) continue;
            int j = 1;
            while (j < p.length && data[i + j] == p[j]) j++;
            if (j == p.length) {
                out.add(new RawMatch(rule.id(), region.objectId(), false, i, p.length));
            }
        }
    }

    private static void scanChars(byte[] data, byte[] p, ArrayRegion region,
                                  ScrubRule rule, List<RawMatch> out) {
        int elements = data.length / 2;
        int last = elements - p.length;
        for (int i = 0; i <= last; i++) {
            if (data[2 * i] != 0 || data[2 * i + 1] != p[0]) continue;
            int j = 1;
            while (j < p.length && data[2 * (i + j)] == 0 && data[2 * (i + j) + 1] == p[j]) j++;
            if (j == p.length) {
                out.add(new RawMatch(rule.id(), region.objectId(), true, i, p.length));
            }
        }
    }
}
