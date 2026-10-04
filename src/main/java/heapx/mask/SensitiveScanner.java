package heapx.mask;

import heapx.graph.DominatorAnalysis;
import heapx.graph.PathFinder;
import heapx.model.HeapModel;
import heapx.parse.AnalysisException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Validates sensitive-value rules and scans byte[]/char[] payloads for
 * exact ASCII matches. Matching is per array (never across arrays),
 * byte-exact for byte[] and char-exact (high byte zero) for char[];
 * other encodings are not recognised. All positions are enumerated,
 * including overlapping matches and multiple rules on one array.
 */
public final class SensitiveScanner {
    private SensitiveScanner() {}

    public static final int MIN_RULES = 1;
    public static final int MAX_RULES = 16;
    public static final int MIN_TEXT = 4;
    public static final int MAX_TEXT = 128;
    public static final int MAX_RULE_ID = 64;

    /** Raw rule as submitted over HTTP (plaintext kept out of responses/logs). */
    public record RuleInput(String id, String text) {}

    /** Validated rule; ascii holds the printable-ASCII bytes of the text. */
    public record Rule(String id, byte[] ascii) {}

    public static List<Rule> validate(List<RuleInput> inputs) throws AnalysisException {
        if (inputs == null || inputs.size() < MIN_RULES || inputs.size() > MAX_RULES) {
            throw new AnalysisException(400, "rules must contain between "
                    + MIN_RULES + " and " + MAX_RULES + " entries");
        }
        List<Rule> rules = new ArrayList<>(inputs.size());
        Set<String> ids = new HashSet<>();
        Set<String> texts = new HashSet<>();
        for (RuleInput in : inputs) {
            if (in == null || in.id() == null || in.id().isBlank()
                    || in.id().length() > MAX_RULE_ID || !printable(in.id())) {
                throw new AnalysisException(400, "each rule needs a non-blank printable ASCII id"
                        + " of at most " + MAX_RULE_ID + " characters");
            }
            if (!ids.add(in.id())) {
                throw new AnalysisException(400, "duplicate rule id: " + in.id());
            }
            if (in.text() == null || in.text().length() < MIN_TEXT
                    || in.text().length() > MAX_TEXT || !printable(in.text())) {
                throw new AnalysisException(400, "rule " + in.id() + ": text must be "
                        + MIN_TEXT + "-" + MAX_TEXT + " printable ASCII characters");
            }
            if (!texts.add(in.text())) {
                throw new AnalysisException(400, "duplicate rule text for rule id: " + in.id());
            }
            rules.add(new Rule(in.id(), in.text().getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        }
        return rules;
    }

    private static boolean printable(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c > 0x7E) return false;
        }
        return true;
    }

    public static ScanResult scan(String scanId, String analysisId, byte[] file,
                                  List<HprofArrays.ArrayPayload> arrays, List<Rule> rules,
                                  HeapModel g, DominatorAnalysis da) {
        List<ScanResult.Hit> hits = new ArrayList<>();
        for (Rule rule : rules) {
            byte[] needle = rule.ascii();
            for (HprofArrays.ArrayPayload ap : arrays) {
                int n = ap.elements();
                int m = needle.length;
                if (m > n) continue;
                boolean charArray = ap.charArray();
                long base = ap.dataOffset();
                for (int i = 0; i + m <= n; i++) {
                    if (matches(file, base, charArray, i, needle)) {
                        hits.add(makeHit(rule.id(), ap, i, m, g, da));
                    }
                }
            }
        }
        return new ScanResult(scanId, analysisId, rules.size(), hits, arrays);
    }

    private static boolean matches(byte[] f, long base, boolean charArray, int start, byte[] needle) {
        for (int j = 0; j < needle.length; j++) {
            if (charArray) {
                long off = base + 2L * (start + j);
                if (f[(int) off] != 0 || f[(int) off + 1] != needle[j]) return false;
            } else {
                if (f[(int) (base + start + j)] != needle[j]) return false;
            }
        }
        return true;
    }

    private static ScanResult.Hit makeHit(String ruleId, HprofArrays.ArrayPayload ap,
                                          int elementStart, int length,
                                          HeapModel g, DominatorAnalysis da) {
        Integer idx = g.indexOf(ap.objectId());
        boolean reachable = idx != null && !da.unreachable[idx];
        List<PathFinder.Step> path = reachable
                ? PathFinder.shortestPathFromRoot(g, da, idx) : null;
        return new ScanResult.Hit(ruleId, ap.objectId(),
                ap.charArray() ? "char[]" : "byte[]",
                elementStart, length, reachable, path);
    }
}
