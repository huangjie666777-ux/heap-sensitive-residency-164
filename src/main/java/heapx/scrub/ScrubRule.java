package heapx.scrub;

import heapx.parse.AnalysisException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * One sensitive-value scan rule: a unique caller-chosen rule id plus the
 * 4-128 character printable-ASCII literal to find. The literal is never
 * echoed back in responses, error messages or logs.
 */
public record ScrubRule(String id, byte[] pattern) {
    public static final int MIN_RULES = 1;
    public static final int MAX_RULES = 16;
    public static final int MIN_LEN = 4;
    public static final int MAX_LEN = 128;

    public static ScrubRule of(String id, String value) throws AnalysisException {
        if (id == null || id.isEmpty() || id.length() > 64 || !isPrintableAscii(id)) {
            throw new AnalysisException(400,
                    "rule id must be 1-64 printable ASCII characters");
        }
        if (value == null || value.length() < MIN_LEN || value.length() > MAX_LEN
                || !isPrintableAscii(value)) {
            throw new AnalysisException(400, "rule '" + id
                    + "': value must be " + MIN_LEN + "-" + MAX_LEN
                    + " printable ASCII characters");
        }
        return new ScrubRule(id, value.getBytes(StandardCharsets.US_ASCII));
    }

    public static List<ScrubRule> validateAll(List<RawRule> raw) throws AnalysisException {
        if (raw == null || raw.size() < MIN_RULES || raw.size() > MAX_RULES) {
            throw new AnalysisException(400, "submit " + MIN_RULES + "-" + MAX_RULES
                    + " rules, got " + (raw == null ? 0 : raw.size()));
        }
        Set<String> seen = new HashSet<>();
        List<ScrubRule> rules = new ArrayList<>(raw.size());
        for (RawRule r : raw) {
            ScrubRule rule = ScrubRule.of(r.id(), r.value());
            if (!seen.add(rule.id())) {
                throw new AnalysisException(400, "duplicate rule id: " + rule.id());
            }
            rules.add(rule);
        }
        return rules;
    }

    private static boolean isPrintableAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c > 0x7E) return false;
        }
        return true;
    }

    /** Unvalidated rule as decoded from the request body. */
    public record RawRule(String id, String value) {}
}
