package heapx.mask;

import heapx.parse.AnalysisException;

import java.util.ArrayList;
import java.util.List;

/**
 * Locates byte[]/char[] primitive-array payloads inside a raw HPROF file.
 * Walks the record structure (never a whole-file byte search), supports
 * 4- and 8-byte identifiers and segmented heap dumps (HEAP_DUMP_SEGMENT
 * records terminated by HEAP_DUMP_END). Only payload file offsets are
 * reported; every other record is skipped by its declared length, so
 * object ids, roots, references, types and lengths stay untouched.
 */
public final class HprofArrays {
    private HprofArrays() {}

    /** One primitive byte/char array payload located in the dump file. */
    public record ArrayPayload(long objectId, boolean charArray, int elements, long dataOffset) {}

    // HPROF primitive type codes
    private static final int T_OBJECT = 2, T_BOOLEAN = 4, T_CHAR = 5, T_FLOAT = 6,
            T_DOUBLE = 7, T_BYTE = 8, T_SHORT = 9, T_INT = 10, T_LONG = 11;

    public static List<ArrayPayload> locate(byte[] f) throws AnalysisException {
        int p = 0;
        while (p < f.length && f[p] != 0) p++;          // NUL-terminated magic
        if (p >= f.length) throw corrupt("missing format header");
        p++;
        if (p + 12 > f.length) throw corrupt("truncated header");
        int idSize = u4(f, p);
        if (idSize != 4 && idSize != 8) {
            throw corrupt("unsupported identifier size " + idSize);
        }
        p += 4 + 8;                                     // identifier size + timestamp
        List<ArrayPayload> out = new ArrayList<>();
        while (p < f.length) {
            if (p + 9 > f.length) throw corrupt("truncated record header");
            int tag = f[p] & 0xFF;
            long len = u4l(f, p + 5);
            long bodyStart = p + 9L;
            if (bodyStart + len > f.length) throw corrupt("record overruns end of file");
            if (tag == 0x0C || tag == 0x1C) {           // HEAP_DUMP / HEAP_DUMP_SEGMENT
                parseHeapSegment(f, bodyStart, bodyStart + len, idSize, out);
            }                                           // 0x2C HEAP_DUMP_END and all
            p = (int) (bodyStart + len);                // other records: skip by length
        }
        return out;
    }

    private static void parseHeapSegment(byte[] f, long start, long end, int idSize,
                                         List<ArrayPayload> out) throws AnalysisException {
        long p = start;
        while (p < end) {
            int tag = f[(int) p] & 0xFF;
            p++;
            switch (tag) {
                case 0xFF -> p += idSize;                       // ROOT UNKNOWN
                case 0x01 -> p += 2L * idSize;                  // ROOT JNI GLOBAL
                case 0x02, 0x03 -> p += idSize + 8L;            // JNI LOCAL / JAVA FRAME
                case 0x04 -> p += idSize + 4L;                  // ROOT NATIVE STACK
                case 0x05, 0x07 -> p += idSize;                 // STICKY CLASS / MONITOR USED
                case 0x06 -> p += idSize + 4L;                  // ROOT THREAD BLOCK
                case 0x08 -> p += idSize + 8L;                  // ROOT THREAD OBJECT
                case 0x20 -> p = skipClassDump(f, p, idSize);   // CLASS DUMP
                case 0x21 -> {                                  // INSTANCE DUMP
                    p += idSize + 4L + idSize;
                    long len = u4l(f, (int) p);
                    p += 4 + len;
                }
                case 0x22 -> {                                  // OBJECT ARRAY DUMP
                    p += idSize + 4L;
                    long count = u4l(f, (int) p);
                    p += 4L + idSize + count * idSize;
                }
                case 0x23 -> {                                  // PRIMITIVE ARRAY DUMP
                    long id = readId(f, (int) p, idSize);
                    p += idSize + 4L;
                    long count = u4l(f, (int) p);
                    p += 4;
                    int type = f[(int) p] & 0xFF;
                    p++;
                    if (type == T_BYTE || type == T_CHAR) {
                        if (count > Integer.MAX_VALUE) throw corrupt("array too large");
                        out.add(new ArrayPayload(id, type == T_CHAR, (int) count, p));
                    }
                    p += count * typeSize(type, idSize);
                }
                default -> throw corrupt("unknown heap sub-record tag 0x"
                        + Integer.toHexString(tag));
            }
            if (p > end) throw corrupt("heap sub-record overruns segment");
        }
    }

    private static long skipClassDump(byte[] f, long p, int idSize) throws AnalysisException {
        p += idSize;            // class object id
        p += 4;                 // stack trace serial
        p += 6L * idSize;       // super, loader, signers, protection domain, reserved x2
        p += 4;                 // instance size
        int cp = u2(f, (int) p);
        p += 2;
        for (int i = 0; i < cp; i++) {
            p += 2;             // constant pool index
            int type = f[(int) p] & 0xFF;
            p += 1 + typeSize(type, idSize);
        }
        int statics = u2(f, (int) p);
        p += 2;
        for (int i = 0; i < statics; i++) {
            p += idSize;        // field name string id
            int type = f[(int) p] & 0xFF;
            p += 1 + typeSize(type, idSize);
        }
        int fields = u2(f, (int) p);
        p += 2;
        p += (long) fields * (idSize + 1L);
        return p;
    }

    private static int typeSize(int type, int idSize) throws AnalysisException {
        return switch (type) {
            case T_OBJECT -> idSize;
            case T_BOOLEAN, T_BYTE -> 1;
            case T_CHAR, T_SHORT -> 2;
            case T_INT, T_FLOAT -> 4;
            case T_LONG, T_DOUBLE -> 8;
            default -> throw corrupt("unknown value type " + type);
        };
    }

    private static long readId(byte[] f, int p, int idSize) {
        return idSize == 4 ? u4l(f, p) : u8(f, p);
    }

    private static int u2(byte[] f, int p) {
        return ((f[p] & 0xFF) << 8) | (f[p + 1] & 0xFF);
    }

    private static int u4(byte[] f, int p) {
        return (int) u4l(f, p);
    }

    private static long u4l(byte[] f, int p) {
        return ((long) (f[p] & 0xFF) << 24) | ((f[p + 1] & 0xFF) << 16)
                | ((f[p + 2] & 0xFF) << 8) | (f[p + 3] & 0xFF);
    }

    private static long u8(byte[] f, int p) {
        return (u4l(f, p) << 32) | u4l(f, p + 4);
    }

    private static AnalysisException corrupt(String why) {
        return new AnalysisException(400, "cannot locate array payloads, corrupt HPROF: " + why);
    }
}
