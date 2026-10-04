package heapx.scrub;

import heapx.parse.AnalysisException;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Walks the raw HPROF binary structure (never string-searching the file)
 * and locates every byte[] / char[] payload: top-level records are skipped
 * by their length field; HEAP_DUMP (0x0C) and HEAP_DUMP_SEGMENT (0x1C)
 * bodies are decoded sub-record by sub-record. Handles 4- and 8-byte
 * identifiers and segmented heaps. Only PRIMITIVE_ARRAY_DUMP (0x23)
 * payloads of type byte or char are reported; every other record keeps its
 * exact bytes untouched.
 */
public final class HprofLayout {
    private static final int REC_HEAP_DUMP = 0x0C;
    private static final int REC_HEAP_DUMP_SEGMENT = 0x1C;

    private static final int SUB_CLASS_DUMP = 0x20;
    private static final int SUB_INSTANCE_DUMP = 0x21;
    private static final int SUB_OBJECT_ARRAY_DUMP = 0x22;
    private static final int SUB_PRIMITIVE_ARRAY_DUMP = 0x23;

    private static final int T_OBJECT = 2, T_BOOLEAN = 4, T_CHAR = 5, T_FLOAT = 6,
            T_DOUBLE = 7, T_BYTE = 8, T_SHORT = 9, T_INT = 10, T_LONG = 11;

    private HprofLayout() {}

    public static List<ArrayRegion> locateArrays(Path file) throws AnalysisException {
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            // header: NUL-terminated version string, u4 id size, u8 timestamp
            int b;
            do {
                b = raf.read();
                if (b < 0) throw corrupt("truncated header");
            } while (b != 0);
            int idSize = raf.readInt();
            if (idSize != 4 && idSize != 8) throw corrupt("unsupported identifier size " + idSize);
            raf.skipBytes(8); // timestamp

            List<ArrayRegion> regions = new ArrayList<>();
            long length = raf.length();
            while (raf.getFilePointer() < length) {
                int tag = raf.read();
                if (tag < 0) break;
                raf.skipBytes(4); // time
                long bodyLen = raf.readInt() & 0xFFFFFFFFL;
                long bodyStart = raf.getFilePointer();
                long bodyEnd = bodyStart + bodyLen;
                if (bodyEnd > length) throw corrupt("record body extends past end of file");
                if (tag == REC_HEAP_DUMP || tag == REC_HEAP_DUMP_SEGMENT) {
                    scanHeapBody(raf, bodyEnd, idSize, regions);
                }
                raf.seek(bodyEnd);
            }
            return regions;
        } catch (IOException e) {
            throw new AnalysisException(400, "failed to read HPROF layout: " + e.getMessage());
        }
    }

    private static void scanHeapBody(RandomAccessFile raf, long end, int idSize,
                                     List<ArrayRegion> regions)
            throws IOException, AnalysisException {
        while (raf.getFilePointer() < end) {
            int sub = raf.read();
            if (sub < 0) throw corrupt("truncated heap dump");
            switch (sub) {
                case 0xFF -> raf.skipBytes(idSize);                       // ROOT UNKNOWN
                case 0x01 -> raf.skipBytes(2 * idSize);                   // ROOT JNI GLOBAL
                case 0x02, 0x03 -> raf.skipBytes(idSize + 8);             // JNI LOCAL / JAVA FRAME
                case 0x04, 0x06 -> raf.skipBytes(idSize + 4);             // NATIVE STACK / THREAD BLOCK
                case 0x05, 0x07 -> raf.skipBytes(idSize);                 // STICKY CLASS / MONITOR USED
                case 0x08 -> raf.skipBytes(idSize + 8);                   // THREAD OBJECT
                case 0x20 -> skipClassDump(raf, idSize);
                case 0x21 -> {                                            // INSTANCE DUMP
                    raf.skipBytes(idSize + 4 + idSize);
                    long dataLen = raf.readInt() & 0xFFFFFFFFL;
                    skipExactly(raf, dataLen);
                }
                case 0x22 -> {                                            // OBJECT ARRAY DUMP
                    raf.skipBytes(idSize + 4);
                    long count = raf.readInt() & 0xFFFFFFFFL;
                    raf.skipBytes(idSize);
                    skipExactly(raf, count * idSize);
                }
                case 0x23 -> {                                            // PRIMITIVE ARRAY DUMP
                    long id = readId(raf, idSize);
                    raf.skipBytes(4);
                    long count = raf.readInt() & 0xFFFFFFFFL;
                    int type = raf.read();
                    int elemSize = typeSize(type, idSize);
                    if (count > Integer.MAX_VALUE) throw corrupt("primitive array too large");
                    if (type == T_BYTE || type == T_CHAR) {
                        regions.add(new ArrayRegion(id, type == T_CHAR,
                                raf.getFilePointer(), (int) count));
                    }
                    skipExactly(raf, count * elemSize);
                }
                default -> throw corrupt("unknown heap sub-record tag 0x"
                        + Integer.toHexString(sub & 0xFF));
            }
        }
        if (raf.getFilePointer() != end) throw corrupt("heap sub-record overruns its record");
    }

    private static void skipClassDump(RandomAccessFile raf, int idSize)
            throws IOException, AnalysisException {
        raf.skipBytes(7 * idSize + 4 + 4); // 7 ids + stack serial + instance size
        int constantPool = raf.readUnsignedShort();
        for (int i = 0; i < constantPool; i++) {
            raf.skipBytes(2);
            int type = raf.read();
            raf.skipBytes(typeSize(type, idSize));
        }
        int statics = raf.readUnsignedShort();
        for (int i = 0; i < statics; i++) {
            raf.skipBytes(idSize);
            int type = raf.read();
            raf.skipBytes(typeSize(type, idSize));
        }
        int fields = raf.readUnsignedShort();
        for (int i = 0; i < fields; i++) {
            raf.skipBytes(idSize + 1);
        }
    }

    private static long readId(RandomAccessFile raf, int idSize) throws IOException {
        return idSize == 4 ? raf.readInt() & 0xFFFFFFFFL : raf.readLong();
    }

    private static int typeSize(int type, int idSize) throws AnalysisException {
        return switch (type) {
            case T_OBJECT -> idSize;
            case T_BOOLEAN, T_BYTE -> 1;
            case T_CHAR, T_SHORT -> 2;
            case T_INT, T_FLOAT -> 4;
            case T_LONG, T_DOUBLE -> 8;
            default -> throw corrupt("unknown primitive type " + type);
        };
    }

    private static void skipExactly(RandomAccessFile raf, long bytes)
            throws IOException, AnalysisException {
        long remaining = bytes;
        while (remaining > 0) {
            int skipped = raf.skipBytes(remaining > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) remaining);
            if (skipped <= 0) throw corrupt("truncated file");
            remaining -= skipped;
        }
    }

    private static AnalysisException corrupt(String why) {
        return new AnalysisException(400, "corrupt or unsupported HPROF file: " + why);
    }
}
