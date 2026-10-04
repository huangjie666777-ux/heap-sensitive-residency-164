package heapx;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal HPROF (JAVA PROFILE 1.0.2) writer used to produce real dump files
 * for tests and demos. Supports 4- and 8-byte identifiers and segmented heaps.
 */
final class HprofWriter {
    static final int T_OBJECT = 2, T_BOOLEAN = 4, T_CHAR = 5, T_FLOAT = 6,
            T_DOUBLE = 7, T_BYTE = 8, T_SHORT = 9, T_INT = 10, T_LONG = 11;

    final int idSize;

    HprofWriter() { this(4); }

    HprofWriter(int idSize) {
        if (idSize != 4 && idSize != 8) throw new IllegalArgumentException();
        this.idSize = idSize;
    }

    private final Map<String, Integer> stringIds = new HashMap<>();
    private final ByteArrayOutputStream strings = new ByteArrayOutputStream();
    private final ByteArrayOutputStream heapClasses = new ByteArrayOutputStream();
    private final ByteArrayOutputStream heapData = new ByteArrayOutputStream();
    private final DataOutputStream h = new DataOutputStream(heapData);
    private final List<byte[]> loadClass = new ArrayList<>();
    private int nextStringId = 1;
    private int nextClassSerial = 1;

    int string(String s) {
        return stringIds.computeIfAbsent(s, k -> {
            int id = nextStringId++;
            try {
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                DataOutputStream d = new DataOutputStream(b);
                writeId(d, id);
                d.write(s.getBytes(StandardCharsets.UTF_8));
                d.flush();
                strings.write(record(0x01, b.toByteArray()));
            } catch (IOException e) { throw new RuntimeException(e); }
            return id;
        });
    }

    static final class FieldDef {
        final String name; final int type; final Object value; // static value or null
        FieldDef(String name, int type, Object value) { this.name = name; this.type = type; this.value = value; }
    }

    static final class ClassDef {
        final int classId;
        final String name;
        final int superClassId; // 0 = none
        final List<FieldDef> instanceFields = new ArrayList<>();
        final List<FieldDef> staticFields = new ArrayList<>();
        int instanceSize;
        ClassDef(int classId, String name, int superClassId) {
            this.classId = classId; this.name = name; this.superClassId = superClassId;
        }
        ClassDef field(String n, int type) { instanceFields.add(new FieldDef(n, type, null)); return this; }
        ClassDef staticRef(String n, int objId) { staticFields.add(new FieldDef(n, T_OBJECT, objId)); return this; }
    }

    private final Map<Integer, ClassDef> classes = new LinkedHashMap<>();

    ClassDef defineClass(int classId, String name, int superClassId) {
        ClassDef c = new ClassDef(classId, name, superClassId);
        classes.put(classId, c);
        return c;
    }

    void jniGlobalRoot(int objId) {
        try {
            h.writeByte(0x01); // ROOT JNI GLOBAL
            writeId(h, objId);
            writeId(h, objId); // jni global ref id
        } catch (IOException e) { throw new RuntimeException(e); }
    }

    void instance(int objId, int classId, Object... values) {
        ClassDef c = classes.get(classId);
        try {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            DataOutputStream d = new DataOutputStream(b);
            writeId(d, objId);
            d.writeInt(0); // stack trace serial
            writeId(d, classId);
            ByteArrayOutputStream fb = new ByteArrayOutputStream();
            DataOutputStream f = new DataOutputStream(fb);
            // write instance fields of superclasses first (jhat/NetBeans expect declaration order)
            List<FieldDef> all = allInstanceFields(c);
            if (values.length != all.size()) throw new IllegalArgumentException(
                    "expected " + all.size() + " values, got " + values.length);
            for (int i = 0; i < all.size(); i++) writeValue(f, all.get(i).type, values[i]);
            f.flush();
            byte[] data = fb.toByteArray();
            d.writeInt(data.length);
            d.write(data);
            d.flush();
            h.writeByte(0x21); // INSTANCE_DUMP
            h.write(b.toByteArray());
        } catch (IOException e) { throw new RuntimeException(e); }
    }

    private List<FieldDef> allInstanceFields(ClassDef c) {
        // the NetBeans reader lays out instance data own-class-fields first
        List<FieldDef> all = new ArrayList<>(c.instanceFields);
        if (c.superClassId != 0) all.addAll(allInstanceFields(classes.get(c.superClassId)));
        return all;
    }

    void objectArray(int objId, int arrayClassId, int... elements) {
        try {
            h.writeByte(0x22); // OBJECT_ARRAY_DUMP
            writeId(h, objId);
            h.writeInt(0);
            h.writeInt(elements.length);
            writeId(h, arrayClassId);
            for (int e : elements) writeId(h, e);
        } catch (IOException e) { throw new RuntimeException(e); }
    }

    void byteArray(int objId, byte[] data) {
        primitiveArray(objId, T_BYTE, data.length, d -> d.write(data));
    }

    void charArray(int objId, char[] data) {
        primitiveArray(objId, T_CHAR, data.length, d -> {
            for (char c : data) d.writeChar(c);
        });
    }

    private interface ArrayBody { void write(DataOutputStream d) throws IOException; }

    private void primitiveArray(int objId, int type, int count, ArrayBody body) {
        try {
            h.writeByte(0x23); // PRIMITIVE_ARRAY_DUMP
            writeId(h, objId);
            h.writeInt(0);
            h.writeInt(count);
            h.writeByte(type);
            body.write(h);
        } catch (IOException e) { throw new RuntimeException(e); }
    }

    private void writeId(DataOutputStream d, long id) throws IOException {
        if (idSize == 4) d.writeInt((int) id); else d.writeLong(id);
    }

    private void writeValue(DataOutputStream d, int type, Object v) throws IOException {
        switch (type) {
            case T_OBJECT -> writeId(d, ((Number) v).longValue());
            case T_INT -> d.writeInt(((Number) v).intValue());
            case T_LONG -> d.writeLong(((Number) v).longValue());
            case T_BYTE, T_BOOLEAN -> d.writeByte(((Number) v).intValue());
            case T_SHORT -> d.writeShort(((Number) v).intValue());
            case T_CHAR -> d.writeChar(((Number) v).intValue());
            case T_FLOAT -> d.writeFloat(((Number) v).floatValue());
            case T_DOUBLE -> d.writeDouble(((Number) v).doubleValue());
            default -> throw new IllegalArgumentException("type " + type);
        }
    }

    private int typeSize(int type) {
        return switch (type) {
            case T_OBJECT -> idSize; case T_BOOLEAN, T_BYTE -> 1;
            case T_CHAR, T_SHORT -> 2; case T_INT, T_FLOAT -> 4;
            case T_LONG, T_DOUBLE -> 8;
            default -> throw new IllegalArgumentException();
        };
    }

    Path write(Path file) throws IOException {
        return write(file, false);
    }

    /** @param segmented emit the heap as two HEAP_DUMP_SEGMENT records plus
     *                    a HEAP_DUMP_END record instead of one HEAP_DUMP */
    Path write(Path file, boolean segmented) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(out);
        d.write("JAVA PROFILE 1.0.2".getBytes(StandardCharsets.US_ASCII));
        d.writeByte(0);
        d.writeInt(idSize);       // identifier size
        d.writeLong(System.currentTimeMillis());
        // intern every string up-front so STRING records precede their use
        for (ClassDef c : classes.values()) {
            string(c.name);
            for (FieldDef f : c.staticFields) string(f.name);
            for (FieldDef f : c.instanceFields) string(f.name);
        }
        out.write(strings.toByteArray());
        // load class records
        for (ClassDef c : classes.values()) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            DataOutputStream x = new DataOutputStream(b);
            x.writeInt(nextClassSerial++);
            writeId(x, c.classId);
            x.writeInt(0);
            writeId(x, string(c.name));
            x.flush();
            out.write(record(0x02, b.toByteArray()));
        }
        // class dumps
        for (ClassDef c : classes.values()) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            DataOutputStream x = new DataOutputStream(b);
            writeId(x, c.classId);
            x.writeInt(0); // stack serial
            writeId(x, c.superClassId);
            writeId(x, 0); writeId(x, 0); writeId(x, 0); // loader, signers, pd
            writeId(x, 0); writeId(x, 0); // reserved
            int size = 0;
            for (FieldDef f : allInstanceFields(c)) size += typeSize(f.type);
            x.writeInt(size);
            x.writeShort(0); // constant pool
            x.writeShort(c.staticFields.size());
            for (FieldDef f : c.staticFields) {
                writeId(x, string(f.name));
                x.writeByte(f.type);
                writeValue(x, f.type, f.value);
            }
            x.writeShort(c.instanceFields.size());
            for (FieldDef f : c.instanceFields) {
                writeId(x, string(f.name));
                x.writeByte(f.type);
            }
            x.flush();
            heapClasses.write(0x20); // CLASS_DUMP sub-record: tag + body, no record header
            heapClasses.write(b.toByteArray());
        }
        h.flush();
        ByteArrayOutputStream heapAll = new ByteArrayOutputStream();
        heapAll.write(heapClasses.toByteArray());
        heapAll.write(heapData.toByteArray());
        if (segmented) {
            out.write(record(0x1C, heapClasses.toByteArray())); // HEAP_DUMP_SEGMENT
            out.write(record(0x1C, heapData.toByteArray()));    // HEAP_DUMP_SEGMENT
            out.write(record(0x2C, new byte[0]));               // HEAP_DUMP_END
        } else {
            out.write(record(0x0C, heapAll.toByteArray()));     // HEAP_DUMP
        }
        d.flush();
        Files.write(file, out.toByteArray());
        return file;
    }

    private static byte[] record(int tag, byte[] body) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(b);
        d.writeByte(tag);
        d.writeInt(0); // time
        d.writeInt(body.length);
        d.write(body);
        d.flush();
        return b.toByteArray();
    }
}
