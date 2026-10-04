package heapx.scrub;

/**
 * File location of one primitive array payload inside an HPROF dump.
 * Only byte[] and char[] payloads are ever located, scanned or scrubbed.
 *
 * @param objectId     HPROF object id of the array
 * @param charArray    true for char[] (2-byte big-endian elements), false for byte[]
 * @param dataOffset   absolute file offset of the first payload byte
 * @param elementCount number of array elements
 */
public record ArrayRegion(long objectId, boolean charArray, long dataOffset, int elementCount) {
    public int elementSize() { return charArray ? 2 : 1; }
}
