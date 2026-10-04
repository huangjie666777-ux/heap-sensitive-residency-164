package heapx.scrub;

import heapx.graph.PathFinder;

import java.util.List;

/**
 * One immutable match of a scan rule inside one array payload.
 * Element offsets/lengths are in array elements (bytes for byte[],
 * chars for char[]). {@code path} is the shortest strong-reference root
 * path of the holding array, present only when the array is reachable.
 */
public record ScanHit(String ruleId, long arrayObjectId, boolean charArray,
                      int elementOffset, int elementLength,
                      boolean reachable, List<PathFinder.Step> path) {}
