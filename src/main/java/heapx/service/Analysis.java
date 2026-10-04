package heapx.service;

import heapx.graph.DominatorAnalysis;
import heapx.model.HeapModel;
import heapx.scrub.ArrayRegion;
import heapx.scrub.ScanRecord;

import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** One completed, immutable heap analysis. Published atomically by id. */
public final class Analysis {
    public final String id;
    public final HeapModel model;
    public final DominatorAnalysis dominators;
    public final long createdAtMillis;
    /** Original dump, kept for sensitive-value scans and scrubbed exports. */
    public final Path sourceFile;
    /** Per-analysis temp directory holding the dump and export copies. */
    public final Path workDir;
    /** Located byte[]/char[] payload regions inside the dump. */
    public final java.util.List<ArrayRegion> arrayRegions;
    /** Immutable scan results by scanId. */
    public final Map<String, ScanRecord> scans = new ConcurrentHashMap<>();

    public Analysis(String id, HeapModel model, DominatorAnalysis dominators,
                    Path workDir, Path sourceFile, java.util.List<ArrayRegion> arrayRegions) {
        this.id = id;
        this.model = model;
        this.dominators = dominators;
        this.createdAtMillis = System.currentTimeMillis();
        this.workDir = workDir;
        this.sourceFile = sourceFile;
        this.arrayRegions = arrayRegions;
    }
}
