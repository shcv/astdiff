# Comprehensive Dump Format Specification for AstDiff

## Overview

This specification defines a binary format for storing complete AST diff analysis results, including all declarations, matching results, and diff information in a single, efficient file.

## Format Design

### 1. What to Store

#### 1.1 Metadata Section
- Magic bytes & version for format identification
- Source file paths, sizes, and content hashes
- Timestamp of analysis
- Configuration used (fingerprints enabled, thresholds, etc.)
- Tool version

#### 1.2 Declarations Section
- All declarations from both files with:
  - Basic info (name, kind, line, signature)
  - Computed hashes (structural, minhash signatures)
  - Fingerprints (strings, constants, API calls)
  - AST node information (start/end positions)
- Index mapping for fast lookup

#### 1.3 Matching Results Section
- Match pairs (decl1_idx → decl2_idx)
- Similarity scores and evidence for each match
- Candidate matches that were considered but rejected
- Reasoning/evidence breakdown

#### 1.4 Diff Results Section
- All computed changes (additions, deletions, modifications)
- Change locations and descriptions
- Statistics (similarity %, matched counts)

### 2. Binary Format Choice

Using **bincode** (Rust's native binary serialization) with **zstd compression**:

```rust
#[derive(Serialize, Deserialize)]
struct AstDiffDump {
    header: DumpHeader,
    metadata: DumpMetadata,
    file1_data: FileData,
    file2_data: FileData,
    matching: MatchingData,
    diff_result: DiffResult,
}

#[derive(Serialize, Deserialize)]
struct DumpHeader {
    magic: [u8; 4], // b"ASTD"
    version: u32,
    flags: DumpFlags,
}

#[derive(Serialize, Deserialize)]
struct DumpMetadata {
    tool_version: String,
    timestamp: u64,
    config: DiffConfig,
}

#[derive(Serialize, Deserialize)]
struct FileData {
    path: PathBuf,
    content_hash: [u8; 32], // SHA-256
    declarations: Vec<DeclarationWithContext>,
    source_preview: Option<String>, // First N bytes for validation
}

#[derive(Serialize, Deserialize)]
struct DeclarationWithContext {
    decl: SerializableDeclaration,
    candidates_considered: Vec<(usize, f64)>, // Other decl indices & scores
    match_decision: Option<MatchDecision>,
}

#[derive(Serialize, Deserialize)]
struct MatchingData {
    matches: Vec<MatchPair>,
    similarity_matrix: Option<SparseMatrix>, // For debugging
    threshold_data: ThresholdInfo,
}

#[derive(Serialize, Deserialize)]
struct MatchPair {
    idx1: usize,
    idx2: usize,
    similarity: f64,
    evidence_count: usize,
    evidence_breakdown: Option<EvidenceBreakdown>,
}

#[derive(Serialize, Deserialize)]
struct MatchDecision {
    matched_to: Option<usize>,
    similarity_score: f64,
    reason: MatchReason,
}

#[derive(Serialize, Deserialize)]
enum MatchReason {
    HighSimilarity { score: f64, evidence: usize },
    FingerprintMatch { common_strings: usize, common_apis: usize },
    NoSuitableCandidate,
    BetterMatchExists { better_idx: usize, better_score: f64 },
}
```

### 3. Storage Strategy

#### 3.1 File Layout
```
[Header - 64 bytes fixed]
  - Magic: 4 bytes ("ASTD")
  - Version: 4 bytes (little endian; current version 2)
  - Flags: 8 bytes (bit 0 means zstd)
  - Uncompressed size: 8 bytes
  - Compressed size: 8 bytes
  - SHA-256 of compressed payload: 32 bytes

[Compressed Data Block - rest of file]
  - zstd-compressed, bounded bincode serialization of AstDiffDump
```

#### 3.2 Compression Approach
- Use zstd level 3-6 (good balance of speed/ratio)
- Compress after bincode serialization
- Verify magic, version, flags, file length, and SHA-256 before decompression
- Bound compressed and uncompressed payloads before allocation
- Reject legacy headerless v1 files rather than attempting ambiguous decoding

#### 3.3 Memory-mapped Option
Memory mapping is deferred to the Isoform persistence roadmap:
- Index section at known offsets
- Allow partial loading of specific sections
- Lazy decompression of accessed blocks

### 4. Retrieval Features

#### 4.1 Fast Query API
```rust
impl AstDiffDump {
    // Find declaration by name
    pub fn find_declaration(&self, name: &str) -> Option<&DeclarationWithContext>;
    
    // Get match for a declaration
    pub fn get_match_for(&self, file1_decl_idx: usize) -> Option<&MatchPair>;
    
    // Explain why two declarations weren't matched
    pub fn why_not_matched(&self, idx1: usize, idx2: usize) -> MatchRejectionReason;
    
    // Get all unmatched declarations
    pub fn unmatched_from_file1(&self) -> Vec<&DeclarationWithContext>;
    pub fn unmatched_from_file2(&self) -> Vec<&DeclarationWithContext>;
    
    // Re-run matching with different parameters
    pub fn rematch(&mut self, config: MatchConfig) -> DiffResult;
}
```

#### 4.2 Validation
- Verify source files haven't changed (via content hash)
- Validate dump integrity (header checksum)
- Version compatibility checking

### 5. Usage Examples

```bash
# Create comprehensive dump
astdiff file1.js file2.js --dump analysis.astdump

# Load and inspect specific declaration
astdiff inspect analysis.astdump --identifier _C8

# Query specific information
astdiff query analysis.astdump find func1
astdiff query analysis.astdump match func1
astdiff query analysis.astdump unmatched-from1
astdiff query analysis.astdump unmatched-from2

# Validate dump is still valid for source files
astdiff query analysis.astdump validate current1.js current2.js

# Display summary/full/JSON views
astdiff load analysis.astdump --format summary
```

### 6. Benefits

1. **Performance**:
   - 10-50x smaller than JSON (bincode + zstd)
   - Loads in milliseconds vs seconds for parsing
   - No need to recompute expensive operations

2. **Debugging**:
   - Complete information preserved
   - Can explore why specific matches were/weren't made
   - Can inspect retained match decisions and results without re-parsing

3. **Workflows**:
   - Batch analysis across many versions
   - CI/CD integration (store dumps as artifacts)
   - Historical analysis and comparison

4. **Extensibility**:
   - Version field allows format evolution
   - Flags field for optional features
   - Reserved space in header for future use

### 7. Implementation Priority

1. **Implemented**: validated v2 header, bounded decode, load/query, source validation
2. **Next**: rejected-candidate evidence and match-decision tracking
3. **Deferred**: Isoform-positioned mmap cache and lineage artifacts

## File Extension

Use `.astdump` or `.adump` as the standard extension for these files.
