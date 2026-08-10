use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::diff::{DiffResult, SerializableDeclaration};
use anyhow::{bail, Context, Result};
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Magic bytes for the format
const MAGIC_BYTES: &[u8; 4] = b"ASTD";
const CURRENT_VERSION: u32 = 2;
const FILE_HEADER_SIZE: usize = 64;
const MAX_DUMP_SIZE: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug)]
pub struct AstDiffDump {
    pub header: DumpHeader,
    pub metadata: DumpMetadata,
    pub file1_data: FileData,
    pub file2_data: FileData,
    pub matching: MatchingData,
    pub diff_result: DiffResult,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DumpHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub flags: DumpFlags,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DumpFlags {
    pub compressed: bool,
    pub has_source_preview: bool,
    pub has_similarity_matrix: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DumpMetadata {
    pub tool_version: String,
    pub timestamp: u64,
    pub config: DiffConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DiffConfig {
    pub use_fingerprints: bool,
    pub parallel_matching: bool,
    pub threshold: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileData {
    pub path: PathBuf,
    pub content_hash: [u8; 32],
    pub declarations: Vec<DeclarationWithContext>,
    pub source_preview: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeclarationWithContext {
    pub decl: SerializableDeclaration,
    pub candidates_considered: Vec<(usize, f64)>,
    pub match_decision: Option<MatchDecision>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MatchingData {
    pub matches: Vec<MatchPair>,
    pub similarity_matrix: Option<SparseMatrix>,
    pub threshold_data: ThresholdInfo,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MatchPair {
    pub idx1: usize,
    pub idx2: usize,
    pub similarity: f64,
    pub evidence_count: usize,
    pub evidence_breakdown: Option<EvidenceBreakdown>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MatchDecision {
    pub matched_to: Option<usize>,
    pub similarity_score: f64,
    pub reason: MatchReason,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MatchReason {
    HighSimilarity {
        score: f64,
        evidence: usize,
    },
    FingerprintMatch {
        common_strings: usize,
        common_apis: usize,
    },
    NoSuitableCandidate,
    BetterMatchExists {
        better_idx: usize,
        better_score: f64,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SparseMatrix {
    pub entries: Vec<(usize, usize, f64)>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ThresholdInfo {
    pub used_threshold: f64,
    pub computed_threshold: Option<f64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceBreakdown {
    pub structural_similarity: f64,
    pub name_similarity: f64,
    pub fingerprint_similarity: Option<f64>,
}

impl AstDiffDump {
    /// Create a new dump from analysis results
    pub fn new(
        file1_path: PathBuf,
        file2_path: PathBuf,
        file1_decls: Vec<SerializableDeclaration>,
        file2_decls: Vec<SerializableDeclaration>,
        matches: Vec<(usize, usize, f64)>,
        diff_result: DiffResult,
        config: DiffConfig,
    ) -> Result<Self> {
        // Calculate content hashes
        let file1_hash = Self::calculate_file_hash(&file1_path)?;
        let file2_hash = Self::calculate_file_hash(&file2_path)?;

        // Create file data
        let file1_data = FileData {
            path: file1_path,
            content_hash: file1_hash,
            declarations: file1_decls
                .into_iter()
                .map(|decl| DeclarationWithContext {
                    decl,
                    candidates_considered: vec![],
                    match_decision: None,
                })
                .collect(),
            source_preview: None,
        };

        let file2_data = FileData {
            path: file2_path,
            content_hash: file2_hash,
            declarations: file2_decls
                .into_iter()
                .map(|decl| DeclarationWithContext {
                    decl,
                    candidates_considered: vec![],
                    match_decision: None,
                })
                .collect(),
            source_preview: None,
        };

        // Create matching data
        let matching = MatchingData {
            matches: matches
                .into_iter()
                .map(|(idx1, idx2, sim)| MatchPair {
                    idx1,
                    idx2,
                    similarity: sim,
                    evidence_count: 0,
                    evidence_breakdown: None,
                })
                .collect(),
            similarity_matrix: None,
            threshold_data: ThresholdInfo {
                used_threshold: config.threshold,
                computed_threshold: None,
            },
        };

        // Create metadata
        let metadata = DumpMetadata {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            config,
        };

        // Create header
        let header = DumpHeader {
            magic: *MAGIC_BYTES,
            version: CURRENT_VERSION,
            flags: DumpFlags {
                compressed: true,
                has_source_preview: false,
                has_similarity_matrix: false,
            },
        };

        Ok(Self {
            header,
            metadata,
            file1_data,
            file2_data,
            matching,
            diff_result,
        })
    }

    /// Save the dump to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_DUMP_SIZE)
            .reject_trailing_bytes()
            .serialize(self)?;
        if data.len() as u64 > MAX_DUMP_SIZE {
            bail!("dump payload exceeds {} bytes", MAX_DUMP_SIZE);
        }
        let compressed = zstd::encode_all(&data[..], 3)?;
        let checksum = Sha256::digest(&compressed);

        let mut header = [0u8; FILE_HEADER_SIZE];
        header[0..4].copy_from_slice(MAGIC_BYTES);
        header[4..8].copy_from_slice(&CURRENT_VERSION.to_le_bytes());
        header[8..16].copy_from_slice(&1u64.to_le_bytes()); // zstd-compressed payload
        header[16..24].copy_from_slice(&(data.len() as u64).to_le_bytes());
        header[24..32].copy_from_slice(&(compressed.len() as u64).to_le_bytes());
        header[32..64].copy_from_slice(&checksum);

        let mut file = std::fs::File::create(path)?;
        file.write_all(&header)?;
        file.write_all(&compressed)?;
        file.sync_all()?;
        Ok(())
    }

    /// Load a dump from a file
    pub fn load(path: &Path) -> Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let file_len = file.metadata()?.len();
        if file_len < FILE_HEADER_SIZE as u64 {
            bail!("dump is truncated or uses the unsupported legacy v1 format");
        }

        let mut header = [0u8; FILE_HEADER_SIZE];
        file.read_exact(&mut header)?;
        if &header[0..4] != MAGIC_BYTES {
            bail!("invalid dump magic; legacy headerless dumps are not supported");
        }
        let version = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if version != CURRENT_VERSION {
            bail!(
                "unsupported dump version {}; expected {}",
                version,
                CURRENT_VERSION
            );
        }
        let flags = u64::from_le_bytes(header[8..16].try_into().unwrap());
        if flags != 1 {
            bail!("unsupported dump flags: {flags:#x}");
        }
        let uncompressed_size = u64::from_le_bytes(header[16..24].try_into().unwrap());
        let compressed_size = u64::from_le_bytes(header[24..32].try_into().unwrap());
        if uncompressed_size > MAX_DUMP_SIZE || compressed_size > MAX_DUMP_SIZE {
            bail!("dump exceeds the configured {} byte limit", MAX_DUMP_SIZE);
        }
        if file_len != FILE_HEADER_SIZE as u64 + compressed_size {
            bail!("dump payload length does not match its header");
        }

        let mut compressed = Vec::with_capacity(compressed_size as usize);
        file.read_to_end(&mut compressed)?;
        let actual_checksum = Sha256::digest(&compressed);
        if actual_checksum.as_slice() != &header[32..64] {
            bail!("dump payload checksum mismatch");
        }

        let decoder = zstd::stream::read::Decoder::new(&compressed[..])?;
        let mut data = Vec::with_capacity(uncompressed_size as usize);
        decoder
            .take(uncompressed_size + 1)
            .read_to_end(&mut data)
            .context("failed to decompress dump payload")?;
        if data.len() as u64 != uncompressed_size {
            bail!("decompressed dump size does not match its header");
        }

        let dump: Self = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(uncompressed_size)
            .reject_trailing_bytes()
            .deserialize(&data)?;
        if dump.header.magic != *MAGIC_BYTES || dump.header.version != CURRENT_VERSION {
            bail!("dump payload header does not match its file header");
        }
        Ok(dump)
    }

    /// Calculate SHA-256 hash of a file
    fn calculate_file_hash(path: &Path) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};

        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok(hasher.finalize().into())
    }

    /// Find a declaration by name
    pub fn find_declaration(&self, name: &str) -> Option<&DeclarationWithContext> {
        self.file1_data
            .declarations
            .iter()
            .chain(self.file2_data.declarations.iter())
            .find(|d| d.decl.name == name)
    }

    /// Get the match for a declaration from file1
    pub fn get_match_for(&self, file1_decl_idx: usize) -> Option<&MatchPair> {
        self.matching
            .matches
            .iter()
            .find(|m| m.idx1 == file1_decl_idx)
    }

    /// Get all unmatched declarations from file1
    pub fn unmatched_from_file1(&self) -> Vec<&DeclarationWithContext> {
        let matched_indices: std::collections::HashSet<_> =
            self.matching.matches.iter().map(|m| m.idx1).collect();

        self.file1_data
            .declarations
            .iter()
            .enumerate()
            .filter(|(idx, _)| !matched_indices.contains(idx))
            .map(|(_, decl)| decl)
            .collect()
    }

    /// Get all unmatched declarations from file2
    pub fn unmatched_from_file2(&self) -> Vec<&DeclarationWithContext> {
        let matched_indices: std::collections::HashSet<_> =
            self.matching.matches.iter().map(|m| m.idx2).collect();

        self.file2_data
            .declarations
            .iter()
            .enumerate()
            .filter(|(idx, _)| !matched_indices.contains(idx))
            .map(|(_, decl)| decl)
            .collect()
    }

    /// Validate that the dump is still valid for the given source files
    pub fn validate(&self, file1_path: &Path, file2_path: &Path) -> Result<bool> {
        let file1_hash = Self::calculate_file_hash(file1_path)?;
        let file2_hash = Self::calculate_file_hash(file2_path)?;

        Ok(
            file1_hash == self.file1_data.content_hash
                && file2_hash == self.file2_data.content_hash,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use tempfile::tempdir;

    use super::*;
    use crate::diff::{Change, ChangeType, DeclarationKind, DiffClassification, Location};

    fn declaration(name: &str, start_byte: usize) -> SerializableDeclaration {
        SerializableDeclaration {
            name: name.to_string(),
            kind: DeclarationKind::Function,
            line: 1,
            end_line: 1,
            start_byte,
            end_byte: start_byte + 10,
            signature: "function(params:0,stmts:1)".to_string(),
            structural_hashes: HashSet::from([1, 2]),
            size: 2,
            minhash_signature: vec![1; 128],
            fingerprint: None,
        }
    }

    fn sample_dump(directory: &Path) -> AstDiffDump {
        let file1 = directory.join("old.js");
        let file2 = directory.join("new.js");
        std::fs::write(&file1, "function old(){}").unwrap();
        std::fs::write(&file2, "function new(){}").unwrap();
        let change = Change {
            change_type: ChangeType::Modification,
            location1: Some(Location {
                line: 1,
                column: 0,
                code_snippet: "function old(){}".to_string(),
                end_line: Some(1),
            }),
            location2: Some(Location {
                line: 1,
                column: 0,
                code_snippet: "function new(){}".to_string(),
                end_line: Some(1),
            }),
            description: "function 'new' (was 'old')".to_string(),
            structural_path: "global.old->new".to_string(),
            classification: Some(DiffClassification::Unchanged),
            display_diff: String::new(),
            similarity_score: Some(1.0),
        };
        AstDiffDump::new(
            file1,
            file2,
            vec![declaration("old", 0)],
            vec![declaration("new", 0)],
            vec![(0, 0, 1.0)],
            DiffResult {
                identical: false,
                similarity: 1.0,
                changes: vec![change],
                matched_declarations: 1,
                total_declarations1: 1,
                total_declarations2: 1,
                rename_map: HashMap::from([("new".to_string(), "old".to_string())]),
                matched_pairs: vec![(0, 0, 1.0)],
            },
            DiffConfig {
                use_fingerprints: true,
                parallel_matching: true,
                threshold: 0.5,
            },
        )
        .unwrap()
    }

    #[test]
    fn v2_dump_round_trips_with_fixed_header_and_matches() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("analysis.astdump");
        sample_dump(directory.path()).save(&path).unwrap();
        assert_eq!(&std::fs::read(&path).unwrap()[0..4], b"ASTD");

        let loaded = AstDiffDump::load(&path).unwrap();
        assert_eq!(loaded.header.version, CURRENT_VERSION);
        assert_eq!(loaded.matching.matches.len(), 1);
        assert_eq!(loaded.matching.matches[0].idx1, 0);
        assert_eq!(loaded.matching.matches[0].idx2, 0);
        assert_eq!(loaded.diff_result.changes.len(), 1);
    }

    #[test]
    fn checksum_corruption_is_rejected_before_decompression() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("analysis.astdump");
        sample_dump(directory.path()).save(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        std::fs::write(&path, bytes).unwrap();

        let error = AstDiffDump::load(&path).unwrap_err();
        assert!(error.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn legacy_headerless_dump_is_rejected_clearly() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("legacy.astdump");
        std::fs::write(&path, zstd::encode_all(&b"legacy"[..], 1).unwrap()).unwrap();

        let error = AstDiffDump::load(&path).unwrap_err();
        assert!(error.to_string().contains("legacy"));
    }
}
