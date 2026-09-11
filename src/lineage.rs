//! Fast, deterministic structural-context matching across analysis artifacts.
//!
//! The matcher never compares artifact-local IDs directly. It builds compact
//! identifier-erased context fingerprints, uses exact/rare/LSH indexes to
//! bound candidate sets, then scores only the surviving sparse pairs.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self};
use std::path::Path;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analysis::{Analysis, AnalysisSymbolKind};
use crate::sourcemap::{positions_for_byte_offsets, OriginalPosition, SourceMap};

const SCORE_SCALE: u32 = 10_000;
const LSH_BANDS: usize = 4;
const MAX_REPORT_BYTES: u64 = 128 * 1024 * 1024;
type FingerprintColumns = (Vec<[u8; 32]>, Vec<u64>, Vec<u32>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MatcherConfig {
    pub min_score_bps: u32,
    pub min_margin_bps: u32,
    pub max_candidates: usize,
    pub rare_feature_max_frequency: usize,
    pub max_size_ratio: u32,
}

impl Default for MatcherConfig {
    fn default() -> Self {
        Self {
            min_score_bps: 7_200,
            min_margin_bps: 700,
            max_candidates: 96,
            rare_feature_max_frequency: 24,
            max_size_ratio: 4,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchDecision {
    Accepted,
    Abstained,
    Deleted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceTier {
    Exact,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MatchEvidence {
    pub exact_shape: bool,
    pub shape_bps: u32,
    pub context_bps: u32,
    pub roles_bps: u32,
    pub size_bps: u32,
    pub scope_bps: u32,
    pub shared_rare_features: u32,
    /// Whether both symbols resolve to the same source-map origin.  `None`
    /// means that source-map evidence was not supplied (the v1 behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_map_origin_match: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SymbolMatch {
    pub source_row: u32,
    pub source_symbol_id: String,
    pub target_row: Option<u32>,
    pub target_symbol_id: Option<String>,
    pub decision: MatchDecision,
    pub confidence: ConfidenceTier,
    pub score_bps: u32,
    pub source_margin_bps: u32,
    pub target_margin_bps: u32,
    pub candidate_count: u32,
    pub candidates_truncated: bool,
    pub evidence: Option<MatchEvidence>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CandidateStats {
    pub source_symbols: u64,
    pub target_symbols: u64,
    pub exact_unique_anchors: u64,
    pub candidate_pairs: u64,
    pub expensive_comparisons: u64,
    pub truncated_sources: u64,
    pub accepted: u64,
    pub abstained: u64,
    pub deleted: u64,
    pub added: u64,
    pub ambiguous_targets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LineageReport {
    pub format: String,
    pub algorithm: String,
    pub source_digest: String,
    pub target_digest: String,
    /// SHA-256 of the exact raw source map supplied for the source artifact.
    /// Both map digests are either present together or absent together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_map_source_digest: Option<String>,
    /// SHA-256 of the exact raw source map supplied for the target artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_map_target_digest: Option<String>,
    pub config: MatcherConfig,
    pub config_digest: String,
    pub stats: CandidateStats,
    pub matches: Vec<SymbolMatch>,
    pub added_target_rows: Vec<u32>,
    pub ambiguous_target_rows: Vec<u32>,
}

impl LineageReport {
    pub fn read(path: &Path) -> Result<Self> {
        if fs::metadata(path)?.len() > MAX_REPORT_BYTES {
            bail!("lineage report exceeds the read limit");
        }
        let report: Self = serde_json::from_slice(&fs::read(path)?)?;
        report.validate()?;
        Ok(report)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        crate::atomic_file::write(path, &[&bytes])
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != "astdiff.lineage.v1" || self.algorithm != "structural-context-v1" {
            bail!("unsupported lineage report format");
        }
        let config_digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&self.config)?).into();
        if self.config_digest != hex(&config_digest) {
            bail!("lineage configuration digest mismatch");
        }
        validate_digest(&self.source_digest)?;
        validate_digest(&self.target_digest)?;
        validate_digest(&self.config_digest)?;
        match (
            self.source_map_source_digest.as_deref(),
            self.source_map_target_digest.as_deref(),
        ) {
            (None, None) => {}
            (Some(source_map), Some(target_map)) => {
                validate_digest(source_map)?;
                validate_digest(target_map)?;
            }
            _ => bail!("lineage source-map digests must be supplied as a pair"),
        }
        let source_maps_bound = self.source_map_source_digest.is_some();
        if self.config.max_candidates == 0
            || self.config.rare_feature_max_frequency == 0
            || self.config.max_size_ratio == 0
            || self.config.min_score_bps > SCORE_SCALE
            || self.config.min_margin_bps > SCORE_SCALE
        {
            bail!("invalid lineage matcher configuration");
        }
        let mut prior = None;
        let mut accepted_targets = BTreeSet::new();
        for matched in &self.matches {
            if prior.is_some_and(|row| row >= matched.source_row) {
                bail!("lineage source rows are not strictly ordered");
            }
            prior = Some(matched.source_row);
            validate_digest(&matched.source_symbol_id)?;
            if matched.score_bps > SCORE_SCALE
                || matched.source_margin_bps > SCORE_SCALE
                || matched.target_margin_bps > SCORE_SCALE
                || matched.candidate_count as usize > self.config.max_candidates
            {
                bail!("lineage score, margin, or candidate count is invalid");
            }
            match matched.decision {
                MatchDecision::Accepted | MatchDecision::Abstained => {
                    let target = matched
                        .target_row
                        .ok_or_else(|| anyhow::anyhow!("candidate match has no target"))?;
                    let target_id = matched
                        .target_symbol_id
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("candidate match has no target ID"))?;
                    validate_digest(target_id)?;
                    if matched.evidence.is_none() || matched.candidate_count == 0 {
                        bail!("candidate match has no evidence");
                    }
                    let evidence = matched.evidence.as_ref().expect("evidence was checked");
                    if [
                        evidence.shape_bps,
                        evidence.context_bps,
                        evidence.roles_bps,
                        evidence.size_bps,
                        evidence.scope_bps,
                    ]
                    .into_iter()
                    .any(|value| value > SCORE_SCALE)
                    {
                        bail!("lineage evidence component is out of range");
                    }
                    if evidence.source_map_origin_match.is_some() && !source_maps_bound {
                        bail!("lineage source-map evidence is not bound to raw maps");
                    }
                    if matched.decision == MatchDecision::Accepted
                        && !accepted_targets.insert(target)
                    {
                        bail!("accepted lineage matches are not one-to-one");
                    }
                }
                MatchDecision::Deleted => {
                    if matched.target_row.is_some()
                        || matched.target_symbol_id.is_some()
                        || matched.evidence.is_some()
                        || matched.candidate_count != 0
                    {
                        bail!("deleted lineage row contains candidate data");
                    }
                }
            }
        }
        if self.stats.source_symbols != self.matches.len() as u64
            || self.stats.accepted
                != self
                    .matches
                    .iter()
                    .filter(|entry| entry.decision == MatchDecision::Accepted)
                    .count() as u64
            || self.stats.abstained
                != self
                    .matches
                    .iter()
                    .filter(|entry| entry.decision == MatchDecision::Abstained)
                    .count() as u64
            || self.stats.deleted
                != self
                    .matches
                    .iter()
                    .filter(|entry| entry.decision == MatchDecision::Deleted)
                    .count() as u64
            || self.stats.added != self.added_target_rows.len() as u64
            || self.stats.ambiguous_targets != self.ambiguous_target_rows.len() as u64
            || self.stats.candidate_pairs != self.stats.expensive_comparisons
        {
            bail!("lineage statistics disagree with report rows");
        }
        if self
            .added_target_rows
            .windows(2)
            .any(|rows| rows[0] >= rows[1])
            || self
                .added_target_rows
                .iter()
                .any(|row| accepted_targets.contains(row))
            || self
                .ambiguous_target_rows
                .windows(2)
                .any(|rows| rows[0] >= rows[1])
            || self.ambiguous_target_rows.iter().any(|row| {
                accepted_targets.contains(row) || self.added_target_rows.binary_search(row).is_ok()
            })
        {
            bail!("added target rows are not canonical");
        }
        Ok(())
    }

    /// Bind a lineage report to the exact analysis rows and stable IDs it names.
    pub fn validate_against(&self, source: &Analysis, target: &Analysis) -> Result<()> {
        self.validate()?;
        if self.source_map_source_digest.is_some() {
            bail!("lineage report is source-map bound; exact source maps are required");
        }
        self.validate_against_inner(
            source,
            target,
            match_analyses(source, target, self.config.clone())?,
        )
    }

    /// Validate and deterministically recompute a report against exact
    /// JavaScript bytes and the exact raw source maps used to create it.
    ///
    /// A report carrying source-map evidence can never be validated with only
    /// an `Analysis`: the map bytes and generated source are part of its
    /// authority boundary.
    pub fn validate_against_with_source_maps(
        &self,
        source: &Analysis,
        target: &Analysis,
        source_text: &str,
        target_text: &str,
        source_map: &SourceMap,
        target_map: &SourceMap,
    ) -> Result<()> {
        self.validate()?;
        let source_map_digest = hex(&source_map.digest());
        let target_map_digest = hex(&target_map.digest());
        if self.source_map_source_digest.as_deref() != Some(source_map_digest.as_str())
            || self.source_map_target_digest.as_deref() != Some(target_map_digest.as_str())
        {
            bail!("lineage report is for different source maps");
        }
        if digest_source(source_text) != source.source_digest
            || digest_source(target_text) != target.source_digest
        {
            bail!("lineage report is for different JavaScript bytes");
        }
        let expected = match_analyses_with_source_maps(
            source,
            target,
            self.config.clone(),
            source_text,
            target_text,
            source_map,
            target_map,
        )?;
        self.validate_against_inner(source, target, expected)
    }

    fn validate_against_inner(
        &self,
        source: &Analysis,
        target: &Analysis,
        expected: LineageReport,
    ) -> Result<()> {
        source.validate()?;
        target.validate()?;
        if self.source_digest != hex(&source.source_digest)
            || self.target_digest != hex(&target.source_digest)
            || self.stats.source_symbols != source.symbols.len() as u64
            || self.stats.target_symbols != target.symbols.len() as u64
        {
            bail!("lineage report is for different analysis artifacts");
        }
        for matched in &self.matches {
            let source_symbol = source
                .symbols
                .get(matched.source_row as usize)
                .ok_or_else(|| anyhow::anyhow!("lineage source row is out of bounds"))?;
            if matched.source_symbol_id != source_symbol.id.to_hex() {
                bail!("lineage source row and stable ID disagree");
            }
            if let Some(target_row) = matched.target_row {
                let target_symbol = target
                    .symbols
                    .get(target_row as usize)
                    .ok_or_else(|| anyhow::anyhow!("lineage target row is out of bounds"))?;
                if matched.target_symbol_id.as_deref() != Some(target_symbol.id.to_hex().as_str()) {
                    bail!("lineage target row and stable ID disagree");
                }
            }
        }
        let added = self
            .added_target_rows
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let ambiguous = self
            .ambiguous_target_rows
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let accepted = self
            .matches
            .iter()
            .filter(|entry| entry.decision == MatchDecision::Accepted)
            .filter_map(|entry| entry.target_row)
            .collect::<HashSet<_>>();
        if added.len() != self.added_target_rows.len()
            || ambiguous.len() != self.ambiguous_target_rows.len()
            || added
                .iter()
                .any(|row| *row as usize >= target.symbols.len())
            || ambiguous
                .iter()
                .any(|row| *row as usize >= target.symbols.len() || added.contains(row))
            || accepted.iter().any(|row| {
                *row as usize >= target.symbols.len()
                    || added.contains(row)
                    || ambiguous.contains(row)
            })
            || added.len() + ambiguous.len() + accepted.len() != target.symbols.len()
        {
            bail!("lineage added target row is invalid");
        }
        if *self != expected {
            bail!("lineage decisions or evidence do not match deterministic recomputation");
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ContextFingerprint {
    symbol_row: u32,
    kind_class: u8,
    scope_kind: u8,
    scope_depth: u32,
    shape_digest: [u8; 32],
    shape_simhash: u64,
    context_simhash: u64,
    subtree_size: u32,
    roles: [u32; 6],
    rare_features: Vec<u64>,
    source_map_origin: Option<[u8; 32]>,
}

#[derive(Default)]
struct ContextIndex {
    contexts: Vec<ContextFingerprint>,
    exact: HashMap<(u8, [u8; 32]), Vec<u32>>,
    source_map_origins: HashMap<[u8; 32], Vec<u32>>,
    rare: HashMap<u64, Vec<u32>>,
    lsh: HashMap<(u8, u8, u16), Vec<u32>>,
    coarse: HashMap<(u8, u8, u8), Vec<u32>>,
}

#[derive(Clone)]
struct CandidateScore {
    source: u32,
    target: u32,
    score: u32,
    exact_unique: bool,
    evidence: MatchEvidence,
}

/// Match lexical symbols between two independently analyzed artifacts.
pub fn match_analyses(
    source: &Analysis,
    target: &Analysis,
    config: MatcherConfig,
) -> Result<LineageReport> {
    match_analyses_internal(source, target, config, None, None, None, None)
}

/// Match symbols while consuming explicitly supplied source maps.  Map files
/// are never discovered from JavaScript paths; callers must provide both raw
/// maps and both exact generated-source strings.
pub fn match_analyses_with_source_maps(
    source: &Analysis,
    target: &Analysis,
    config: MatcherConfig,
    source_text: &str,
    target_text: &str,
    source_map: &SourceMap,
    target_map: &SourceMap,
) -> Result<LineageReport> {
    source.validate()?;
    target.validate()?;
    if digest_source(source_text) != source.source_digest
        || digest_source(target_text) != target.source_digest
    {
        bail!("source-map lineage requires exact JavaScript bytes");
    }
    let source_origins = source_map_origins(source, source_text, source_map)?;
    let target_origins = source_map_origins(target, target_text, target_map)?;
    match_analyses_internal(
        source,
        target,
        config,
        Some(&source_origins),
        Some(&target_origins),
        Some(hex(&source_map.digest())),
        Some(hex(&target_map.digest())),
    )
}

fn match_analyses_internal(
    source: &Analysis,
    target: &Analysis,
    config: MatcherConfig,
    source_origins: Option<&[Option<[u8; 32]>]>,
    target_origins: Option<&[Option<[u8; 32]>]>,
    source_map_source_digest: Option<String>,
    source_map_target_digest: Option<String>,
) -> Result<LineageReport> {
    source.validate()?;
    target.validate()?;
    if source.language != target.language || source.frontend != target.frontend {
        bail!("analysis language/front-end profiles are incompatible");
    }
    if config.max_candidates == 0
        || config.rare_feature_max_frequency == 0
        || config.max_size_ratio == 0
        || config.min_score_bps > SCORE_SCALE
        || config.min_margin_bps > SCORE_SCALE
    {
        bail!("invalid matcher configuration");
    }

    let posting_cap = config.max_candidates.saturating_mul(8).max(64);
    if source_origins.is_some_and(|origins| origins.len() != source.symbols.len())
        || target_origins.is_some_and(|origins| origins.len() != target.symbols.len())
        || source_origins.is_some() != target_origins.is_some()
        || source_map_source_digest.is_some() != source_map_target_digest.is_some()
    {
        bail!("source-map lineage inputs are incomplete");
    }
    let source_index = ContextIndex::build(
        source,
        config.rare_feature_max_frequency,
        posting_cap,
        source_origins,
    )?;
    let target_index = ContextIndex::build(
        target,
        config.rare_feature_max_frequency,
        posting_cap,
        target_origins,
    )?;
    let mut stats = CandidateStats {
        source_symbols: source.symbols.len() as u64,
        target_symbols: target.symbols.len() as u64,
        ..CandidateStats::default()
    };
    let mut scored_by_source = vec![Vec::<CandidateScore>::new(); source.symbols.len()];
    let mut truncated = vec![false; source.symbols.len()];

    for source_context in &source_index.contexts {
        let key = (source_context.kind_class, source_context.shape_digest);
        let source_exact_count = source_index.exact.get(&key).map_or(0, Vec::len);
        let target_exact = target_index.exact.get(&key);
        let exact_unique =
            source_exact_count == 1 && target_exact.is_some_and(|rows| rows.len() == 1);
        let mut candidate_votes = HashMap::<u32, u16>::new();
        if exact_unique {
            candidate_votes.insert(target_exact.expect("unique exact row exists")[0], u16::MAX);
        }
        if candidate_votes.is_empty() {
            for feature in &source_context.rare_features {
                if let Some(rows) = target_index.rare.get(feature) {
                    for row in rows {
                        let votes = candidate_votes.entry(*row).or_default();
                        *votes = votes.saturating_add(1);
                    }
                }
            }
            for (signal, simhash) in [
                (0u8, source_context.shape_simhash),
                (1u8, source_context.context_simhash),
            ] {
                for band in 0..LSH_BANDS {
                    let value = simhash_band(simhash, band);
                    let band_key = signal * LSH_BANDS as u8 + band as u8;
                    if let Some(rows) =
                        target_index
                            .lsh
                            .get(&(source_context.kind_class, band_key, value))
                    {
                        for row in rows {
                            candidate_votes.entry(*row).or_insert(0);
                        }
                    }
                }
            }
        }
        if candidate_votes.is_empty() {
            for bucket in neighboring_size_buckets(source_context.subtree_size) {
                if let Some(rows) = target_index.coarse.get(&(
                    source_context.kind_class,
                    source_context.scope_kind,
                    bucket,
                )) {
                    for row in bounded_nearby_rows(
                        rows,
                        &target_index.contexts,
                        source_context.subtree_size,
                        config.max_candidates.saturating_mul(2),
                    ) {
                        candidate_votes.entry(*row).or_insert(0);
                    }
                }
            }
        }
        // Source-map origins are a high-priority posting, not a hard gate:
        // generated builds can move original coordinates between versions.
        // Structural candidates remain eligible when no origin posting
        // matches, while equal origins are scored first and retained as
        // deterministic evidence.
        if let Some(origin) = source_context.source_map_origin {
            if let Some(rows) = target_index.source_map_origins.get(&origin) {
                for row in rows {
                    candidate_votes.insert(*row, u16::MAX);
                }
            }
        }
        let mut candidates = candidate_votes.into_iter().collect::<Vec<_>>();
        candidates.retain(|(row, _)| {
            let candidate = &target_index.contexts[*row as usize];
            compatible(source_context, candidate, config.max_size_ratio)
        });
        candidates.sort_by_key(|(row, votes)| {
            let candidate = &target_index.contexts[*row as usize];
            (
                std::cmp::Reverse(*votes),
                (source_context.subtree_size as i64 - candidate.subtree_size as i64).unsigned_abs(),
                source_context.shape_simhash ^ candidate.shape_simhash,
                *row,
            )
        });
        if candidates.len() > config.max_candidates {
            candidates.truncate(config.max_candidates);
            truncated[source_context.symbol_row as usize] = true;
            stats.truncated_sources += 1;
        }
        stats.candidate_pairs += candidates.len() as u64;
        for (target_row, _) in candidates {
            let candidate = &target_index.contexts[target_row as usize];
            let scored = score_pair(source_context, candidate, exact_unique);
            stats.expensive_comparisons += 1;
            scored_by_source[source_context.symbol_row as usize].push(scored);
        }
        scored_by_source[source_context.symbol_row as usize]
            .sort_by_key(|candidate| (std::cmp::Reverse(candidate.score), candidate.target));
    }

    let mut target_scores = vec![Vec::<(u32, u32)>::new(); target.symbols.len()];
    for candidates in &scored_by_source {
        for candidate in candidates {
            target_scores[candidate.target as usize].push((candidate.source, candidate.score));
        }
    }
    for scores in &mut target_scores {
        scores.sort_by_key(|(source, score)| (std::cmp::Reverse(*score), *source));
    }

    let mut accepted_targets = vec![false; target.symbols.len()];
    let mut records = Vec::with_capacity(source.symbols.len());
    for source_row in 0..source.symbols.len() {
        let candidates = &scored_by_source[source_row];
        let Some(best) = candidates.first() else {
            stats.deleted += 1;
            records.push(empty_record(
                source,
                source_row,
                MatchDecision::Deleted,
                truncated[source_row],
            ));
            continue;
        };
        let source_runner_up = candidates.get(1).map_or(0, |candidate| candidate.score);
        let source_margin = best.score.saturating_sub(source_runner_up);
        let competing = &target_scores[best.target as usize];
        let target_is_best = competing
            .first()
            .is_some_and(|(row, _)| *row == source_row as u32);
        let target_runner_up = competing
            .iter()
            .find(|(row, _)| *row != source_row as u32)
            .map_or(0, |(_, score)| *score);
        let target_margin = best.score.saturating_sub(target_runner_up);
        let accept = !accepted_targets[best.target as usize]
            && target_is_best
            && (best.exact_unique
                || (best.score >= config.min_score_bps
                    && source_margin >= config.min_margin_bps
                    && target_margin >= config.min_margin_bps
                    && !truncated[source_row]));
        let decision = if accept {
            accepted_targets[best.target as usize] = true;
            stats.accepted += 1;
            if best.exact_unique {
                stats.exact_unique_anchors += 1;
            }
            MatchDecision::Accepted
        } else {
            stats.abstained += 1;
            MatchDecision::Abstained
        };
        records.push(SymbolMatch {
            source_row: source_row as u32,
            source_symbol_id: source.symbols[source_row].id.to_hex(),
            target_row: Some(best.target),
            target_symbol_id: Some(target.symbols[best.target as usize].id.to_hex()),
            decision,
            confidence: confidence_tier(best, source_margin, target_margin),
            score_bps: best.score,
            source_margin_bps: source_margin,
            target_margin_bps: target_margin,
            candidate_count: candidates.len() as u32,
            candidates_truncated: truncated[source_row],
            evidence: Some(best.evidence.clone()),
        });
    }
    let added_target_rows = accepted_targets
        .iter()
        .enumerate()
        .filter_map(|(row, matched)| {
            (!matched && target_scores[row].is_empty()).then_some(row as u32)
        })
        .collect::<Vec<_>>();
    let ambiguous_target_rows = accepted_targets
        .iter()
        .enumerate()
        .filter_map(|(row, matched)| {
            (!matched && !target_scores[row].is_empty()).then_some(row as u32)
        })
        .collect::<Vec<_>>();
    stats.added = added_target_rows.len() as u64;
    stats.ambiguous_targets = ambiguous_target_rows.len() as u64;

    let config_bytes = serde_json::to_vec(&config)?;
    Ok(LineageReport {
        format: "astdiff.lineage.v1".to_string(),
        algorithm: "structural-context-v1".to_string(),
        source_digest: hex(&source.source_digest),
        target_digest: hex(&target.source_digest),
        source_map_source_digest,
        source_map_target_digest,
        config_digest: hex(&Sha256::digest(config_bytes).into()),
        config,
        stats,
        matches: records,
        added_target_rows,
        ambiguous_target_rows,
    })
}

/// Resolve every declaration position in one UTF-8/UTF-16 conversion pass.
/// Tree-sitter records byte offsets while Source Map v3 queries use generated
/// UTF-16 columns; doing this in a batch avoids rescanning the source once per
/// symbol and keeps the map lookup itself bounded to a binary search.
fn source_map_origins(
    analysis: &Analysis,
    source_text: &str,
    source_map: &SourceMap,
) -> Result<Vec<Option<[u8; 32]>>> {
    let offsets = analysis
        .symbols
        .iter()
        .map(|symbol| {
            analysis
                .nodes
                .get(symbol.declaration_node as usize)
                .ok_or_else(|| anyhow::anyhow!("symbol declaration node is out of bounds"))
                .map(|node| node.start_byte)
        })
        .collect::<Result<Vec<_>>>()?;
    let positions = positions_for_byte_offsets(source_text, &offsets)?;
    Ok(positions
        .into_iter()
        .map(|position| {
            source_map
                .lookup(position)
                .and_then(|origin| origin_hash(&origin))
        })
        .collect())
}

/// Hash only source-map provenance.  Raw source paths, names, and snippets
/// never enter the lineage report; the length-delimited encoding keeps the
/// digest unambiguous even for adversarial source/name strings.
fn origin_hash(origin: &OriginalPosition) -> Option<[u8; 32]> {
    let source = origin.source.as_deref()?;
    let mut hasher = Sha256::new();
    hasher.update(b"astdiff.lineage.source-map-origin.v1");
    hash_optional_string(&mut hasher, origin.source_root.as_deref());
    hash_optional_string(&mut hasher, Some(source));
    hasher.update(origin.line.to_le_bytes());
    hasher.update(origin.column.to_le_bytes());
    Some(hasher.finalize().into())
}

fn hash_optional_string(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update((value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn digest_source(source: &str) -> [u8; 32] {
    Sha256::digest(source.as_bytes()).into()
}

impl ContextIndex {
    fn build(
        analysis: &Analysis,
        rare_cap: usize,
        posting_cap: usize,
        source_map_origins: Option<&[Option<[u8; 32]>]>,
    ) -> Result<Self> {
        if source_map_origins.is_some_and(|origins| origins.len() != analysis.symbols.len()) {
            bail!("source-map origin count disagrees with analysis symbols");
        }
        let (shape_digests, shape_simhashes, subtree_sizes) = subtree_fingerprints(analysis)?;
        let mut incoming_calls = vec![Vec::new(); analysis.symbols.len()];
        for call in &analysis.calls {
            if let Some(target) = call.target_symbol {
                incoming_calls[target as usize].push(call.kind as u8);
            }
        }
        let mut contexts = Vec::with_capacity(analysis.symbols.len());
        for (row, symbol) in analysis.symbols.iter().enumerate() {
            let declaration = semantic_container(analysis, symbol.declaration_node as usize);
            let scope = &analysis.scopes[symbol.scope as usize];
            let mut roles = [0u32; 6];
            let mut context_features = Vec::new();
            let start = symbol.reference_first as usize;
            let end = start + symbol.reference_count as usize;
            for (offset, reference) in analysis.references[start..end].iter().enumerate() {
                roles[reference.role as usize - 1] += 1;
                let def_use = &analysis.def_uses[start + offset];
                let node = &analysis.nodes[reference.node as usize];
                let parent_kind = node
                    .parent
                    .map(|parent| {
                        analysis.strings[analysis.nodes[parent as usize].kind as usize].as_str()
                    })
                    .unwrap_or("root");
                context_features.push(feature_hash(&[
                    b"use",
                    &[reference.role as u8],
                    parent_kind.as_bytes(),
                ]));
                context_features.push(feature_hash(&[b"resolution", &[def_use.resolution as u8]]));
                if let Some(target) = def_use.symbol {
                    context_features.push(feature_hash(&[
                        b"target-kind",
                        &[symbol_kind_class(analysis.symbols[target as usize].kind)],
                    ]));
                }
            }
            let mut ancestor = analysis.nodes[declaration].parent;
            for distance in 0..6u8 {
                let Some(node_row) = ancestor else { break };
                let node = &analysis.nodes[node_row as usize];
                let kind = analysis.strings[node.kind as usize].as_bytes();
                context_features.push(feature_hash(&[b"ancestor", &[distance], kind]));
                ancestor = node.parent;
            }
            let mut ancestor_scope = Some(symbol.scope);
            for distance in 0..6u8 {
                let Some(scope_row) = ancestor_scope else {
                    break;
                };
                let ancestor = &analysis.scopes[scope_row as usize];
                context_features.push(feature_hash(&[
                    b"scope-ancestor",
                    &[distance, ancestor.kind as u8],
                ]));
                ancestor_scope = ancestor.parent;
            }
            let declaration_node = &analysis.nodes[declaration];
            context_features.push(feature_hash(&[
                b"sibling-rank-bucket",
                &[declaration_node.child_ordinal.min(15) as u8],
            ]));
            for kind in &incoming_calls[row] {
                context_features.push(feature_hash(&[b"target-call", &[*kind]]));
            }
            context_features.sort_unstable();
            context_features.dedup();
            let context_simhash = simhash(context_features.iter().copied());
            contexts.push(ContextFingerprint {
                symbol_row: row as u32,
                kind_class: symbol_kind_class(symbol.kind),
                scope_kind: scope.kind as u8,
                scope_depth: scope.depth,
                shape_digest: shape_digests[declaration],
                shape_simhash: shape_simhashes[declaration],
                context_simhash,
                subtree_size: subtree_sizes[declaration],
                roles,
                rare_features: context_features,
                source_map_origin: source_map_origins
                    .and_then(|origins| origins.get(row).copied().flatten()),
            });
        }

        let mut index = Self {
            contexts,
            ..Self::default()
        };
        for context in &index.contexts {
            if let Some(origin) = context.source_map_origin {
                index
                    .source_map_origins
                    .entry(origin)
                    .or_default()
                    .push(context.symbol_row);
            }
            index
                .exact
                .entry((context.kind_class, context.shape_digest))
                .or_default()
                .push(context.symbol_row);
            index
                .coarse
                .entry((
                    context.kind_class,
                    context.scope_kind,
                    size_bucket(context.subtree_size),
                ))
                .or_default()
                .push(context.symbol_row);
            for (signal, simhash) in [(0u8, context.shape_simhash), (1u8, context.context_simhash)]
            {
                for band in 0..LSH_BANDS {
                    index
                        .lsh
                        .entry((
                            context.kind_class,
                            signal * LSH_BANDS as u8 + band as u8,
                            simhash_band(simhash, band),
                        ))
                        .or_default()
                        .push(context.symbol_row);
                }
            }
            for feature in &context.rare_features {
                index
                    .rare
                    .entry(*feature)
                    .or_default()
                    .push(context.symbol_row);
            }
        }
        index.rare.retain(|_, rows| rows.len() <= rare_cap);
        index
            .source_map_origins
            .retain(|_, rows| rows.len() <= posting_cap);
        index.lsh.retain(|_, rows| rows.len() <= posting_cap);
        for rows in index.coarse.values_mut() {
            rows.sort_by_key(|row| (index.contexts[*row as usize].subtree_size, *row));
        }
        Ok(index)
    }
}

pub(crate) fn semantic_container(analysis: &Analysis, declaration: usize) -> usize {
    let mut current = declaration;
    while let Some(parent) = analysis.nodes[current].parent {
        let parent = parent as usize;
        let kind = analysis.strings[analysis.nodes[parent].kind as usize].as_str();
        if matches!(
            kind,
            "variable_declarator"
                | "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "class_declaration"
                | "class_expression"
                | "import_specifier"
                | "namespace_import"
                | "import_clause"
                | "catch_clause"
        ) {
            return parent;
        }
        current = parent;
    }
    declaration
}

struct ShapeFrame {
    row: u32,
    hasher: Sha256,
    size: u32,
    votes: [i32; 64],
}

fn subtree_fingerprints(analysis: &Analysis) -> Result<FingerprintColumns> {
    let mut digests = vec![[0u8; 32]; analysis.nodes.len()];
    let mut simhashes = vec![0u64; analysis.nodes.len()];
    let mut sizes = vec![0u32; analysis.nodes.len()];
    let mut stack = Vec::<ShapeFrame>::new();
    for (row, node) in analysis.nodes.iter().enumerate() {
        while stack.last().map(|frame| frame.row) != node.parent {
            finalize_shape(&mut stack, &mut digests, &mut simhashes, &mut sizes)?;
        }
        let kind = analysis.strings[node.kind as usize].as_bytes();
        let feature = feature_hash(&[b"node", kind, &[node.flags]]);
        let mut hasher = Sha256::new();
        hasher.update((kind.len() as u64).to_le_bytes());
        hasher.update(kind);
        hasher.update([node.flags]);
        stack.push(ShapeFrame {
            row: row as u32,
            hasher,
            size: 1,
            votes: votes_for(feature),
        });
    }
    while !stack.is_empty() {
        finalize_shape(&mut stack, &mut digests, &mut simhashes, &mut sizes)?;
    }
    Ok((digests, simhashes, sizes))
}

fn finalize_shape(
    stack: &mut Vec<ShapeFrame>,
    digests: &mut [[u8; 32]],
    simhashes: &mut [u64],
    sizes: &mut [u32],
) -> Result<()> {
    let frame = stack.pop().expect("shape stack is not empty");
    let digest: [u8; 32] = frame.hasher.finalize().into();
    let simhash = votes_to_simhash(&frame.votes);
    digests[frame.row as usize] = digest;
    simhashes[frame.row as usize] = simhash;
    sizes[frame.row as usize] = frame.size;
    if let Some(parent) = stack.last_mut() {
        parent.hasher.update(digest);
        parent.size = parent
            .size
            .checked_add(frame.size)
            .ok_or_else(|| anyhow::anyhow!("syntax subtree is too large"))?;
        for (target, source) in parent.votes.iter_mut().zip(frame.votes) {
            *target = target.saturating_add(source);
        }
    }
    Ok(())
}

fn compatible(source: &ContextFingerprint, target: &ContextFingerprint, max_ratio: u32) -> bool {
    if source.kind_class != target.kind_class || source.scope_kind != target.scope_kind {
        return false;
    }
    let small = source.subtree_size.min(target.subtree_size).max(1);
    let large = source.subtree_size.max(target.subtree_size);
    large <= small.saturating_mul(max_ratio)
}

fn score_pair(
    source: &ContextFingerprint,
    target: &ContextFingerprint,
    exact_unique: bool,
) -> CandidateScore {
    let shape = hamming_similarity(source.shape_simhash, target.shape_simhash);
    let context = hamming_similarity(source.context_simhash, target.context_simhash);
    let roles = histogram_similarity(&source.roles, &target.roles);
    let size = ratio_similarity(source.subtree_size, target.subtree_size);
    let depth_delta = source.scope_depth.abs_diff(target.scope_depth).min(8);
    let scope = SCORE_SCALE.saturating_sub(depth_delta * 1_250);
    let shared = intersection_count(&source.rare_features, &target.rare_features) as u32;
    let exact_shape = source.shape_digest == target.shape_digest;
    let score = (shape as u64 * 45
        + context as u64 * 20
        + roles as u64 * 15
        + size as u64 * 10
        + scope as u64 * 10)
        / 100;
    CandidateScore {
        source: source.symbol_row,
        target: target.symbol_row,
        score: score as u32,
        exact_unique,
        evidence: MatchEvidence {
            exact_shape,
            shape_bps: shape,
            context_bps: context,
            roles_bps: roles,
            size_bps: size,
            scope_bps: scope,
            shared_rare_features: shared,
            source_map_origin_match: source
                .source_map_origin
                .zip(target.source_map_origin)
                .map(|(left, right)| left == right),
        },
    }
}

fn empty_record(
    source: &Analysis,
    row: usize,
    decision: MatchDecision,
    candidates_truncated: bool,
) -> SymbolMatch {
    SymbolMatch {
        source_row: row as u32,
        source_symbol_id: source.symbols[row].id.to_hex(),
        target_row: None,
        target_symbol_id: None,
        decision,
        confidence: ConfidenceTier::Low,
        score_bps: 0,
        source_margin_bps: 0,
        target_margin_bps: 0,
        candidate_count: 0,
        candidates_truncated,
        evidence: None,
    }
}

fn confidence_tier(
    candidate: &CandidateScore,
    source_margin: u32,
    target_margin: u32,
) -> ConfidenceTier {
    if candidate.exact_unique {
        ConfidenceTier::Exact
    } else if candidate.score >= 8_500 && source_margin >= 1_500 && target_margin >= 1_500 {
        ConfidenceTier::High
    } else if candidate.score >= 7_200 && source_margin >= 700 && target_margin >= 700 {
        ConfidenceTier::Medium
    } else {
        ConfidenceTier::Low
    }
}

fn symbol_kind_class(kind: AnalysisSymbolKind) -> u8 {
    match kind {
        AnalysisSymbolKind::Var | AnalysisSymbolKind::Let | AnalysisSymbolKind::Const => 1,
        AnalysisSymbolKind::Function => 2,
        AnalysisSymbolKind::Parameter | AnalysisSymbolKind::Catch => 3,
        AnalysisSymbolKind::Class => 4,
        AnalysisSymbolKind::Import => 5,
    }
}

fn feature_hash(parts: &[&[u8]]) -> u64 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("eight-byte digest prefix"))
}

fn votes_for(feature: u64) -> [i32; 64] {
    let mut votes = [0i32; 64];
    for (bit, vote) in votes.iter_mut().enumerate() {
        *vote = if feature & (1u64 << bit) == 0 { -1 } else { 1 };
    }
    votes
}

fn simhash(features: impl Iterator<Item = u64>) -> u64 {
    let mut votes = [0i32; 64];
    for feature in features {
        for (target, source) in votes.iter_mut().zip(votes_for(feature)) {
            *target = target.saturating_add(source);
        }
    }
    votes_to_simhash(&votes)
}

fn votes_to_simhash(votes: &[i32; 64]) -> u64 {
    votes.iter().enumerate().fold(0u64, |output, (bit, vote)| {
        output | (u64::from(*vote >= 0) << bit)
    })
}

fn simhash_band(value: u64, band: usize) -> u16 {
    ((value >> (band * 16)) & 0xffff) as u16
}

fn hamming_similarity(left: u64, right: u64) -> u32 {
    SCORE_SCALE - (left ^ right).count_ones() * SCORE_SCALE / 64
}

fn histogram_similarity(left: &[u32; 6], right: &[u32; 6]) -> u32 {
    let intersection = left.iter().zip(right).map(|(a, b)| a.min(b)).sum::<u32>();
    let union = left.iter().zip(right).map(|(a, b)| a.max(b)).sum::<u32>();
    u64::from(intersection)
        .saturating_mul(u64::from(SCORE_SCALE))
        .checked_div(u64::from(union))
        .map_or(SCORE_SCALE, |value| value as u32)
}

fn ratio_similarity(left: u32, right: u32) -> u32 {
    let small = left.min(right).max(1);
    let large = left.max(right).max(1);
    small * SCORE_SCALE / large
}

fn intersection_count(left: &[u64], right: &[u64]) -> usize {
    let (mut i, mut j, mut count) = (0, 0, 0);
    while i < left.len() && j < right.len() {
        match left[i].cmp(&right[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                count += 1;
                i += 1;
                j += 1;
            }
        }
    }
    count
}

fn size_bucket(size: u32) -> u8 {
    (u32::BITS - size.max(1).leading_zeros() - 1) as u8
}

fn neighboring_size_buckets(size: u32) -> BTreeSet<u8> {
    let bucket = size_bucket(size);
    [bucket.saturating_sub(1), bucket, bucket.saturating_add(1)]
        .into_iter()
        .collect()
}

fn bounded_nearby_rows<'a>(
    rows: &'a [u32],
    contexts: &[ContextFingerprint],
    size: u32,
    limit: usize,
) -> Vec<&'a u32> {
    if rows.len() <= limit {
        return rows.iter().collect();
    }
    let split = rows.partition_point(|row| contexts[*row as usize].subtree_size <= size);
    let (mut left, mut right) = (split.checked_sub(1), split);
    let mut output = Vec::with_capacity(limit);
    while output.len() < limit && (left.is_some() || right < rows.len()) {
        let take_left = match (left, rows.get(right)) {
            (Some(left_row), Some(right_row)) => {
                let left_size = contexts[rows[left_row] as usize].subtree_size;
                let right_size = contexts[*right_row as usize].subtree_size;
                size.abs_diff(left_size) <= size.abs_diff(right_size)
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        if take_left {
            let index = left.expect("left index exists");
            output.push(&rows[index]);
            left = index.checked_sub(1);
        } else {
            output.push(&rows[right]);
            right += 1;
        }
    }
    output
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("expected a lowercase 256-bit hexadecimal value");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::JsParser;

    fn analysis(source: &str) -> Analysis {
        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();
        Analysis::from_javascript(source, &tree).unwrap()
    }

    #[test]
    fn unique_structural_renames_are_exact_anchors() {
        let source = analysis("function descriptive(value) { return value + 1; }");
        let target = analysis("function a(b) { return b + 1; }");
        let report = match_analyses(&source, &target, MatcherConfig::default()).unwrap();
        assert_eq!(report.stats.accepted, 2);
        assert!(report.matches.iter().all(|record| {
            record.decision == MatchDecision::Accepted && record.confidence == ConfidenceTier::Exact
        }));
    }

    #[test]
    fn identical_clones_abstain_on_zero_margin() {
        let source = analysis("function a(){return 1} function b(){return 1}");
        let target = analysis("function x(){return 1} function y(){return 1}");
        let report = match_analyses(&source, &target, MatcherConfig::default()).unwrap();
        assert_eq!(report.stats.accepted, 0);
        assert_eq!(report.stats.abstained, 2);
    }

    #[test]
    fn repeated_exact_shapes_do_not_expand_into_all_pairs() {
        let source_text = (0..256)
            .map(|index| format!("function source_{index}(){{return 1}}"))
            .collect::<String>();
        let target_text = (0..256)
            .map(|index| format!("function target_{index}(){{return 1}}"))
            .collect::<String>();
        let source = analysis(&source_text);
        let target = analysis(&target_text);
        let config = MatcherConfig {
            max_candidates: 8,
            ..MatcherConfig::default()
        };
        let report = match_analyses(&source, &target, config).unwrap();
        assert!(
            report.stats.candidate_pairs
                <= report.stats.source_symbols * report.config.max_candidates as u64,
            "non-unique exact postings expanded beyond the candidate cap: {:#?}",
            report.stats
        );
        assert!(
            report.stats.candidate_pairs
                < report.stats.source_symbols * report.stats.target_symbols
        );
    }

    #[test]
    fn inserted_unrelated_symbols_do_not_break_exact_matches() {
        let source = analysis("function a(x){return x+1} function b(x){return x*2}");
        let target = analysis(
            "function noise(){return null} function q(y){return y+1} function r(y){return y*2}",
        );
        let report = match_analyses(&source, &target, MatcherConfig::default()).unwrap();
        assert_eq!(report.stats.accepted, 4, "{report:#?}");
        assert!(report.stats.added >= 1);
        assert!(report.stats.expensive_comparisons < 25);
    }

    #[test]
    fn report_is_byte_deterministic() {
        let source = analysis("const value = 1; function read(){ return value; }");
        let target = analysis("const a = 1; function b(){ return a; }");
        let first = match_analyses(&source, &target, MatcherConfig::default()).unwrap();
        let second = match_analyses(&source, &target, MatcherConfig::default()).unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
    }

    #[test]
    fn report_validation_binds_rows_to_stable_ids() {
        let source = analysis("function descriptive(value) { return value + 1; }");
        let target = analysis("function a(b) { return b + 1; }");
        let mut report = match_analyses(&source, &target, MatcherConfig::default()).unwrap();
        report.validate_against(&source, &target).unwrap();
        report.matches[0].source_symbol_id = "00".repeat(32);
        assert!(report.validate_against(&source, &target).is_err());
    }

    #[test]
    fn source_maps_bind_raw_digests_and_gate_impossible_origins() {
        let source_text = "function descriptive(value) { return value + 1; }";
        let target_text = "function a(b) { return b + 1; }";
        let source = analysis(source_text);
        let target = analysis(target_text);
        let source_map = SourceMap::parse(
            br#"{"version":3,"sources":["original.js"],"names":[],"mappings":"AAAA"}"#,
            crate::sourcemap::SourceMapLimits::default(),
        )
        .unwrap();
        let target_map = SourceMap::parse(
            br#"{"version":3,"sources":["original.js"],"names":[],"mappings":"AAAA"}"#,
            crate::sourcemap::SourceMapLimits::default(),
        )
        .unwrap();
        let report = match_analyses_with_source_maps(
            &source,
            &target,
            MatcherConfig::default(),
            source_text,
            target_text,
            &source_map,
            &target_map,
        )
        .unwrap();
        let source_map_digest = hex(&source_map.digest());
        assert_eq!(
            report.source_map_source_digest.as_deref(),
            Some(source_map_digest.as_str())
        );
        assert!(report.matches.iter().any(|matched| {
            matched
                .evidence
                .as_ref()
                .and_then(|evidence| evidence.source_map_origin_match)
                == Some(true)
        }));
        report
            .validate_against_with_source_maps(
                &source,
                &target,
                source_text,
                target_text,
                &source_map,
                &target_map,
            )
            .unwrap();

        let mismatched_target_map = SourceMap::parse(
            br#"{"version":3,"sources":["original.js"],"names":[],"mappings":"AACA"}"#,
            crate::sourcemap::SourceMapLimits::default(),
        )
        .unwrap();
        let gated = match_analyses_with_source_maps(
            &source,
            &target,
            MatcherConfig::default(),
            source_text,
            target_text,
            &source_map,
            &mismatched_target_map,
        )
        .unwrap();
        assert!(gated.stats.accepted <= report.stats.accepted);
        assert!(gated.matches.iter().all(|matched| {
            matched
                .evidence
                .as_ref()
                .and_then(|evidence| evidence.source_map_origin_match)
                != Some(true)
        }));
    }

    #[test]
    fn source_map_validation_rejects_wrong_generated_bytes_or_map() {
        let source_text = "function a(value) { return value; }";
        let target_text = "function b(other) { return other; }";
        let source = analysis(source_text);
        let target = analysis(target_text);
        let map = SourceMap::parse(
            br#"{"version":3,"sources":["original.js"],"names":[],"mappings":"AAAA"}"#,
            crate::sourcemap::SourceMapLimits::default(),
        )
        .unwrap();
        let report = match_analyses_with_source_maps(
            &source,
            &target,
            MatcherConfig::default(),
            source_text,
            target_text,
            &map,
            &map,
        )
        .unwrap();
        assert!(report
            .validate_against_with_source_maps(
                &source,
                &target,
                "function forged(value) { return value; }",
                target_text,
                &map,
                &map,
            )
            .is_err());
        assert!(report.validate_against(&source, &target).is_err());
    }
}
