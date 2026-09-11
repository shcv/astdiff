use super::fingerprint::{calculate_fingerprint_similarity, RarityScorer};
use super::{Change, ChangeType, Declaration, DeclarationKind, DiffClassification, MINHASH_LANES};
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Estimated MinHash similarity a pair must reach to survive the candidate filter.
const LSH_SIMILARITY_THRESHOLD: f64 = 0.3;

/// Lanes compared before the gate checks whether the pair is still reachable.
///
/// Divisibility is checked at compile time; signatures have a fixed width.
const LSH_GATE_BLOCK_LANES: usize = 32;
const _: () = assert!(MINHASH_LANES.is_multiple_of(LSH_GATE_BLOCK_LANES));

/// Smallest number of agreeing lanes that clears LSH_SIMILARITY_THRESHOLD.
///
/// The gate is `matches / lanes >= threshold`. `matches` is a small integer and
/// `lanes` is a power of two, so that quotient is exact in f64 and the comparison
/// has a single integer crossing point: below it every pair fails, at or above it
/// every pair passes. Finding that point once at compile time lets the hot loop
/// count lanes and compare integers instead of dividing 230 million times, and it
/// is the reason the loop can bail early: once the lanes still uncompared cannot
/// carry the count this far, the pair is already rejected. For the current 128
/// lanes and 0.3 threshold the point is 39, since 38/128 = 0.296875 fails and
/// 39/128 = 0.3046875 passes.
const LSH_MIN_MATCHING_LANES: usize = min_matching_lanes(MINHASH_LANES, LSH_SIMILARITY_THRESHOLD);

const fn min_matching_lanes(lanes: usize, threshold: f64) -> usize {
    let mut matching = 0;

    while matching < lanes {
        if matching as f64 / lanes as f64 >= threshold {
            break;
        }

        matching += 1;
    }

    matching
}

/// One decls2 entry as the window scan sees it, in sorted2 order.
///
/// The scan touches this instead of the full Declaration, which is ~200 bytes
/// and drags a String heap allocation in behind every probe. Everything the scan
/// decides on lives here, so a rejected pair costs one sequential read.
struct Decl2Probe {
    size: usize,
    name_id: u32,
    i2: u32,
    kind: DeclarationKind,
}

/// A pair that survived LSH filtering.
///
/// Indices are u32 because this list is the largest live allocation in the tool
/// (50M+ entries on a 34 MB bundle) and no input has come close to 4 billion
/// declarations. The old struct also carried the LSH score, which nothing ever
/// read; dropping it and narrowing the indices takes the entry from 32 to 12 bytes.
#[derive(Debug, Clone)]
pub struct CandidateMatch {
    pub i1: u32,
    pub i2: u32,
    pub name_match: bool, // True if names match exactly
}

#[derive(Debug, Clone)]
pub struct SimilarityResult {
    pub i1: usize,
    pub i2: usize,
    pub similarity: f64,
}

pub struct ParallelMatcher {
    use_fingerprints: bool,
    batch_size: usize,
}

impl ParallelMatcher {
    pub fn new(use_fingerprints: bool) -> Self {
        Self {
            use_fingerprints,
            batch_size: 1000, // Process LSH in batches of 1000
        }
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn match_declarations(
        &self,
        decls1: &[Declaration],
        decls2: &[Declaration],
        source1: &str,
        source2: &str,
        scorer: Option<&RarityScorer>,
    ) -> (
        Vec<(usize, usize, f64)>,
        Vec<Change>,
        HashMap<String, String>,
    ) {
        use super::profiling::Timer;

        // Steps 1+2: generate candidate pairs and LSH-filter them in one pass, so
        // only survivors are ever stored (see build_and_filter_candidates).
        let lsh_candidates = {
            let _timer = Timer::new("build_and_filter_candidates");
            self.build_and_filter_candidates(decls1, decls2)
        };

        eprintln!(
            "LSH filtering reduced to {} candidates",
            lsh_candidates.len()
        );

        // Step 3: Parallel full similarity calculation for remaining candidates
        let similarity_results = {
            let _timer = Timer::new("parallel_full_similarity");
            self.parallel_full_similarity(&lsh_candidates, decls1, decls2, scorer)
        };

        drop(lsh_candidates);
        // Step 4: Resolve best matches + normalize/diff all pairs
        let (matches, changes, rename_map) = {
            let _timer = Timer::new("resolve_matches");
            self.resolve_best_matches(similarity_results, decls1, decls2, source1, source2)
        };

        (matches, changes, rename_map)
    }
    /// Generate the candidate pairs and LSH-filter them in a single pass.
    ///
    /// This used to be two steps: materialize every (i1, i2) pair whose sizes and
    /// kinds were compatible, then filter that list down. On a 34 MB bundle the
    /// intermediate list held 230 million pairs, 3.7 GB, and it stayed alive while
    /// the filtered list was built next to it. Worse, a Vec that large grows by
    /// doubling, so the last reallocation needs the old and new buffers resident at
    /// the same time. That transient spike is what aborted the process on hosts
    /// where the memory was not there.
    ///
    /// Testing each pair as it is generated means only the survivors are ever
    /// stored, which is roughly a fifth of the pairs on real input.
    ///
    /// The scan itself reads a flat copy of the decls2 signatures and a compact side
    /// table, both laid out in the same size order the window walks, so a probe costs a
    /// sequential read instead of a pointer chase into a 37k-allocation heap. Neither
    /// copy changes any value the scan compares, only where it reads them from.
    ///
    /// Output order is unchanged (i1 ascending, then decls2 in size order):
    /// resolve_best_matches sorts these by similarity with a stable sort, so the
    /// order here decides tie-breaks and therefore the final diff.
    fn build_and_filter_candidates(
        &self,
        decls1: &[Declaration],
        decls2: &[Declaration],
    ) -> Vec<CandidateMatch> {
        // Sort declarations by size for efficient window search
        let mut sorted2: Vec<(usize, usize)> = decls2
            .iter()
            .enumerate()
            .map(|(i, d)| (i, d.size))
            .collect();
        sorted2.sort_by_key(|(_, size)| *size);

        let mut exact_names2: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i2, decl2) in decls2.iter().enumerate() {
            exact_names2.entry(&decl2.name).or_default().push(i2);
        }

        // Names are interned across both files so the scan compares u32 ids instead of
        // two String heap reads per probe. Ids come from one table over both inputs, so
        // two names share an id exactly when the strings are equal, which is the test
        // the id comparison replaces.
        let name_capacity = decls1
            .len()
            .checked_add(decls2.len())
            .expect("declaration count overflow");
        let mut name_ids: HashMap<&str, u32> = HashMap::with_capacity(name_capacity);
        let mut next_name_id: u32 = 0;

        let name_ids1: Vec<u32> = decls1
            .iter()
            .map(|decl| {
                *name_ids.entry(decl.name.as_str()).or_insert_with(|| {
                    let id = next_name_id;
                    next_name_id = next_name_id.checked_add(1).expect("too many unique names");
                    id
                })
            })
            .collect();

        // Signatures are copied into one flat buffer in sorted2 order so the window scan
        // reads them front to back. Each declaration otherwise owns its own ~1 KB
        // allocation, which turns the scan into one random pointer chase per probe over a
        // working set far larger than cache.
        let mut flat_signatures = Vec::with_capacity(sorted2.len());
        let mut probes: Vec<Decl2Probe> = Vec::with_capacity(sorted2.len());

        for &(i2, size) in &sorted2 {
            let decl2 = &decls2[i2];
            flat_signatures.push(decl2.minhash_signature);

            let name_id = *name_ids.entry(decl2.name.as_str()).or_insert_with(|| {
                let id = next_name_id;
                next_name_id = next_name_id.checked_add(1).expect("too many unique names");
                id
            });

            probes.push(Decl2Probe {
                size,
                name_id,
                i2: u32::try_from(i2).expect("astdiff supports at most u32::MAX declarations"),
                kind: decl2.kind.clone(),
            });
        }

        let examined = AtomicUsize::new(0);
        let last_update = Mutex::new(Instant::now());

        let results: Vec<CandidateMatch> = decls1
            .par_iter()
            .enumerate()
            .flat_map_iter(|(i1_usize, decl1)| {
                let i1 = u32::try_from(i1_usize)
                    .expect("astdiff supports at most u32::MAX declarations");
                let min_size = ((decl1.size as f64) * 0.5).max(1.0) as usize;
                let max_size = ((decl1.size as f64) * 1.5) as usize;
                let name_id1 = name_ids1[i1_usize];

                // Binary search for window start
                let start_idx = probes.partition_point(|probe| probe.size < min_size);

                let mut local_results = Vec::new();
                let mut local_examined = 0usize;

                // Stable names remain anchors even across extensive rewrites that
                // fall outside the structural size window.
                if let Some(indices) = exact_names2.get(decl1.name.as_str()) {
                    for &i2 in indices {
                        if kinds_are_compatible(&decl1.kind, &decls2[i2].kind) {
                            local_examined += 1;
                            local_results.push(CandidateMatch {
                                i1,
                                i2: u32::try_from(i2)
                                    .expect("astdiff supports at most u32::MAX declarations"),
                                name_match: true,
                            });
                        }
                    }
                }

                for (idx, probe) in probes.iter().enumerate().skip(start_idx) {
                    if probe.size > max_size {
                        break;
                    }

                    if name_id1 == probe.name_id || !kinds_are_compatible(&decl1.kind, &probe.kind)
                    {
                        continue;
                    }

                    local_examined += 1;

                    let sig2 = &flat_signatures[idx];

                    if passes_lsh_gate(&decl1.minhash_signature, sig2) {
                        local_results.push(CandidateMatch {
                            i1,
                            i2: probe.i2,
                            name_match: false,
                        });
                    }
                }

                // Report progress every second
                let done = examined.fetch_add(local_examined, Ordering::Relaxed) + local_examined;

                if let Ok(mut last) = last_update.try_lock() {
                    if last.elapsed() >= Duration::from_secs(1) {
                        eprint!("\r  LSH filtering: {} pairs examined", done);
                        *last = Instant::now();
                    }
                }

                local_results.into_iter()
            })
            .collect();

        // Clear the progress line with a final update
        eprintln!(
            "\r  LSH filtering: {} pairs examined - Complete",
            examined.load(Ordering::Relaxed)
        );

        results
    }

    #[allow(clippy::too_many_arguments)]
    fn parallel_full_similarity(
        &self,
        candidates: &[CandidateMatch],
        decls1: &[Declaration],
        decls2: &[Declaration],
        scorer: Option<&RarityScorer>,
    ) -> Vec<SimilarityResult> {
        let progress = AtomicUsize::new(0);
        let total = candidates.len();
        let last_update = Mutex::new(Instant::now());

        let results = candidates
            .par_chunks(self.batch_size / 10) // Smaller batches for expensive calculations
            .flat_map(|batch| {
                let mut results = Vec::with_capacity(batch.len());

                for candidate in batch {
                    let decl1 = &decls1[candidate.i1 as usize];
                    let decl2 = &decls2[candidate.i2 as usize];

                    let (similarity, evidence_count) = match (
                        self.use_fingerprints,
                        &decl1.fingerprint,
                        &decl2.fingerprint,
                        scorer,
                    ) {
                        (true, Some(fp1), Some(fp2), Some(scorer)) => {
                            let (score, count) = calculate_fingerprint_similarity(fp1, fp2, scorer);
                            if !candidate.name_match
                                && !should_match_with_score(score * 0.7 + 0.3, count, decl1.size)
                            {
                                continue;
                            }
                            (
                                score * 0.7 + super::declaration_similarity(decl1, decl2) * 0.3,
                                count,
                            )
                        }
                        _ => (super::declaration_similarity(decl1, decl2), 0),
                    };

                    // Apply thresholds - always include name matches
                    if candidate.name_match
                        || should_match_with_score(similarity, evidence_count, decl1.size)
                    {
                        results.push(SimilarityResult {
                            i1: candidate.i1 as usize,
                            i2: candidate.i2 as usize,
                            similarity,
                        });
                    }
                }

                // Report progress every second
                let done = progress.fetch_add(batch.len(), Ordering::Relaxed) + batch.len();

                if let Ok(mut last) = last_update.try_lock() {
                    if last.elapsed() >= Duration::from_secs(1) || done == total {
                        eprint!(
                            "\r  Full similarity: {}/{} ({:.1}%)",
                            done,
                            total,
                            done as f64 / total as f64 * 100.0
                        );
                        *last = Instant::now();
                    }
                }

                results
            })
            .collect();

        // Clear the progress line with a final update
        eprintln!(
            "\r  Full similarity: {}/{} (100.0%) - Complete",
            total, total
        );

        results
    }

    #[allow(clippy::type_complexity)]
    fn resolve_best_matches(
        &self,
        mut results: Vec<SimilarityResult>,
        decls1: &[Declaration],
        decls2: &[Declaration],
        source1: &str,
        source2: &str,
    ) -> (
        Vec<(usize, usize, f64)>,
        Vec<Change>,
        HashMap<String, String>,
    ) {
        use super::profiling::Timer;
        use super::StructuralDiff;

        // Pre-compute source lines for human-readable locations only. Source
        // comparisons use the exact tree-sitter byte ranges below.
        let _timer = Timer::new("precompute_source_lines");
        let lines1: Vec<&str> = source1.lines().collect();
        let lines2: Vec<&str> = source2.lines().collect();

        // Sort by similarity descending
        results.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap());

        let mut matches = Vec::new();
        let mut matched1 = vec![false; decls1.len()];
        let mut matched2 = vec![false; decls2.len()];
        let mut changes = Vec::new();

        // ── Phase A: Greedy matching + build rename map ──
        let mut rename_map: HashMap<String, String> = HashMap::new();
        let mut source_symbols = HashMap::new();
        let mut target_symbols = HashMap::new();

        for result in &results {
            if !matched1[result.i1] && !matched2[result.i2] {
                matched1[result.i1] = true;
                matched2[result.i2] = true;
                matches.push((result.i1, result.i2, result.similarity));

                let decl1 = &decls1[result.i1];
                let decl2 = &decls2[result.i2];

                if let (Some(source), Some(target)) =
                    (decl1.comparison.symbol, decl2.comparison.symbol)
                {
                    source_symbols.insert(source, source);
                    target_symbols.insert(target, source);
                }
                // Export declaration names for the human-facing mapping.
                if decl1.name != decl2.name {
                    rename_map.insert(decl2.name.clone(), decl1.name.clone());
                }
            }
        }

        eprintln!(
            "Phase A: {} matches, {} renames",
            matches.len(),
            rename_map.len()
        );

        // ── Phase B: Normalize + diff all matched pairs ──
        let mut unchanged_count = 0usize;
        let mut string_only_count = 0usize;
        let mut structural_count = 0usize;

        drop(results);
        for &(i1, i2, similarity) in &matches {
            let decl1 = &decls1[i1];
            let decl2 = &decls2[i2];

            // Extract source for both declarations
            let src1 = &source1[decl1.start_byte..decl1.end_byte];
            let src2 = &source2[decl2.start_byte..decl2.end_byte];

            let left = decl1.comparison.normalize(&source_symbols);
            let right = decl2.comparison.normalize(&target_symbols);
            if left.equal(&right) {
                unchanged_count += 1;
                continue;
            }
            let classification = if left.equal_ignoring_strings(&right) {
                DiffClassification::StringOnly
            } else {
                DiffClassification::Structural
            };
            let display_diff = StructuralDiff::generate_normalized_display_diff(
                src1,
                src2,
                &left.lines(),
                &right.lines(),
                3,
            );

            let desc = if decl1.name != decl2.name {
                match classification {
                    DiffClassification::StringOnly => format!(
                        "{} '{}' (was '{}') — string-only",
                        kind_to_string(&decl1.kind),
                        decl2.name,
                        decl1.name
                    ),
                    DiffClassification::Structural => format!(
                        "{} '{}' (was '{}') — structural ({:.1}%)",
                        kind_to_string(&decl1.kind),
                        decl2.name,
                        decl1.name,
                        similarity * 100.0
                    ),
                    DiffClassification::Unchanged => unreachable!(),
                }
            } else {
                match classification {
                    DiffClassification::StringOnly => format!(
                        "{} '{}' — string-only",
                        kind_to_string(&decl1.kind),
                        decl1.name
                    ),
                    DiffClassification::Structural => format!(
                        "{} '{}' — structural ({:.1}%)",
                        kind_to_string(&decl1.kind),
                        decl1.name,
                        similarity * 100.0
                    ),
                    DiffClassification::Unchanged => unreachable!(),
                }
            };

            let structural_path = if decl1.name != decl2.name {
                format!("global.{}->{}", decl1.name, decl2.name)
            } else {
                format!("global.{}", decl1.name)
            };

            match classification {
                DiffClassification::StringOnly => string_only_count += 1,
                DiffClassification::Structural => structural_count += 1,
                _ => {}
            }

            changes.push(create_classified_change(
                ChangeType::Modification,
                Some(create_location_with_lines(decl1, &lines1)),
                Some(create_location_with_lines(decl2, &lines2)),
                desc,
                structural_path,
                classification,
                display_diff,
                Some(similarity),
            ));
        }

        eprintln!(
            "Phase B: {} unchanged, {} string-only, {} structural",
            unchanged_count, string_only_count, structural_count
        );

        // Add deletions and additions
        for (i, decl) in decls1.iter().enumerate() {
            if !matched1[i] {
                changes.push(create_change(
                    ChangeType::Deletion,
                    Some(create_location_with_lines(decl, &lines1)),
                    None,
                    format!("Removed {} '{}'", kind_to_string(&decl.kind), decl.name),
                    format!("global.{}", decl.name),
                ));
            }
        }

        for (i, decl) in decls2.iter().enumerate() {
            if !matched2[i] {
                changes.push(create_change(
                    ChangeType::Addition,
                    None,
                    Some(create_location_with_lines(decl, &lines2)),
                    format!("Added {} '{}'", kind_to_string(&decl.kind), decl.name),
                    format!("global.{}", decl.name),
                ));
            }
        }

        (matches, changes, rename_map)
    }
}

fn kinds_are_compatible(kind1: &DeclarationKind, kind2: &DeclarationKind) -> bool {
    kind1 == kind2
        || matches!(
            (kind1, kind2),
            (DeclarationKind::Function, DeclarationKind::Variable)
                | (DeclarationKind::Variable, DeclarationKind::Function)
        )
}

// Helper functions

/// Fixed-width signatures and the compile-time block invariant leave one gate.
fn passes_lsh_gate(sig1: &[u64; MINHASH_LANES], sig2: &[u64; MINHASH_LANES]) -> bool {
    let mut matching = 0usize;
    let mut uncompared = MINHASH_LANES;

    for (block1, block2) in sig1
        .chunks_exact(LSH_GATE_BLOCK_LANES)
        .zip(sig2.chunks_exact(LSH_GATE_BLOCK_LANES))
    {
        matching += block1.iter().zip(block2).filter(|(a, b)| a == b).count();
        uncompared -= LSH_GATE_BLOCK_LANES;

        if matching + uncompared < LSH_MIN_MATCHING_LANES {
            return false;
        }
    }

    matching >= LSH_MIN_MATCHING_LANES
}

fn should_match_with_score(similarity: f64, evidence_count: usize, size: usize) -> bool {
    if evidence_count > 0 {
        match evidence_count {
            1 => similarity >= 0.6,
            2 => similarity >= 0.45,
            3..=4 => similarity >= 0.4,
            _ => similarity >= 0.35,
        }
    } else {
        if similarity >= 0.85 {
            true
        } else if size < 10 {
            similarity >= 0.7
        } else if size < 50 {
            similarity >= 0.5
        } else {
            similarity >= 0.4
        }
    }
}

fn create_change(
    change_type: ChangeType,
    location1: Option<super::Location>,
    location2: Option<super::Location>,
    description: String,
    structural_path: String,
) -> super::Change {
    super::Change {
        change_type,
        location1,
        location2,
        description,
        structural_path,
        classification: None,
        display_diff: String::new(),
        similarity_score: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn create_classified_change(
    change_type: ChangeType,
    location1: Option<super::Location>,
    location2: Option<super::Location>,
    description: String,
    structural_path: String,
    classification: super::DiffClassification,
    display_diff: String,
    similarity_score: Option<f64>,
) -> super::Change {
    super::Change {
        change_type,
        location1,
        location2,
        description,
        structural_path,
        classification: Some(classification),
        display_diff,
        similarity_score,
    }
}

fn create_location_with_lines(decl: &Declaration, lines: &[&str]) -> super::Location {
    const MAX_SNIPPET_CHARS: usize = 200;
    let snippet = if decl.line > 0 && decl.line <= lines.len() {
        let line = lines[decl.line - 1].trim();
        let mut chars = line.chars();
        let prefix: String = chars.by_ref().take(MAX_SNIPPET_CHARS).collect();
        if chars.next().is_some() {
            format!("{prefix}…")
        } else {
            prefix
        }
    } else {
        String::new()
    };

    super::Location {
        line: decl.line,
        column: 0,
        code_snippet: snippet,
        end_line: Some(decl.end_line),
    }
}

fn kind_to_string(kind: &DeclarationKind) -> &'static str {
    match kind {
        DeclarationKind::Function => "function",
        DeclarationKind::Class => "class",
        DeclarationKind::Variable => "variable",
        DeclarationKind::Import => "import",
        DeclarationKind::Export => "export",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsh_gate_matches_the_reference_for_every_agreement_count() {
        let left = std::array::from_fn(|i| i as u64);
        for count in 0..=MINHASH_LANES {
            let right = std::array::from_fn(|i| {
                if i < count {
                    i as u64
                } else {
                    (i + MINHASH_LANES) as u64
                }
            });
            assert_eq!(
                passes_lsh_gate(&left, &right),
                count as f64 / MINHASH_LANES as f64 >= LSH_SIMILARITY_THRESHOLD
            );
        }
    }
}
