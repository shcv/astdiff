use super::fingerprint::{
    self, calculate_fingerprint_similarity, FunctionFingerprint, RarityScorer,
};
use super::matching_report::EvidenceBreakdown;
use super::{Change, ChangeType, DeclarationData, DeclarationKind, DiffClassification};
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CandidateMatch {
    pub i1: usize,
    pub i2: usize,
    pub lsh_similarity: f64,
    pub name_match: bool, // True if names match exactly
}

#[derive(Debug, Clone)]
pub struct SimilarityResult {
    pub i1: usize,
    pub i2: usize,
    pub similarity: f64,
    pub evidence_count: usize,
    pub evidence_breakdown: Option<EvidenceBreakdown>,
    pub name_match: bool, // True if names match exactly
}

pub struct ParallelMatcherV2 {
    use_fingerprints: bool,
    batch_size: usize,
}

impl ParallelMatcherV2 {
    pub fn new(use_fingerprints: bool) -> Self {
        Self {
            use_fingerprints,
            batch_size: 1000, // Process LSH in batches of 1000
        }
    }

    pub fn match_declarations(
        &self,
        decls1: &[DeclarationData],
        decls2: &[DeclarationData],
        source1: &str,
        source2: &str,
        scorer: Option<&RarityScorer>,
        calculate_similarity: impl Fn(&DeclarationData, &DeclarationData, &str, &str) -> f64 + Sync,
        create_evidence: impl Fn(
                &DeclarationData,
                &DeclarationData,
                &FunctionFingerprint,
                &FunctionFingerprint,
                &RarityScorer,
            ) -> EvidenceBreakdown
            + Sync,
    ) -> (
        Vec<(usize, usize, f64)>,
        Vec<Change>,
        HashMap<String, String>,
    ) {
        use super::profiling::Timer;

        // Step 1: Build all potential pairs with size filtering
        let pairs = {
            let _timer = Timer::new("build_candidate_pairs");
            self.build_candidate_pairs(decls1, decls2)
        };

        eprintln!("Built {} candidate pairs to check", pairs.len());

        // Step 2: Parallel LSH filtering
        let lsh_candidates = {
            let _timer = Timer::new("parallel_lsh_filter");
            self.parallel_lsh_filter(&pairs, decls1, decls2)
        };

        eprintln!(
            "LSH filtering reduced to {} candidates",
            lsh_candidates.len()
        );

        // Step 3: Parallel full similarity calculation for remaining candidates
        let similarity_results = {
            let _timer = Timer::new("parallel_full_similarity");
            self.parallel_full_similarity(
                &lsh_candidates,
                decls1,
                decls2,
                source1,
                source2,
                scorer,
                &calculate_similarity,
                &create_evidence,
            )
        };

        // Step 4: Resolve best matches + normalize/diff all pairs
        let (matches, changes, rename_map) = {
            let _timer = Timer::new("resolve_matches");
            self.resolve_best_matches(similarity_results, decls1, decls2, source1, source2)
        };

        (matches, changes, rename_map)
    }

    fn build_candidate_pairs(
        &self,
        decls1: &[DeclarationData],
        decls2: &[DeclarationData],
    ) -> Vec<(usize, usize)> {
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

        let mut pairs = Vec::with_capacity(decls1.len() * 100); // Estimate ~100 candidates per declaration

        for (i1, decl1) in decls1.iter().enumerate() {
            // Stable names are anchors even when a declaration was extensively
            // rewritten and falls outside the structural size window.
            if let Some(indices) = exact_names2.get(decl1.name.as_str()) {
                for &i2 in indices {
                    if kinds_are_compatible(&decl1.kind, &decls2[i2].kind) {
                        pairs.push((i1, i2));
                    }
                }
            }

            let min_size = ((decl1.size as f64) * 0.5).max(1.0) as usize;
            let max_size = ((decl1.size as f64) * 1.5) as usize;

            // Binary search for window start
            let start_idx = sorted2.partition_point(|(_, size)| *size < min_size);

            // Add all pairs within size window and matching kind
            for idx in start_idx..sorted2.len() {
                let (i2, size2) = sorted2[idx];
                if size2 > max_size {
                    break;
                }

                if decl1.name != decls2[i2].name
                    && kinds_are_compatible(&decl1.kind, &decls2[i2].kind)
                {
                    pairs.push((i1, i2));
                }
            }
        }

        pairs
    }

    fn parallel_lsh_filter(
        &self,
        pairs: &[(usize, usize)],
        decls1: &[DeclarationData],
        decls2: &[DeclarationData],
    ) -> Vec<CandidateMatch> {
        let progress = AtomicUsize::new(0);
        let total = pairs.len();
        let last_update = Mutex::new(Instant::now());

        // Process in parallel batches
        let results = pairs
            .par_chunks(self.batch_size)
            .flat_map(|batch| {
                let mut local_results = Vec::with_capacity(batch.len() / 3); // Estimate 1/3 will pass

                for &(i1, i2) in batch {
                    let decl1 = &decls1[i1];
                    let decl2 = &decls2[i2];

                    // Always include pairs with matching names - they're almost certainly
                    // the same function/variable and need to be compared for string diffs
                    // even if structural similarity is low (e.g., template string content changed)
                    if decl1.name == decl2.name {
                        local_results.push(CandidateMatch {
                            i1,
                            i2,
                            lsh_similarity: 1.0, // Treat as high similarity for matching priority
                            name_match: true,
                        });
                        continue;
                    }

                    let lsh_sim = estimate_minhash_similarity(
                        &decl1.minhash_signature,
                        &decl2.minhash_signature,
                    );

                    if lsh_sim >= 0.3 {
                        local_results.push(CandidateMatch {
                            i1,
                            i2,
                            lsh_similarity: lsh_sim,
                            name_match: false,
                        });
                    }
                }

                // Report progress every second
                let done = progress.fetch_add(batch.len(), Ordering::Relaxed) + batch.len();

                if let Ok(mut last) = last_update.try_lock() {
                    if last.elapsed() >= Duration::from_secs(1) || done == total {
                        eprint!(
                            "\r  LSH filtering: {}/{} ({:.1}%)",
                            done,
                            total,
                            done as f64 / total as f64 * 100.0
                        );
                        *last = Instant::now();
                    }
                }

                local_results
            })
            .collect();

        // Clear the progress line with a final update
        eprintln!("\r  LSH filtering: {}/{} (100.0%) - Complete", total, total);

        results
    }

    fn parallel_full_similarity(
        &self,
        candidates: &[CandidateMatch],
        decls1: &[DeclarationData],
        decls2: &[DeclarationData],
        source1: &str,
        source2: &str,
        scorer: Option<&RarityScorer>,
        calculate_similarity: &(impl Fn(&DeclarationData, &DeclarationData, &str, &str) -> f64 + Sync),
        create_evidence: &(impl Fn(
            &DeclarationData,
            &DeclarationData,
            &FunctionFingerprint,
            &FunctionFingerprint,
            &RarityScorer,
        ) -> EvidenceBreakdown
              + Sync),
    ) -> Vec<SimilarityResult> {
        let progress = AtomicUsize::new(0);
        let total = candidates.len();
        let last_update = Mutex::new(Instant::now());

        let results = candidates
            .par_chunks(self.batch_size / 10) // Smaller batches for expensive calculations
            .flat_map(|batch| {
                let mut results = Vec::with_capacity(batch.len());

                for candidate in batch {
                    let decl1 = &decls1[candidate.i1];
                    let decl2 = &decls2[candidate.i2];

                    let (similarity, evidence_count, evidence_breakdown) = if self.use_fingerprints
                    {
                        if let (Some(ref fp1), Some(ref fp2), Some(s)) =
                            (&decl1.fingerprint, &decl2.fingerprint, scorer)
                        {
                            let (fp_score, ev_count) =
                                calculate_fingerprint_similarity(fp1, fp2, s);
                            let breakdown = create_evidence(decl1, decl2, fp1, fp2, s);
                            let struct_sim = calculate_similarity(decl1, decl2, source1, source2);
                            let combined = fp_score * 0.7 + struct_sim * 0.3;
                            (combined, ev_count, Some(breakdown))
                        } else {
                            (
                                calculate_similarity(decl1, decl2, source1, source2),
                                0,
                                None,
                            )
                        }
                    } else {
                        (
                            calculate_similarity(decl1, decl2, source1, source2),
                            0,
                            None,
                        )
                    };

                    // Apply thresholds - always include name matches
                    if candidate.name_match
                        || should_match_with_score(similarity, evidence_count, decl1.size)
                    {
                        results.push(SimilarityResult {
                            i1: candidate.i1,
                            i2: candidate.i2,
                            similarity,
                            evidence_count,
                            evidence_breakdown,
                            name_match: candidate.name_match,
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

    fn resolve_best_matches(
        &self,
        mut results: Vec<SimilarityResult>,
        decls1: &[DeclarationData],
        decls2: &[DeclarationData],
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
        let mut match_data: Vec<(usize, usize, f64)> = Vec::new(); // (i1, i2, similarity)

        for result in &results {
            if !matched1[result.i1] && !matched2[result.i2] {
                matched1[result.i1] = true;
                matched2[result.i2] = true;
                matches.push((result.i1, result.i2, result.similarity));
                match_data.push((result.i1, result.i2, result.similarity));

                let decl1 = &decls1[result.i1];
                let decl2 = &decls2[result.i2];

                // Build rename map inline: new_name → old_name
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

        for &(i1, i2, similarity) in &match_data {
            let decl1 = &decls1[i1];
            let decl2 = &decls2[i2];

            // Extract source for both declarations
            let src1 = super::extract_source_bytes(source1, decl1.start_byte, decl1.end_byte);
            let src2 = super::extract_source_bytes(source2, decl2.start_byte, decl2.end_byte);

            if src1.is_empty() || src2.is_empty() {
                // Can't extract source — skip diffing
                if decl1.name != decl2.name {
                    changes.push(create_classified_change(
                        ChangeType::Modification,
                        Some(create_location_with_lines(decl1, &lines1)),
                        Some(create_location_with_lines(decl2, &lines2)),
                        format!(
                            "{} '{}' matched with '{}' (was '{}')",
                            kind_to_string(&decl1.kind),
                            decl2.name,
                            decl1.name,
                            decl1.name
                        ),
                        format!("global.{}->{}", decl1.name, decl2.name),
                        DiffClassification::Unchanged,
                        String::new(),
                        Some(similarity),
                    ));
                    unchanged_count += 1;
                }
                continue;
            }

            // Normalize pipeline (order matters — keywords must survive for stripping):
            // 1. Comparison normalization on RAW source (canonicalize imports, strip
            //    var/let/const, strip trailing punct, collapse whitespace)
            // 2. Apply rename map to pre-normalized source2
            // 3. Blank minified identifiers on both
            let is_import = matches!(decl1.kind, DeclarationKind::Import);
            let pre_s1 = fingerprint::normalize_javascript_identifiers(src1, &HashMap::new());
            let pre_s2 = fingerprint::normalize_javascript_identifiers(src2, &rename_map);
            let comp_s1 = fingerprint::normalize_for_comparison(&pre_s1, is_import);
            let comp_s2 = fingerprint::normalize_for_comparison(&pre_s2, is_import);

            // Compare after syntax-aware identifier normalization.
            if comp_s1 == comp_s2 {
                unchanged_count += 1;
                continue;
            }

            // Generate display diff using comparison normalization for LCS alignment
            let display_diff = StructuralDiff::generate_normalized_display_diff(
                &src1, &src2, &comp_s1, &comp_s2, 3,
            );

            if display_diff.is_empty() {
                unchanged_count += 1;
                continue;
            }

            // Classify: string-only vs structural
            let classification = fingerprint::classify_diff_lines(&display_diff);

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

fn estimate_minhash_similarity(sig1: &[u64], sig2: &[u64]) -> f64 {
    let matches = sig1.iter().zip(sig2).filter(|(a, b)| a == b).count();
    matches as f64 / sig1.len() as f64
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

fn create_location_with_lines(decl: &DeclarationData, lines: &[&str]) -> super::Location {
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
