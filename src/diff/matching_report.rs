use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Detailed report of how matching decisions were made
#[derive(Debug, Serialize, Deserialize)]
pub struct MatchingReport {
    pub summary: MatchingSummary,
    pub matches: Vec<MatchDetail>,
    pub non_matches: Vec<NonMatchDetail>,
    pub borderline_cases: Vec<BorderlineCase>,
    pub statistics: MatchingStatistics,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MatchingSummary {
    pub total_functions_file1: usize,
    pub total_functions_file2: usize,
    pub confident_matches: usize,
    pub possible_matches: usize,
    pub non_matches: usize,
    pub threshold_used: f64,
    pub min_evidence_required: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MatchDetail {
    // Function identities
    pub func1: FunctionInfo,
    pub func2: FunctionInfo,

    // Matching scores
    pub final_score: f64,
    pub confidence_level: String, // "high", "medium", "low"

    // Evidence breakdown
    pub evidence: EvidenceBreakdown,

    // Why we matched
    pub matching_rationale: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NonMatchDetail {
    pub func: FunctionInfo,
    pub from_file: u8, // 1 or 2
    pub best_candidates: Vec<CandidateInfo>,
    pub why_no_match: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BorderlineCase {
    pub func1: FunctionInfo,
    pub func2: FunctionInfo,
    pub score: f64,
    pub evidence: EvidenceBreakdown,
    pub decision: String, // "matched" or "not_matched"
    pub distance_from_threshold: f64,
    pub suggestion: String, // What would change the decision
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub name: String,
    pub line: usize,
    pub size: usize,
    pub signature: String,
    pub first_line: String, // First line of code for context
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CandidateInfo {
    pub func: FunctionInfo,
    pub score: f64,
    pub evidence_count: usize,
    pub missing_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBreakdown {
    pub total_score: f64,
    pub evidence_count: usize,

    // Detailed evidence
    pub string_matches: Vec<StringMatch>,
    pub constant_matches: Vec<ConstantMatch>,
    pub api_matches: Vec<ApiMatch>,

    // What wasn't matched
    pub unique_to_func1: UniqueElements,
    pub unique_to_func2: UniqueElements,

    // Size analysis
    pub size_analysis: SizeAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringMatch {
    pub value: String,
    pub context: String,
    pub rarity_score: f64,
    pub contribution: f64, // How much this added to total score
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantMatch {
    pub value: String,
    pub type_: String, // "number", "regex", etc
    pub rarity_score: f64,
    pub contribution: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMatch {
    pub call: String, // e.g., "fs.readFileSync"
    pub first_arg: Option<String>,
    pub rarity_score: f64,
    pub contribution: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniqueElements {
    pub strings: Vec<(String, String)>, // (value, context)
    pub constants: Vec<String>,
    pub api_calls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeAnalysis {
    pub size1: usize,
    pub size2: usize,
    pub ratio: f64,
    pub size_penalty: f64,
    pub interpretation: String, // "likely enhanced", "significantly different", etc
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MatchingStatistics {
    pub string_importance: HashMap<String, f64>, // Which strings were most decisive
    pub threshold_effectiveness: ThresholdAnalysis,
    pub common_patterns: Vec<Pattern>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThresholdAnalysis {
    pub current_threshold: f64,
    pub decisions_near_threshold: usize, // Within 10% of threshold
    pub suggested_adjustments: Vec<ThresholdSuggestion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThresholdSuggestion {
    pub condition: String, // e.g., "When evidence_count >= 3"
    pub current_threshold: f64,
    pub suggested_threshold: f64,
    pub rationale: String,
    pub examples: Vec<String>, // Function pairs affected
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pattern {
    pub pattern_type: String,
    pub description: String,
    pub frequency: usize,
    pub examples: Vec<String>,
}

pub struct MatchingReportBuilder {
    matches: Vec<MatchDetail>,
    non_matches: Vec<NonMatchDetail>,
    borderline_cases: Vec<BorderlineCase>,
    all_scores: Vec<(String, String, f64, usize)>, // For statistics
    threshold: f64,
    min_evidence: usize,
}

impl MatchingReportBuilder {
    pub fn new(threshold: f64, min_evidence: usize) -> Self {
        Self {
            matches: Vec::new(),
            non_matches: Vec::new(),
            borderline_cases: Vec::new(),
            all_scores: Vec::new(),
            threshold,
            min_evidence,
        }
    }

    pub fn add_match(&mut self, detail: MatchDetail) {
        // Check if borderline
        let distance = (detail.final_score - self.threshold).abs();
        if distance < 0.1 {
            // Within 10% of threshold
            self.borderline_cases.push(BorderlineCase {
                func1: detail.func1.clone(),
                func2: detail.func2.clone(),
                score: detail.final_score,
                evidence: detail.evidence.clone(),
                decision: "matched".to_string(),
                distance_from_threshold: distance,
                suggestion: self.generate_suggestion(&detail),
            });
        }

        self.all_scores.push((
            detail.func1.name.clone(),
            detail.func2.name.clone(),
            detail.final_score,
            detail.evidence.evidence_count,
        ));

        self.matches.push(detail);
    }

    pub fn add_non_match(&mut self, detail: NonMatchDetail) {
        self.non_matches.push(detail);
    }

    fn generate_suggestion(&self, detail: &MatchDetail) -> String {
        if detail.evidence.evidence_count < self.min_evidence {
            format!(
                "Needs {} more evidence pieces for confident match",
                self.min_evidence - detail.evidence.evidence_count
            )
        } else if detail.final_score < self.threshold + 0.1 {
            "Consider lowering threshold or weighing unique strings more heavily".to_string()
        } else {
            "Strong match despite being near threshold".to_string()
        }
    }

    pub fn build(self, total1: usize, total2: usize) -> MatchingReport {
        let statistics = self.calculate_statistics();

        MatchingReport {
            summary: MatchingSummary {
                total_functions_file1: total1,
                total_functions_file2: total2,
                confident_matches: self
                    .matches
                    .iter()
                    .filter(|m| m.confidence_level == "high")
                    .count(),
                possible_matches: self
                    .matches
                    .iter()
                    .filter(|m| m.confidence_level != "high")
                    .count(),
                non_matches: self.non_matches.len(),
                threshold_used: self.threshold,
                min_evidence_required: self.min_evidence,
            },
            matches: self.matches,
            non_matches: self.non_matches,
            borderline_cases: self.borderline_cases,
            statistics,
        }
    }

    fn calculate_statistics(&self) -> MatchingStatistics {
        // Analyze which strings were most important
        let mut string_importance = HashMap::new();
        for match_detail in &self.matches {
            for string_match in &match_detail.evidence.string_matches {
                *string_importance
                    .entry(string_match.value.clone())
                    .or_insert(0.0) += string_match.contribution;
            }
        }

        // Threshold effectiveness
        let near_threshold = self
            .all_scores
            .iter()
            .filter(|(_, _, score, _)| (*score - self.threshold).abs() < 0.1)
            .count();

        let threshold_analysis = ThresholdAnalysis {
            current_threshold: self.threshold,
            decisions_near_threshold: near_threshold,
            suggested_adjustments: self.suggest_threshold_adjustments(),
        };

        // Common patterns
        let patterns = self.identify_patterns();

        MatchingStatistics {
            string_importance,
            threshold_effectiveness: threshold_analysis,
            common_patterns: patterns,
        }
    }

    fn suggest_threshold_adjustments(&self) -> Vec<ThresholdSuggestion> {
        let mut suggestions = Vec::new();

        // Analyze scores by evidence count
        let mut by_evidence: HashMap<usize, Vec<f64>> = HashMap::new();
        for (_, _, score, evidence) in &self.all_scores {
            by_evidence
                .entry(*evidence)
                .or_insert_with(Vec::new)
                .push(*score);
        }

        for (evidence_count, scores) in by_evidence {
            if scores.len() >= 3 {
                let avg = scores.iter().sum::<f64>() / scores.len() as f64;
                if (avg - self.threshold).abs() > 0.2 {
                    suggestions.push(ThresholdSuggestion {
                        condition: format!("evidence_count = {}", evidence_count),
                        current_threshold: self.threshold,
                        suggested_threshold: avg,
                        rationale: format!(
                            "Average score for {} evidence pieces is {:.2}",
                            evidence_count, avg
                        ),
                        examples: self
                            .all_scores
                            .iter()
                            .filter(|(_, _, _, e)| *e == evidence_count)
                            .take(3)
                            .map(|(f1, f2, _, _)| format!("{} <-> {}", f1, f2))
                            .collect(),
                    });
                }
            }
        }

        suggestions
    }

    fn identify_patterns(&self) -> Vec<Pattern> {
        let mut patterns = Vec::new();

        // Pattern: Functions with error messages
        let error_matches = self
            .matches
            .iter()
            .filter(|m| {
                m.evidence
                    .string_matches
                    .iter()
                    .any(|s| s.context == "ErrorMessage")
            })
            .count();

        if error_matches > 2 {
            patterns.push(Pattern {
                pattern_type: "error_string_matching".to_string(),
                description: "Functions with unique error messages match reliably".to_string(),
                frequency: error_matches,
                examples: self
                    .matches
                    .iter()
                    .filter(|m| {
                        m.evidence
                            .string_matches
                            .iter()
                            .any(|s| s.context == "ErrorMessage")
                    })
                    .take(3)
                    .map(|m| format!("{} <-> {}", m.func1.name, m.func2.name))
                    .collect(),
            });
        }

        // Pattern: Enhanced functions
        let enhanced = self
            .matches
            .iter()
            .filter(|m| m.evidence.size_analysis.interpretation.contains("enhanced"))
            .count();

        if enhanced > 2 {
            patterns.push(Pattern {
                pattern_type: "function_enhancement".to_string(),
                description: "Functions that grew in size but kept core strings".to_string(),
                frequency: enhanced,
                examples: self
                    .matches
                    .iter()
                    .filter(|m| m.evidence.size_analysis.interpretation.contains("enhanced"))
                    .take(3)
                    .map(|m| {
                        format!(
                            "{} -> {} (+{}%)",
                            m.func1.name,
                            m.func2.name,
                            ((m.evidence.size_analysis.ratio - 1.0) * 100.0) as i32
                        )
                    })
                    .collect(),
            });
        }

        patterns
    }
}

/// Generate markdown report for human/LLM review
pub fn generate_markdown_report(report: &MatchingReport) -> String {
    let mut md = String::new();

    md.push_str("# Function Matching Report\n\n");

    // Summary
    md.push_str("## Summary\n\n");
    md.push_str(&format!(
        "- File 1: {} functions\n",
        report.summary.total_functions_file1
    ));
    md.push_str(&format!(
        "- File 2: {} functions\n",
        report.summary.total_functions_file2
    ));
    md.push_str(&format!(
        "- Confident matches: {}\n",
        report.summary.confident_matches
    ));
    md.push_str(&format!(
        "- Possible matches: {}\n",
        report.summary.possible_matches
    ));
    md.push_str(&format!(
        "- No match found: {}\n",
        report.summary.non_matches
    ));
    md.push_str(&format!(
        "- Threshold: {:.2}\n",
        report.summary.threshold_used
    ));
    md.push_str(&format!(
        "- Min evidence: {}\n\n",
        report.summary.min_evidence_required
    ));

    // Borderline cases - most important for LLM review
    if !report.borderline_cases.is_empty() {
        md.push_str("## Borderline Cases (Need Review)\n\n");
        md.push_str("These matches are close to the threshold and may benefit from manual verification:\n\n");

        for case in &report.borderline_cases {
            md.push_str(&format!(
                "### {} ↔ {} (score: {:.2})\n",
                case.func1.name, case.func2.name, case.score
            ));
            md.push_str(&format!("- Decision: **{}**\n", case.decision));
            md.push_str(&format!(
                "- Distance from threshold: {:.2}\n",
                case.distance_from_threshold
            ));
            md.push_str(&format!(
                "- Evidence pieces: {}\n",
                case.evidence.evidence_count
            ));
            md.push_str(&format!("- Suggestion: {}\n", case.suggestion));

            // Show key evidence
            if !case.evidence.string_matches.is_empty() {
                md.push_str("- Key strings: ");
                for (i, s) in case.evidence.string_matches.iter().enumerate() {
                    if i > 0 {
                        md.push_str(", ");
                    }
                    md.push_str(&format!("`{}`", s.value));
                }
                md.push_str("\n");
            }
            md.push_str("\n");
        }
    }

    // Threshold suggestions
    if !report
        .statistics
        .threshold_effectiveness
        .suggested_adjustments
        .is_empty()
    {
        md.push_str("## Threshold Adjustment Suggestions\n\n");

        for suggestion in &report
            .statistics
            .threshold_effectiveness
            .suggested_adjustments
        {
            md.push_str(&format!(
                "- **{}**: {:.2} → {:.2}\n",
                suggestion.condition, suggestion.current_threshold, suggestion.suggested_threshold
            ));
            md.push_str(&format!("  - Rationale: {}\n", suggestion.rationale));
            md.push_str("  - Examples: ");
            for ex in &suggestion.examples {
                md.push_str(&format!("`{}` ", ex));
            }
            md.push_str("\n\n");
        }
    }

    // Patterns
    if !report.statistics.common_patterns.is_empty() {
        md.push_str("## Identified Patterns\n\n");

        for pattern in &report.statistics.common_patterns {
            md.push_str(&format!(
                "### {} ({}x)\n",
                pattern.pattern_type, pattern.frequency
            ));
            md.push_str(&format!("{}\n", pattern.description));
            md.push_str("Examples: ");
            for ex in &pattern.examples {
                md.push_str(&format!("`{}` ", ex));
            }
            md.push_str("\n\n");
        }
    }

    // Non-matches that might be mistakes
    md.push_str("## Potential Missed Matches\n\n");
    for nm in report.non_matches.iter().take(10) {
        if let Some(best) = nm.best_candidates.first() {
            if best.score > 0.4 {
                // Reasonably high score but didn't match
                md.push_str(&format!("- **{}** (line {})\n", nm.func.name, nm.func.line));
                md.push_str(&format!(
                    "  - Best candidate: {} (score: {:.2})\n",
                    best.func.name, best.score
                ));
                md.push_str(&format!("  - Evidence: {} pieces\n", best.evidence_count));
                if !best.missing_evidence.is_empty() {
                    md.push_str("  - Missing: ");
                    for me in &best.missing_evidence {
                        md.push_str(&format!("`{}` ", me));
                    }
                    md.push_str("\n");
                }
                md.push_str("\n");
            }
        }
    }

    md
}

/// Generate JSON for programmatic analysis
pub fn generate_llm_config_update(report: &MatchingReport) -> String {
    let config = serde_json::json!({
        "threshold_adjustments": report.statistics.threshold_effectiveness.suggested_adjustments,
        "high_value_strings": report.statistics.string_importance.iter()
            .filter(|(_, &imp)| imp > 1.0)
            .map(|(s, imp)| (s, imp))
            .collect::<Vec<_>>(),
        "borderline_verifications_needed": report.borderline_cases.iter()
            .map(|c| {
                serde_json::json!({
                    "func1": c.func1.name,
                    "func2": c.func2.name,
                    "score": c.score,
                    "current_decision": c.decision,
                })
            })
            .collect::<Vec<_>>(),
    });

    serde_json::to_string_pretty(&config).unwrap()
}
