use anyhow::Result;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::Path;
use tree_sitter::Node;

mod alpha;
pub mod fingerprint;
mod parallel_matching;
pub mod profiling;

use fingerprint::*;

pub(crate) const MINHASH_LANES: usize = 128;

/// Represents a structural diff between two JavaScript ASTs
pub struct StructuralDiff {
    use_fingerprints: bool,
}

impl Default for StructuralDiff {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct Declaration {
    pub name: String,
    pub kind: DeclarationKind,
    pub line: usize,
    pub end_line: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub node_kind: &'static str,
    pub signature: String,
    /// Sorted and deduplicated. Both consumers (MinHash, intersection count) are
    /// order-independent, and sequential u64s intersect far faster than a hash set
    /// whose RandomState re-hashes values that are already uniformly distributed.
    pub structural_hashes: Vec<u64>,
    pub size: usize,
    pub minhash_signature: [u64; MINHASH_LANES],
    pub fingerprint: Option<FunctionFingerprint>,
    pub(crate) comparison: alpha::Tokens,
}

// Serializable representation preserves the existing dump contract.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerializableDeclaration {
    pub name: String,
    pub kind: DeclarationKind,
    pub line: usize,
    pub end_line: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub signature: String,
    pub structural_hashes: HashSet<u64>,
    pub size: usize,
    pub minhash_signature: Vec<u64>,
    pub fingerprint: Option<FunctionFingerprint>,
}

impl From<&Declaration> for SerializableDeclaration {
    fn from(decl: &Declaration) -> Self {
        SerializableDeclaration {
            name: decl.name.clone(),
            kind: decl.kind.clone(),
            line: decl.line,
            end_line: decl.end_line,
            start_byte: decl.start_byte,
            end_byte: decl.end_byte,
            signature: decl.signature.clone(),
            // Converted here rather than changing the field type: the dump is a
            // bincode format on disk and existing dumps must stay loadable.
            structural_hashes: decl.structural_hashes.iter().copied().collect(),
            size: decl.size,
            minhash_signature: decl.minhash_signature.to_vec(),
            fingerprint: decl.fingerprint.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum DeclarationKind {
    Function,
    Variable,
    Class,
    Import,
    Export,
}

impl std::fmt::Display for DeclarationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeclarationKind::Function => write!(f, "function"),
            DeclarationKind::Variable => write!(f, "variable"),
            DeclarationKind::Class => write!(f, "class"),
            DeclarationKind::Import => write!(f, "import"),
            DeclarationKind::Export => write!(f, "export"),
        }
    }
}

/// Apply cross-kind penalty to similarity score.
/// Function <-> Variable swaps are common in minified code (small penalty).
/// Other kind mismatches get a larger penalty.
fn apply_kind_penalty(similarity: f64, kind1: &DeclarationKind, kind2: &DeclarationKind) -> f64 {
    if kind1 == kind2 {
        return similarity;
    }
    let is_func_var_swap = matches!(
        (kind1, kind2),
        (DeclarationKind::Function, DeclarationKind::Variable)
            | (DeclarationKind::Variable, DeclarationKind::Function)
    );
    similarity * if is_func_var_swap { 0.9 } else { 0.7 }
}

/// Number of values present in both sorted, deduplicated slices.
///
/// A straight merge rather than galloping: the only caller has already rejected any pair
/// whose size ratio is below 0.3, so the two sides are never skewed enough for binary
/// search to beat two sequential scans.
fn sorted_intersection_count(a: &[u64], b: &[u64]) -> usize {
    let mut count = 0;
    let mut i = 0;
    let mut j = 0;

    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
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

/// Classification of a matched declaration pair based on normalized diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffClassification {
    /// Empty normalized diff — pure rename or identical
    Unchanged,
    /// Only string literal values changed (code skeleton identical)
    StringOnly,
    /// Code logic changed (structural differences beyond strings)
    Structural,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub identical: bool,
    pub similarity: f64,
    pub changes: Vec<Change>,
    pub matched_declarations: usize,
    pub total_declarations1: usize,
    pub total_declarations2: usize,
    /// Rename map: new_name → old_name (file2 → file1) for normalizing source2 references
    #[serde(skip)]
    pub rename_map: HashMap<String, String>,
    #[serde(skip)]
    pub matched_pairs: Vec<(usize, usize, f64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub change_type: ChangeType,
    pub location1: Option<Location>,
    pub location2: Option<Location>,
    pub description: String,
    pub structural_path: String,
    /// Classification derived from normalized diff (None for Add/Delete)
    pub classification: Option<DiffClassification>,
    /// The display diff (original text, normalized comparison). Empty if Unchanged.
    #[serde(skip)]
    pub display_diff: String,
    /// Similarity score for matched pairs
    pub similarity_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeType {
    Addition,
    Deletion,
    Modification,
    Reorder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub line: usize,
    pub column: usize,
    pub code_snippet: String,
    pub end_line: Option<usize>, // Optional end line for line ranges
}

/// Extract source text by line range. O(1) with pre-built line vector.
/// Lines are 1-indexed (matching tree-sitter convention).
pub fn extract_source_range(lines: &[&str], start_line: usize, end_line: usize) -> String {
    if start_line == 0 || start_line > lines.len() {
        return String::new();
    }
    let start = start_line - 1; // Convert to 0-indexed
    let end = end_line.min(lines.len());
    if start >= end {
        return String::new();
    }
    lines[start..end].join("\n")
}

impl StructuralDiff {
    pub fn new() -> Self {
        Self {
            use_fingerprints: false, // Match the CLI default; fingerprints are opt-in.
        }
    }

    pub fn set_use_fingerprints(&mut self, use_fingerprints: bool) {
        self.use_fingerprints = use_fingerprints;
    }

    /// Count declarations affected by additions, deletions, and modifications.
    fn calculate_line_statistics(&self, result: &DiffResult) -> (usize, usize, usize) {
        let mut declarations_added = 0;
        let mut declarations_removed = 0;
        let mut declarations_modified = 0;

        for change in &result.changes {
            match change.change_type {
                ChangeType::Addition => declarations_added += 1,
                ChangeType::Deletion => declarations_removed += 1,
                ChangeType::Modification => match change.classification.as_ref() {
                    Some(DiffClassification::Structural) | Some(DiffClassification::StringOnly) => {
                        declarations_modified += 1;
                    }
                    _ => {}
                },
                ChangeType::Reorder => {}
            }
        }

        (
            declarations_added,
            declarations_removed,
            declarations_added + declarations_removed + declarations_modified,
        )
    }

    pub fn compare_declarations(
        &self,
        declarations1: &[Declaration],
        declarations2: &[Declaration],
        source1: &str,
        source2: &str,
    ) -> Result<DiffResult> {
        use profiling::Timer;

        for (declarations, source) in [(declarations1, source1), (declarations2, source2)] {
            for declaration in declarations {
                anyhow::ensure!(
                    declaration.start_byte < declaration.end_byte
                        && source
                            .get(declaration.start_byte..declaration.end_byte)
                            .is_some(),
                    "invalid source range for declaration '{}'",
                    declaration.name
                );
            }
        }

        eprintln!(
            "Extracted {} declarations from file1, {} from file2",
            declarations1.len(),
            declarations2.len()
        );

        // Match declarations — now returns rename map and pre-classified changes
        let (matches, changes, rename_map) = {
            let _timer = Timer::new("match_declarations_total");
            self.match_declarations(declarations1, declarations2, source1, source2)
        };

        let matched_declarations = matches.len();
        let total_declarations1 = declarations1.len();
        let total_declarations2 = declarations2.len();

        let similarity = if total_declarations1 == 0 && total_declarations2 == 0 {
            1.0
        } else {
            matched_declarations as f64 / total_declarations1.max(total_declarations2) as f64
        };

        Ok(DiffResult {
            identical: changes.is_empty(),
            similarity,
            changes,
            matched_declarations,
            total_declarations1,
            total_declarations2,
            rename_map,
            matched_pairs: matches,
        })
    }

    pub fn extract_declarations(
        &self,
        tree: &tree_sitter::Tree,
        source: &str,
    ) -> Result<Vec<Declaration>> {
        let mut declarations = Vec::new();
        let root = tree.root_node();
        let bindings = alpha::Bindings::new(root, source)?;
        self.extract_declarations_recursive(root, source, &mut declarations, true);
        for declaration in &mut declarations {
            let node = root
                .descendant_for_byte_range(declaration.start_byte, declaration.end_byte)
                .ok_or_else(|| anyhow::anyhow!("declaration range has no syntax node"))?;
            declaration.comparison = bindings.tokenize(node, source);
        }
        declarations.par_iter_mut().for_each(|declaration| {
            declaration.minhash_signature = Self::compute_minhash(&declaration.structural_hashes);
        });
        Ok(declarations)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_declaration(
        &self,
        name: String,
        kind: DeclarationKind,
        line: usize,
        end_line: usize,
        start_byte: usize,
        end_byte: usize,
        node_kind: &'static str,
        signature: String,
        structural_hashes: Vec<u64>,
        fingerprint: Option<FunctionFingerprint>,
    ) -> Declaration {
        let size = structural_hashes.len();

        Declaration {
            name,
            kind,
            line,
            end_line,
            start_byte,
            end_byte,
            node_kind,
            signature,
            structural_hashes,
            size,
            minhash_signature: [u64::MAX; MINHASH_LANES],
            fingerprint,
            comparison: alpha::Tokens::default(),
        }
    }

    fn extract_fingerprint(
        &self,
        node: Node,
        source: &str,
        kind: &DeclarationKind,
        name: &str,
    ) -> Option<FunctionFingerprint> {
        if !self.use_fingerprints {
            return None;
        }
        if !matches!(kind, DeclarationKind::Function | DeclarationKind::Variable) {
            return None;
        }
        let _timer = profiling::Timer::new("extract_fingerprint");
        let extractor = FingerprintExtractor::new(source);
        let fp = extractor.extract_function_fingerprint(node);

        if std::env::var("ASTDIFF_DEBUG").is_ok() && !fp.strings.is_empty() {
            eprintln!(
                "Fingerprint for {} '{}': {} strings, {} constants, {} API calls",
                kind,
                name,
                fp.strings.len(),
                fp.constants.len(),
                fp.api_calls.len()
            );
            for s in &fp.strings {
                eprintln!("  String: '{}' ({:?})", s.value, s.context);
            }
        }

        Some(fp)
    }

    fn extract_declarations_recursive<'a>(
        &self,
        node: Node<'a>,
        source: &str,
        declarations: &mut Vec<Declaration>,
        is_global: bool,
    ) {
        match node.kind() {
            "function_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = &source[name_node.byte_range()];
                    let kind = DeclarationKind::Function;
                    let fp = self.extract_fingerprint(node, source, &kind, name);
                    let signature = self.get_function_signature(node, source);
                    let structural_hashes = self.collect_structural_hashes(node, source);
                    declarations.push(self.create_declaration(
                        name.to_string(),
                        kind,
                        node.start_position().row + 1,
                        node.end_position().row + 1,
                        node.start_byte(),
                        node.end_byte(),
                        node.kind(),
                        signature,
                        structural_hashes,
                        fp,
                    ));
                }
            }
            "variable_declaration" | "lexical_declaration" if is_global => {
                for child in node.children(&mut node.walk()) {
                    if child.kind() == "variable_declarator" {
                        if child.child_by_field_name("value").is_none() {
                            continue;
                        }
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if name_node.kind() == "identifier" {
                                let name = &source[name_node.byte_range()];
                                let kind = DeclarationKind::Variable;
                                let fp = self.extract_fingerprint(child, source, &kind, name);
                                let signature = self.get_variable_signature(child, source);
                                let structural_hashes =
                                    if let Some(value_node) = child.child_by_field_name("value") {
                                        self.collect_structural_hashes(value_node, source)
                                    } else {
                                        Vec::new()
                                    };
                                declarations.push(self.create_declaration(
                                    name.to_string(),
                                    kind,
                                    child.start_position().row + 1,
                                    child.end_position().row + 1,
                                    child.start_byte(),
                                    child.end_byte(),
                                    child.kind(),
                                    signature,
                                    structural_hashes,
                                    fp,
                                ));
                            }
                        }
                    }
                }
            }
            "class_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = &source[name_node.byte_range()];
                    let kind = DeclarationKind::Class;
                    let fp = self.extract_fingerprint(node, source, &kind, name);
                    let signature = self.get_class_signature(node, source);
                    let structural_hashes = self.collect_structural_hashes(node, source);
                    declarations.push(self.create_declaration(
                        name.to_string(),
                        kind,
                        node.start_position().row + 1,
                        node.end_position().row + 1,
                        node.start_byte(),
                        node.end_byte(),
                        node.kind(),
                        signature,
                        structural_hashes,
                        fp,
                    ));
                }
            }
            "import_statement" => {
                let kind = DeclarationKind::Import;
                let name = format!("import@{}", node.start_position().row);
                let fp = self.extract_fingerprint(node, source, &kind, &name);
                let signature = self.get_import_signature(node, source);
                let structural_hashes = self.collect_structural_hashes(node, source);
                declarations.push(self.create_declaration(
                    name,
                    kind,
                    node.start_position().row + 1,
                    node.end_position().row + 1,
                    node.start_byte(),
                    node.end_byte(),
                    node.kind(),
                    signature,
                    structural_hashes,
                    fp,
                ));
            }
            "export_statement" => {
                if let Some(decl) = node.child_by_field_name("declaration") {
                    self.extract_declarations_recursive(decl, source, declarations, is_global);
                } else {
                    let kind = DeclarationKind::Export;
                    let name = format!("export@{}", node.start_position().row);
                    let fp = self.extract_fingerprint(node, source, &kind, &name);
                    let signature = self.get_export_signature(node, source);
                    let structural_hashes = self.collect_structural_hashes(node, source);
                    declarations.push(self.create_declaration(
                        name,
                        kind,
                        node.start_position().row + 1,
                        node.end_position().row + 1,
                        node.start_byte(),
                        node.end_byte(),
                        node.kind(),
                        signature,
                        structural_hashes,
                        fp,
                    ));
                }
            }
            _ => {
                // Only look for global declarations at the top level
                if is_global
                    && node
                        == node
                            .parent()
                            .and_then(|parent| parent.child(0))
                            .unwrap_or(node)
                {
                    for child in node.children(&mut node.walk()) {
                        self.extract_declarations_recursive(
                            child,
                            source,
                            declarations,
                            child.kind() != "function_declaration"
                                && child.kind() != "class_declaration",
                        );
                    }
                }
            }
        }
    }
    fn collect_structural_hashes(&self, node: Node, source: &str) -> Vec<u64> {
        let mut hashes = Vec::new();
        let mut scratch = Vec::new();
        self.collect_structural_hashes_recursive(node, source, &mut hashes, &mut scratch);

        // Dedup here is not an optimization: `size` and the Jaccard denominator are
        // both set cardinalities, so the vector has to carry each hash once.
        hashes.sort_unstable();
        hashes.dedup();
        hashes.shrink_to_fit();

        hashes
    }

    /// Hashes `node`, inserts its hash plus every descendant's into `hashes`, and returns it.
    ///
    /// A node's hash depends only on its own subtree, so the old separate `compute_structural_hash`
    /// pass re-walked a subtree the collector was already walking; folding the two into one
    /// post-order pass visits each node exactly once for the same result.
    ///
    /// `scratch` is a shared stack of child hashes: each frame owns the slice from `base` onwards
    /// and truncates back to it before returning, so the whole traversal shares one allocation
    /// instead of allocating a `Vec` per internal node.
    fn collect_structural_hashes_recursive(
        &self,
        node: Node,
        source: &str,
        hashes: &mut Vec<u64>,
        scratch: &mut Vec<u64>,
    ) -> u64 {
        use std::collections::hash_map::DefaultHasher;

        let is_literal = self.is_literal(node);
        let is_identifier = node.kind() == "identifier";
        let base = scratch.len();

        // Literals and identifiers ignore their children when hashing, but the walk still descends
        // into them so that descendants (a template_string's substitutions, say) reach the set.
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if !matches!(child.kind(), "comment") {
                    let child_hash =
                        self.collect_structural_hashes_recursive(child, source, hashes, scratch);
                    let contributes = !is_literal
                        && !is_identifier
                        && !matches!(child.kind(), ";" | "," | "(" | ")" | "{" | "}" | "[" | "]");
                    if contributes {
                        scratch.push(child_hash);
                    }
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        let mut hasher = DefaultHasher::new();

        // Hash node type
        node.kind().hash(&mut hasher);

        // For literals, include the value
        if is_literal {
            source[node.byte_range()].hash(&mut hasher);
        } else if is_identifier {
            // For identifiers, just use a placeholder
            "<ID>".hash(&mut hasher);
        } else {
            // Sort child hashes for order-independent nodes
            if self.is_order_independent(node) {
                scratch[base..].sort();
            }
            for hash in &scratch[base..] {
                hash.hash(&mut hasher);
            }
        }

        scratch.truncate(base);

        let hash = hasher.finish();
        hashes.push(hash);

        hash
    }

    fn get_function_signature(&self, node: Node, _source: &str) -> String {
        let params = if let Some(params_node) = node.child_by_field_name("parameters") {
            let param_count = params_node
                .children(&mut params_node.walk())
                .filter(|n| n.kind() == "identifier" || n.kind() == "formal_parameters")
                .count();
            format!("params:{}", param_count)
        } else {
            "params:0".to_string()
        };

        let body = if let Some(body_node) = node.child_by_field_name("body") {
            let statement_count = body_node
                .children(&mut body_node.walk())
                .filter(|n| !matches!(n.kind(), "{" | "}" | ";"))
                .count();
            format!("stmts:{}", statement_count)
        } else {
            "stmts:0".to_string()
        };

        format!("function({},{})", params, body)
    }

    fn get_variable_signature(&self, node: Node, source: &str) -> String {
        if let Some(init) = node.child_by_field_name("value") {
            match init.kind() {
                "number" => format!("var=number:{}", &source[init.byte_range()]),
                "string" => format!("var=string:len{}", source[init.byte_range()].len()),
                "true" | "false" => format!("var=bool:{}", init.kind()),
                "array" => format!("var=array:len{}", init.children(&mut init.walk()).count()),
                "object" => format!(
                    "var=object:props{}",
                    init.children(&mut init.walk())
                        .filter(|n| n.kind() == "pair")
                        .count()
                ),
                "arrow_function" | "function" => {
                    let param_count = if let Some(params) = init.child_by_field_name("parameters") {
                        params.children(&mut params.walk()).count()
                    } else if init.child_by_field_name("parameter").is_some() {
                        1
                    } else {
                        0
                    };
                    format!("var=function:params{}", param_count)
                }
                _ => format!("var={}", init.kind()),
            }
        } else {
            "var=undefined".to_string()
        }
    }

    fn get_class_signature(&self, node: Node, _source: &str) -> String {
        if let Some(body) = node.child_by_field_name("body") {
            let method_count = body
                .children(&mut body.walk())
                .filter(|n| n.kind() == "method_definition")
                .count();
            let field_count = body
                .children(&mut body.walk())
                .filter(|n| n.kind() == "field_definition")
                .count();
            format!("class(methods:{},fields:{})", method_count, field_count)
        } else {
            "class()".to_string()
        }
    }

    fn get_import_signature(&self, node: Node, source: &str) -> String {
        let source_path = node
            .children(&mut node.walk())
            .find(|n| n.kind() == "string")
            .map(|n| &source[n.byte_range()])
            .unwrap_or("");
        format!("import from {}", source_path)
    }

    fn get_export_signature(&self, node: Node, _source: &str) -> String {
        if node.child_by_field_name("declaration").is_some() {
            "export declaration".to_string()
        } else if let Some(clause) = node.child_by_field_name("clause") {
            let export_count = clause
                .children(&mut clause.walk())
                .filter(|n| n.kind() == "export_specifier")
                .count();
            format!("export {} items", export_count)
        } else {
            "export".to_string()
        }
    }
    fn compute_minhash(hashes: &[u64]) -> [u64; MINHASH_LANES] {
        let mut signature = [u64::MAX; MINHASH_LANES];
        for &hash in hashes {
            let mut prefix = std::collections::hash_map::DefaultHasher::new();
            hash.hash(&mut prefix);
            for (seed, slot) in signature.iter_mut().enumerate() {
                let mut hasher = prefix.clone();
                seed.hash(&mut hasher);
                *slot = (*slot).min(hasher.finish());
            }
        }
        signature
    }

    fn is_literal(&self, node: Node) -> bool {
        matches!(
            node.kind(),
            "string"
                | "number"
                | "true"
                | "false"
                | "null"
                | "undefined"
                | "regex"
                | "string_fragment"
        )
    }

    fn is_order_independent(&self, node: Node) -> bool {
        matches!(
            node.kind(),
            "object" | "object_pattern" | "named_imports" | "export_clause"
        )
    }

    pub fn print_summary(&self, result: &DiffResult, file1: &Path, file2: &Path) {
        println!("--- {}", file1.display());
        println!("+++ {}", file2.display());
        println!("Structural similarity: {:.1}%", result.similarity * 100.0);
        println!(
            "Matched declarations: {}/{} vs {}",
            result.matched_declarations, result.total_declarations1, result.total_declarations2
        );

        // Calculate and print line statistics
        let (lines_added, lines_removed, total_diff) = self.calculate_line_statistics(result);
        println!(
            "Diff size: {} declarations (+{} added, -{} removed)",
            total_diff, lines_added, lines_removed
        );

        // Group changes by type using classification
        let mut additions = Vec::new();
        let mut deletions = Vec::new();
        let mut structural_changes = Vec::new();
        let mut string_changes = Vec::new();

        for change in &result.changes {
            match change.change_type {
                ChangeType::Addition => additions.push(change),
                ChangeType::Deletion => deletions.push(change),
                ChangeType::Modification => {
                    match change.classification.as_ref() {
                        Some(DiffClassification::Structural) => structural_changes.push(change),
                        Some(DiffClassification::StringOnly) => string_changes.push(change),
                        _ => {} // Unchanged — not shown
                    }
                }
                ChangeType::Reorder => {}
            }
        }

        let total_unchanged = result
            .matched_declarations
            .saturating_sub(structural_changes.len())
            .saturating_sub(string_changes.len());

        println!(
            "Changes: {} added, {} removed, {} structural, {} string-only ({} unchanged)",
            additions.len(),
            deletions.len(),
            structural_changes.len(),
            string_changes.len(),
            total_unchanged
        );
        println!();

        // Show deletions
        if !deletions.is_empty() {
            println!("=== Removed ===");
            for change in &deletions {
                println!("--- {}", change.description);
                if let Some(loc) = &change.location1 {
                    println!("    at line {}: {}", loc.line, loc.code_snippet);
                }
            }
            println!();
        }

        // Show additions
        if !additions.is_empty() {
            println!("=== Added ===");
            for change in &additions {
                println!("+++ {}", change.description);
                if let Some(loc) = &change.location2 {
                    println!("    at line {}: {}", loc.line, loc.code_snippet);
                }
            }
            println!();
        }

        // Show structural changes
        if !structural_changes.is_empty() {
            println!("=== Structural Changes ===");
            for change in &structural_changes {
                println!("@@@ {}", change.description);
                if let Some(loc) = &change.location1 {
                    println!("  - at line {}: {}", loc.line, loc.code_snippet);
                }
                if let Some(loc) = &change.location2 {
                    println!("  + at line {}: {}", loc.line, loc.code_snippet);
                }
            }
            println!();
        }

        // Show string changes
        if !string_changes.is_empty() {
            println!("=== String Changes ===");
            for change in &string_changes {
                println!("@@@ {}", change.description);
                if let Some(loc) = &change.location1 {
                    println!("  - at line {}: {}", loc.line, loc.code_snippet);
                }
                if let Some(loc) = &change.location2 {
                    println!("  + at line {}: {}", loc.line, loc.code_snippet);
                }
            }
            println!();
        }
    }

    pub fn generate_normalized_display_diff(
        orig1: &str,
        orig2: &str,
        norm1: &[String],
        norm2: &[String],
        context_lines: usize,
    ) -> String {
        use similar::{ChangeTag, TextDiff};

        let left = norm1.iter().map(String::as_str).collect::<Vec<_>>();
        let right = norm2.iter().map(String::as_str).collect::<Vec<_>>();
        let diff = TextDiff::from_slices(&left, &right);
        let orig_lines1: Vec<&str> = orig1.lines().collect();
        let orig_lines2: Vec<&str> = orig2.lines().collect();

        let mut output = String::new();
        let mut has_changes = false;

        for hunk in diff
            .unified_diff()
            .context_radius(context_lines)
            .iter_hunks()
        {
            has_changes = true;
            output.push_str(&format!("{}\n", hunk.header()));
            for change in hunk.iter_changes() {
                let sign = match change.tag() {
                    ChangeTag::Delete => "-",
                    ChangeTag::Insert => "+",
                    ChangeTag::Equal => " ",
                };
                // Look up the original (non-normalized) line at the same index
                let orig_line = match change.tag() {
                    ChangeTag::Delete => change
                        .old_index()
                        .and_then(|i| orig_lines1.get(i))
                        .copied()
                        .unwrap_or(""),
                    ChangeTag::Insert | ChangeTag::Equal => change
                        .new_index()
                        .and_then(|i| orig_lines2.get(i))
                        .copied()
                        .unwrap_or(""),
                };
                output.push_str(sign);
                output.push_str(orig_line);
                if !orig_line.ends_with('\n') {
                    output.push('\n');
                }
            }
        }

        if has_changes {
            output
        } else {
            String::new()
        }
    }

    pub fn print_default(
        &self,
        result: &DiffResult,
        file1: &Path,
        file2: &Path,
        source1: &str,
        source2: &str,
    ) -> Result<()> {
        let file1_name = file1
            .file_name()
            .unwrap_or(file1.as_os_str())
            .to_string_lossy();
        let file2_name = file2
            .file_name()
            .unwrap_or(file2.as_os_str())
            .to_string_lossy();

        println!("--- {}", file1.display());
        println!("+++ {}", file2.display());
        println!("Structural similarity: {:.1}%", result.similarity * 100.0);
        println!(
            "Matched: {}/{} vs {}",
            result.matched_declarations, result.total_declarations1, result.total_declarations2
        );

        // Classify changes
        let mut additions = Vec::new();
        let mut deletions = Vec::new();
        let mut structural = Vec::new();
        let mut string_only = Vec::new();
        for change in &result.changes {
            match change.change_type {
                ChangeType::Addition => additions.push(change),
                ChangeType::Deletion => deletions.push(change),
                ChangeType::Modification => match change.classification.as_ref() {
                    Some(DiffClassification::Structural) => structural.push(change),
                    Some(DiffClassification::StringOnly) => string_only.push(change),
                    Some(DiffClassification::Unchanged) | None => {}
                },
                ChangeType::Reorder => {} // Implicit in location
            }
        }

        // Count unchanged as: matched - structural - string_only
        let total_unchanged = result
            .matched_declarations
            .saturating_sub(structural.len())
            .saturating_sub(string_only.len());

        println!(
            "Changes: {} added, {} removed, {} structural, {} string-only ({} unchanged)",
            additions.len(),
            deletions.len(),
            structural.len(),
            string_only.len(),
            total_unchanged
        );
        println!();

        // === Removed ===
        if !deletions.is_empty() {
            println!("=== Removed ===");
            let lines1: Vec<&str> = source1.lines().collect();
            for change in &deletions {
                if let Some(loc) = &change.location1 {
                    let end = loc.end_line.unwrap_or(loc.line);
                    println!(
                        "\n--- Removed {} ({}:{}-{})",
                        Self::extract_name_from_desc(&change.description),
                        file1_name,
                        loc.line,
                        end
                    );
                    let body = extract_source_range(&lines1, loc.line, end);
                    for line in body.lines() {
                        println!("- {}", line);
                    }
                }
            }
            println!();
        }

        // === Added ===
        if !additions.is_empty() {
            println!("=== Added ===");
            let lines2: Vec<&str> = source2.lines().collect();
            for change in &additions {
                if let Some(loc) = &change.location2 {
                    let end = loc.end_line.unwrap_or(loc.line);
                    println!(
                        "\n+++ Added {} ({}:{}-{})",
                        Self::extract_name_from_desc(&change.description),
                        file2_name,
                        loc.line,
                        end
                    );
                    let body = extract_source_range(&lines2, loc.line, end);
                    for line in body.lines() {
                        println!("+ {}", line);
                    }
                }
            }
            println!();
        }

        // === Structural Changes ===
        if !structural.is_empty() {
            println!("=== Structural Changes ===");
            for change in &structural {
                if let (Some(loc1), Some(loc2)) = (&change.location1, &change.location2) {
                    println!("\n@@@ {}", change.description);
                    println!("--- {}:{}", file1_name, loc1.line);
                    println!("+++ {}:{}", file2_name, loc2.line);
                    if !change.display_diff.is_empty() {
                        print!("{}", change.display_diff);
                    }
                }
            }
            println!();
        }

        // === String Changes ===
        if !string_only.is_empty() {
            println!("=== String Changes ===");
            for change in &string_only {
                if let (Some(loc1), Some(loc2)) = (&change.location1, &change.location2) {
                    println!("\n@@@ {}", change.description);
                    println!("--- {}:{}", file1_name, loc1.line);
                    println!("+++ {}:{}", file2_name, loc2.line);
                    if !change.display_diff.is_empty() {
                        print!("{}", change.display_diff);
                    }
                }
            }
            println!();
        }

        Ok(())
    }

    /// Compact output: location-only summary grouped by classification.
    pub fn print_compact_locations(&self, result: &DiffResult, file1: &Path, file2: &Path) {
        let file1_name = file1
            .file_name()
            .unwrap_or(file1.as_os_str())
            .to_string_lossy();
        let file2_name = file2
            .file_name()
            .unwrap_or(file2.as_os_str())
            .to_string_lossy();

        // Classify changes
        let mut additions = Vec::new();
        let mut deletions = Vec::new();
        let mut structural = Vec::new();
        let mut string_only = Vec::new();

        for change in &result.changes {
            match change.change_type {
                ChangeType::Addition => additions.push(change),
                ChangeType::Deletion => deletions.push(change),
                ChangeType::Modification => {
                    match change.classification.as_ref() {
                        Some(DiffClassification::Structural) => structural.push(change),
                        Some(DiffClassification::StringOnly) => string_only.push(change),
                        _ => {} // Unchanged — not shown
                    }
                }
                ChangeType::Reorder => {}
            }
        }

        let total_unchanged = result
            .matched_declarations
            .saturating_sub(structural.len())
            .saturating_sub(string_only.len());

        // Removed
        if !deletions.is_empty() {
            println!("Removed: {}", deletions.len());
            for change in &deletions {
                if let Some(loc) = &change.location1 {
                    let end = loc.end_line.unwrap_or(loc.line);
                    let name = Self::extract_name_from_desc(&change.description);
                    println!("  {} ({}:{}-{})", name, file1_name, loc.line, end);
                }
            }
            println!();
        }

        // Added
        if !additions.is_empty() {
            println!("Added: {}", additions.len());
            for change in &additions {
                if let Some(loc) = &change.location2 {
                    let end = loc.end_line.unwrap_or(loc.line);
                    let name = Self::extract_name_from_desc(&change.description);
                    println!("  {} ({}:{}-{})", name, file2_name, loc.line, end);
                }
            }
            println!();
        }

        // Structural
        if !structural.is_empty() {
            println!("Structural: {}", structural.len());
            for change in &structural {
                if let (Some(loc1), Some(loc2)) = (&change.location1, &change.location2) {
                    let name = Self::extract_name_from_desc(&change.description);
                    let sim = change
                        .similarity_score
                        .map(|s| format!(" {:.1}%", s * 100.0))
                        .unwrap_or_default();
                    println!(
                        "  {} ({}:{} -> {}:{}){}",
                        name, file1_name, loc1.line, file2_name, loc2.line, sim
                    );
                }
            }
            println!();
        }

        // String-only
        if !string_only.is_empty() {
            println!("String-only: {}", string_only.len());
            for change in &string_only {
                if let (Some(loc1), Some(loc2)) = (&change.location1, &change.location2) {
                    let name = Self::extract_name_from_desc(&change.description);
                    println!(
                        "  {} ({}:{} -> {}:{})",
                        name, file1_name, loc1.line, file2_name, loc2.line
                    );
                }
            }
            println!();
        }

        println!("Unchanged: {} (not shown)", total_unchanged);
    }

    /// Extract declaration name from a description string.
    fn extract_name_from_desc(desc: &str) -> &str {
        // Try patterns like "function 'foo' ..." or "Removed function 'foo'"
        if let Some(start) = desc.find('\'') {
            if let Some(end) = desc[start + 1..].find('\'') {
                return &desc[start + 1..start + 1 + end];
            }
        }
        desc
    }

    pub fn print_json(&self, result: &DiffResult) -> Result<()> {
        let json = serde_json::to_string_pretty(result)?;
        println!("{}", json);
        Ok(())
    }

    pub fn generate_rename_mapping(&self, result: &DiffResult) -> HashMap<String, String> {
        // DiffResult stores new -> old so source2 can be normalized to source1.
        // Export the human-facing evolution direction, old -> new.
        result
            .rename_map
            .iter()
            .map(|(new_name, old_name)| (old_name.clone(), new_name.clone()))
            .collect()
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn match_declarations(
        &self,
        decls1: &[Declaration],
        decls2: &[Declaration],
        source1: &str,
        source2: &str,
    ) -> (
        Vec<(usize, usize, f64)>,
        Vec<Change>,
        HashMap<String, String>,
    ) {
        use parallel_matching::ParallelMatcher;
        use profiling::Timer;

        eprintln!("Matching {} x {} declarations", decls1.len(), decls2.len());

        // Build rarity scorer if using fingerprints
        let scorer = if self.use_fingerprints {
            let _timer = Timer::new("build_rarity_scorer_parallel");
            let mut scorer = RarityScorer::new();
            for decl in decls1.iter().chain(decls2.iter()) {
                if let Some(ref fp) = decl.fingerprint {
                    scorer.add_fingerprint(fp);
                }
            }
            Some(scorer)
        } else {
            None
        };

        let matcher = ParallelMatcher::new(self.use_fingerprints);

        matcher.match_declarations(decls1, decls2, source1, source2, scorer.as_ref())
    }
}

pub fn declaration_similarity(decl1: &Declaration, decl2: &Declaration) -> f64 {
    // For imports and exports, use signature similarity regardless of kind
    if matches!(
        decl1.kind,
        DeclarationKind::Import | DeclarationKind::Export
    ) || matches!(
        decl2.kind,
        DeclarationKind::Import | DeclarationKind::Export
    ) {
        return if decl1.signature == decl2.signature {
            1.0
        } else {
            0.3
        };
    }

    let size1 = decl1.structural_hashes.len();
    let size2 = decl2.structural_hashes.len();

    if size1 == 0 && size2 == 0 {
        let base = if decl1.signature == decl2.signature {
            1.0
        } else {
            0.5
        };
        return apply_kind_penalty(base, &decl1.kind, &decl2.kind);
    }

    // If one is much larger than the other, they can't be similar enough
    let size_ratio = size1.min(size2) as f64 / size1.max(size2) as f64;
    if size_ratio < 0.3 {
        return 0.2;
    }

    // Jaccard similarity from structural hash intersection.
    // Count directly instead of materializing the two sets: this runs once per
    // surviving candidate pair (50M+ on a large bundle), and collecting sets
    // just to read .len() off them was the single hottest allocation in the
    // tool. |A u B| = |A| + |B| - |A n B| makes the union free.
    let intersection =
        sorted_intersection_count(&decl1.structural_hashes, &decl2.structural_hashes);
    let union = size1 + size2 - intersection;
    let base_similarity = intersection as f64 / union as f64;

    apply_kind_penalty(base_similarity, &decl1.kind, &decl2.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minhash_prefix_reuse_preserves_all_lanes() {
        for hashes in [
            vec![],
            vec![0],
            vec![u64::MAX, 17, 500, 0],
            (0..200).map(|n| n * 913).collect(),
        ] {
            let expected = std::array::from_fn(|seed: usize| {
                hashes
                    .iter()
                    .map(|hash| {
                        let mut hasher = std::collections::hash_map::DefaultHasher::new();
                        hash.hash(&mut hasher);
                        seed.hash(&mut hasher);
                        hasher.finish()
                    })
                    .min()
                    .unwrap_or(u64::MAX)
            });
            assert_eq!(StructuralDiff::compute_minhash(&hashes), expected);
        }
    }
}
