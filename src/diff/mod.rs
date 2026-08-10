use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use tree_sitter::{Node, Tree};

pub mod fingerprint;
pub mod matching_report;
pub mod parallel_matching_v2;
pub mod profiling;

use fingerprint::*;
use matching_report::*;

pub(crate) const MINHASH_LANES: usize = 128;

/// Represents a structural diff between two JavaScript ASTs
pub struct StructuralDiff {
    use_fingerprints: bool,
}

#[derive(Debug, Clone)]
pub struct Declaration {
    pub name: String,
    pub kind: DeclarationKind,
    pub line: usize,
    pub end_line: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub node_kind: String,
    pub signature: String,
    /// Sorted and deduplicated. Both consumers (MinHash, intersection count) are
    /// order-independent, and sequential u64s intersect far faster than a hash set
    /// whose RandomState re-hashes values that are already uniformly distributed.
    pub structural_hashes: Vec<u64>,
    pub size: usize,
    pub minhash_signature: Vec<u64>,
    pub fingerprint: Option<FunctionFingerprint>,
}

// Serializable version (same fields now that Node is gone)
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
            minhash_signature: decl.minhash_signature.clone(),
            fingerprint: decl.fingerprint.clone(),
        }
    }
}

// Thread-safe declaration data for parallel processing
#[derive(Debug, Clone)]
pub struct DeclarationData {
    name: String,
    kind: DeclarationKind,
    line: usize,
    end_line: usize,
    start_byte: usize,
    end_byte: usize,
    signature: String,
    structural_hashes: Vec<u64>,
    size: usize,
    minhash_signature: Vec<u64>,
    fingerprint: Option<FunctionFingerprint>,
}

impl Declaration {
    fn to_data(&self) -> DeclarationData {
        DeclarationData {
            name: self.name.clone(),
            kind: self.kind.clone(),
            line: self.line,
            end_line: self.end_line,
            start_byte: self.start_byte,
            end_byte: self.end_byte,
            signature: self.signature.clone(),
            structural_hashes: self.structural_hashes.clone(),
            size: self.size,
            minhash_signature: self.minhash_signature.clone(),
            fingerprint: self.fingerprint.clone(),
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

/// Extract an exact declaration range from UTF-8 source text.
/// Tree-sitter byte offsets are guaranteed to fall on character boundaries for
/// nodes produced from the same source. Invalid or stale ranges fail closed.
pub fn extract_source_bytes(source: &str, start_byte: usize, end_byte: usize) -> &str {
    source.get(start_byte..end_byte).unwrap_or("")
}

impl StructuralDiff {
    pub fn new() -> Self {
        Self {
            use_fingerprints: true, // Default to true for better accuracy
        }
    }

    pub fn extract_declarations_for_inspection<'a>(
        &self,
        root: Node<'a>,
        source: &str,
    ) -> Vec<Declaration> {
        self.extract_declarations(root, source)
    }

    pub fn set_use_fingerprints(&mut self, use_fingerprints: bool) {
        self.use_fingerprints = use_fingerprints;
    }

    /// Format string diff for display, highlighting important changes
    fn calculate_line_statistics(
        &self,
        result: &DiffResult,
        _source1: &str,
        _source2: &str,
    ) -> (usize, usize, usize) {
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

    pub fn compare(
        &self,
        source1: &str,
        source2: &str,
        tree1: &Tree,
        tree2: &Tree,
        dump: Option<&std::path::Path>,
        file1_path: &std::path::Path,
        file2_path: &std::path::Path,
    ) -> Result<DiffResult> {
        use crate::dump::{AstDiffDump, DiffConfig};
        use profiling::Timer;

        // Extract declarations
        let declarations1 = {
            let _timer = Timer::new("extract_declarations_file1");
            self.extract_declarations(tree1.root_node(), source1)
        };

        let declarations2 = {
            let _timer = Timer::new("extract_declarations_file2");
            self.extract_declarations(tree2.root_node(), source2)
        };

        // Compare declarations
        let need_dump = dump.is_some();
        let declarations1_clone = if need_dump {
            Some(declarations1.clone())
        } else {
            None
        };
        let declarations2_clone = if need_dump {
            Some(declarations2.clone())
        } else {
            None
        };

        let result = self.compare_declarations(declarations1, declarations2, source1, source2)?;

        // Dump if requested
        if let Some(dump_path) = dump {
            eprintln!("Creating comprehensive dump at {}", dump_path.display());

            let decls1_clone = declarations1_clone.unwrap();
            let decls2_clone = declarations2_clone.unwrap();
            let decls1: Vec<SerializableDeclaration> =
                decls1_clone.iter().map(|d| d.into()).collect();
            let decls2: Vec<SerializableDeclaration> =
                decls2_clone.iter().map(|d| d.into()).collect();

            let config = DiffConfig {
                use_fingerprints: self.use_fingerprints,
                parallel_matching: true,
                threshold: 0.5,
            };

            let dump = AstDiffDump::new(
                file1_path.to_path_buf(),
                file2_path.to_path_buf(),
                decls1,
                decls2,
                result.matched_pairs.clone(),
                result.clone(),
                config,
            )?;

            dump.save(dump_path)?;
        }

        Ok(result)
    }

    pub fn compare_declarations(
        &self,
        declarations1: Vec<Declaration>,
        declarations2: Vec<Declaration>,
        source1: &str,
        source2: &str,
    ) -> Result<DiffResult> {
        use profiling::Timer;

        eprintln!(
            "Extracted {} declarations from file1, {} from file2",
            declarations1.len(),
            declarations2.len()
        );

        // Match declarations — now returns rename map and pre-classified changes
        let (matches, changes, rename_map) = {
            let _timer = Timer::new("match_declarations_total");
            self.match_declarations(&declarations1, &declarations2, source1, source2)
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

    fn extract_declarations<'a>(&self, root: Node<'a>, source: &str) -> Vec<Declaration> {
        let mut declarations = Vec::new();
        self.extract_declarations_recursive(root, source, &mut declarations, true);
        declarations
    }

    fn create_declaration(
        &self,
        name: String,
        kind: DeclarationKind,
        line: usize,
        end_line: usize,
        start_byte: usize,
        end_byte: usize,
        node_kind: &str,
        signature: String,
        structural_hashes: Vec<u64>,
        fingerprint: Option<FunctionFingerprint>,
    ) -> Declaration {
        let size = structural_hashes.len();
        let minhash_signature = self.compute_minhash(&structural_hashes, MINHASH_LANES);

        Declaration {
            name,
            kind,
            line,
            end_line,
            start_byte,
            end_byte,
            node_kind: node_kind.to_string(),
            signature,
            structural_hashes,
            size,
            minhash_signature,
            fingerprint,
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
            "variable_declaration" if is_global => {
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
                if is_global && node == node.parent().map(|p| p.child(0)).flatten().unwrap_or(node)
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
    fn compute_minhash(&self, hashes: &[u64], num_hashes: usize) -> Vec<u64> {
        let mut signature = vec![u64::MAX; num_hashes];

        for &hash in hashes {
            for i in 0..num_hashes {
                let hash_value = self.hash_with_seed_u64(hash, i);
                signature[i] = signature[i].min(hash_value);
            }
        }

        signature
    }

    fn hash_with_seed_u64(&self, value: u64, seed: usize) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        seed.hash(&mut hasher);
        hasher.finish()
    }

    pub fn calculate_declaration_similarity(
        &self,
        decl1: &Declaration,
        decl2: &Declaration,
        _source1: &str,
        _source2: &str,
    ) -> f64 {
        // Delegate to the _data version via conversion
        let d1 = decl1.to_data();
        let d2 = decl2.to_data();
        self.calculate_declaration_similarity_data(&d1, &d2, "", "")
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
                | "template_string"
        )
    }

    fn is_order_independent(&self, node: Node) -> bool {
        matches!(
            node.kind(),
            "object" | "object_pattern" | "named_imports" | "export_clause"
        )
    }

    pub fn print_summary(
        &self,
        result: &DiffResult,
        file1: &std::path::PathBuf,
        file2: &std::path::PathBuf,
        source1: &str,
        source2: &str,
    ) {
        println!("--- {}", file1.display());
        println!("+++ {}", file2.display());
        println!("Structural similarity: {:.1}%", result.similarity * 100.0);
        println!(
            "Matched declarations: {}/{} vs {}",
            result.matched_declarations, result.total_declarations1, result.total_declarations2
        );

        // Calculate and print line statistics
        let (lines_added, lines_removed, total_diff) =
            self.calculate_line_statistics(result, source1, source2);
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
        norm1: &str,
        norm2: &str,
        context_lines: usize,
    ) -> String {
        use similar::{ChangeTag, TextDiff};

        let diff = TextDiff::from_lines(norm1, norm2);
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
                    ChangeTag::Delete | ChangeTag::Equal => change
                        .old_index()
                        .and_then(|i| orig_lines1.get(i))
                        .copied()
                        .unwrap_or(""),
                    ChangeTag::Insert => change
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
        file1: &std::path::PathBuf,
        file2: &std::path::PathBuf,
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
    pub fn print_compact_locations(
        &self,
        result: &DiffResult,
        file1: &std::path::PathBuf,
        file2: &std::path::PathBuf,
    ) {
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

    pub fn print_side_by_side(
        &self,
        result: &DiffResult,
        file1: &std::path::PathBuf,
        file2: &std::path::PathBuf,
        source1: &str,
        source2: &str,
    ) {
        println!("Structural similarity: {:.1}%", result.similarity * 100.0);
        println!();
        // Simplified implementation
        self.print_summary(result, file1, file2, source1, source2);
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

    pub fn match_declarations(
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
        use parallel_matching_v2::ParallelMatcherV2;
        use profiling::Timer;

        eprintln!(
            "Using parallel matching v2 for {} x {} declarations",
            decls1.len(),
            decls2.len()
        );

        // Convert to thread-safe data structures
        let data1: Vec<DeclarationData> = {
            let _timer = Timer::new("convert_to_data_structures");
            decls1.iter().map(|d| d.to_data()).collect()
        };
        let data2: Vec<DeclarationData> = decls2.iter().map(|d| d.to_data()).collect();

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

        let matcher = ParallelMatcherV2::new(self.use_fingerprints);

        matcher.match_declarations(
            &data1,
            &data2,
            source1,
            source2,
            scorer.as_ref(),
            |d1, d2, s1, s2| self.calculate_declaration_similarity_data(d1, d2, s1, s2),
            |d1, d2, fp1, fp2, s| self.create_evidence_breakdown_data(d1, d2, fp1, fp2, s),
        )
    }

    fn calculate_declaration_similarity_data(
        &self,
        decl1: &DeclarationData,
        decl2: &DeclarationData,
        _source1: &str,
        _source2: &str,
    ) -> f64 {
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

    fn create_evidence_breakdown_data(
        &self,
        decl1: &DeclarationData,
        decl2: &DeclarationData,
        fp1: &FunctionFingerprint,
        fp2: &FunctionFingerprint,
        scorer: &RarityScorer,
    ) -> EvidenceBreakdown {
        let mut string_matches = Vec::new();
        let mut constant_matches = Vec::new();
        let mut api_matches = Vec::new();

        // Match strings
        for s1 in &fp1.strings {
            for s2 in &fp2.strings {
                if s1.value == s2.value {
                    let rarity = scorer.score_string(&s1.value);
                    let context_weight = match s1.context {
                        StringContext::ErrorMessage => 1.2,
                        StringContext::FilePath => 1.1,
                        StringContext::CommandName => 1.0,
                        StringContext::ConfigKey => 0.9,
                        StringContext::ApiEndpoint => 1.0,
                        StringContext::Regular => 0.7,
                    };
                    string_matches.push(StringMatch {
                        value: s1.value.clone(),
                        context: format!("{:?}", s1.context),
                        rarity_score: rarity,
                        contribution: rarity * context_weight,
                    });
                    break;
                }
            }
        }

        // Match constants
        for c1 in &fp1.constants {
            for c2 in &fp2.constants {
                if c1.value == c2.value {
                    let rarity = scorer.score_constant(&c1.value);
                    constant_matches.push(ConstantMatch {
                        value: format!("{:?}", c1.value),
                        type_: match &c1.value {
                            ConstantValue::Number(_) => "number",
                            ConstantValue::Float(_) => "float",
                            ConstantValue::Regex(_) => "regex",
                            ConstantValue::Duration(_) => "duration",
                        }
                        .to_string(),
                        rarity_score: rarity,
                        contribution: rarity * 0.8,
                    });
                    break;
                }
            }
        }

        // Match API calls
        for api1 in &fp1.api_calls {
            for api2 in &fp2.api_calls {
                if api1.object == api2.object && api1.method == api2.method {
                    let rarity = scorer.score_api_call(api1);
                    api_matches.push(ApiMatch {
                        call: format!(
                            "{}.{}",
                            api1.object.as_deref().unwrap_or("global"),
                            api1.method
                        ),
                        first_arg: api1.first_arg.clone(),
                        rarity_score: rarity,
                        contribution: rarity * 0.6,
                    });
                    break;
                }
            }
        }

        // Calculate unique elements
        let unique_strings1: Vec<_> = fp1
            .strings
            .iter()
            .filter(|s| !fp2.strings.iter().any(|s2| s2.value == s.value))
            .map(|s| (s.value.clone(), format!("{:?}", s.context)))
            .collect();

        let unique_strings2: Vec<_> = fp2
            .strings
            .iter()
            .filter(|s| !fp1.strings.iter().any(|s1| s1.value == s.value))
            .map(|s| (s.value.clone(), format!("{:?}", s.context)))
            .collect();

        let unique_to_func1 = UniqueElements {
            strings: unique_strings1,
            constants: Vec::new(), // TODO: implement
            api_calls: Vec::new(), // TODO: implement
        };

        let unique_to_func2 = UniqueElements {
            strings: unique_strings2,
            constants: Vec::new(), // TODO: implement
            api_calls: Vec::new(), // TODO: implement
        };

        // Size analysis
        let size_ratio = decl2.size as f64 / decl1.size as f64;
        let interpretation = if size_ratio > 1.2 {
            "likely enhanced"
        } else if size_ratio < 0.8 {
            "significantly reduced"
        } else {
            "similar size"
        }
        .to_string();

        let total_score = string_matches.iter().map(|s| s.contribution).sum::<f64>()
            + constant_matches.iter().map(|c| c.contribution).sum::<f64>()
            + api_matches.iter().map(|a| a.contribution).sum::<f64>();

        let evidence_count = string_matches.len() + constant_matches.len() + api_matches.len();

        EvidenceBreakdown {
            total_score,
            evidence_count,
            string_matches,
            constant_matches,
            api_matches,
            unique_to_func1,
            unique_to_func2,
            size_analysis: SizeAnalysis {
                size1: decl1.size,
                size2: decl2.size,
                ratio: size_ratio,
                size_penalty: if size_ratio < 0.7 { 0.2 } else { 0.0 },
                interpretation,
            },
        }
    }
}
