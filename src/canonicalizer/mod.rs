use crate::scope::{Scope, ScopeAnalyzer, VariableKind};
use anyhow::Result;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use tree_sitter::{Node, Tree};

pub struct Canonicalizer {
    pub scope_analyzer: ScopeAnalyzer,
    canonical_mappings: HashMap<String, CanonicalMapping>,
    counters: NameCounters,
}

#[derive(Debug, Clone)]
pub struct CanonicalMapping {
    pub original_name: String,
    pub canonical_name: String,
    pub scope_id: String,
    pub position: Position,
}

#[derive(Debug, Clone)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

#[derive(Default)]
struct NameCounters {
    scope_counters: HashMap<String, ScopeLocalCounters>, // Per-scope counters
    function_hashes: HashMap<String, usize>,             // Track collisions: hash -> counter
    class_counter: usize,
}

#[derive(Default)]
struct ScopeLocalCounters {
    variable_counter: usize,
    parameter_counter: usize,
}

impl Canonicalizer {
    pub fn new(scope_analyzer: ScopeAnalyzer) -> Self {
        Self {
            scope_analyzer,
            canonical_mappings: HashMap::new(),
            counters: NameCounters::default(),
        }
    }

    /// Hash the function's scope structure (parameters and variables)
    fn hash_function_scope_structure(&self, scope_id: &str) -> String {
        let mut hasher = DefaultHasher::new();

        // Get the scope for this function
        if let Some(scope) = self.scope_analyzer.get_scopes().get(scope_id) {
            // Sort variables by kind and position for stable ordering
            let mut vars = scope.variables.clone();
            vars.sort_by_key(|v| {
                (
                    match v.kind {
                        VariableKind::Parameter => 0,
                        VariableKind::Var => 1,
                        VariableKind::Let => 2,
                        VariableKind::Const => 3,
                        _ => 4,
                    },
                    v.declaration_line,
                    v.declaration_column,
                )
            });

            // Hash the structure: parameter count, then variable kinds
            let param_count = vars
                .iter()
                .filter(|v| matches!(v.kind, VariableKind::Parameter))
                .count();
            param_count.hash(&mut hasher);

            // Hash variable declaration pattern (just the kinds, not names)
            for var in &vars {
                match var.kind {
                    VariableKind::Parameter => "param".hash(&mut hasher),
                    VariableKind::Var => "var".hash(&mut hasher),
                    VariableKind::Let => "let".hash(&mut hasher),
                    VariableKind::Const => "const".hash(&mut hasher),
                    _ => {}
                }
            }

            // Also hash child scope count to capture nesting
            scope.children.len().hash(&mut hasher);
        }

        let hash = hasher.finish();
        format!("{:x}", hash % 0xFFFF)
    }

    pub fn canonicalize(&mut self, tree: &Tree, source: &str) -> Result<()> {
        let scopes = self.scope_analyzer.get_scopes().clone();

        self.canonicalize_scope("global", &scopes, tree, source)?;

        Ok(())
    }

    fn canonicalize_scope(
        &mut self,
        scope_id: &str,
        all_scopes: &HashMap<String, Scope>,
        _tree: &Tree,
        source: &str,
    ) -> Result<()> {
        let scope = all_scopes
            .get(scope_id)
            .ok_or_else(|| anyhow::anyhow!("Scope not found: {}", scope_id))?;

        let mut sorted_variables = scope.variables.clone();
        sorted_variables.sort_by_key(|v| (v.declaration_line, v.declaration_column));

        for variable in sorted_variables {
            let function_node = if matches!(variable.kind, VariableKind::FunctionDeclaration)
                && scope_id.starts_with("fn_")
            {
                // For now, let's use a simpler approach - hash based on the scope's variables
                // This gives us stability based on function structure
                None // We'll use a different approach
            } else {
                None
            };

            let canonical_name = self.generate_canonical_name(
                &variable.kind,
                scope_id,
                function_node,
                source,
                variable.declaration_byte,
            );

            let mapping = CanonicalMapping {
                original_name: variable.name.clone(),
                canonical_name: canonical_name.clone(),
                scope_id: scope_id.to_string(),
                position: Position {
                    line: variable.declaration_line,
                    column: variable.declaration_column,
                },
            };

            let key = format!("{}:{}", scope_id, variable.name);
            self.canonical_mappings.insert(key, mapping);
        }

        for child_scope_id in &scope.children {
            self.canonicalize_scope(child_scope_id, all_scopes, _tree, source)?;
        }

        Ok(())
    }

    fn generate_canonical_name(
        &mut self,
        kind: &VariableKind,
        scope_id: &str,
        _function_node: Option<Node>,
        _source: &str,
        declaration_byte: usize,
    ) -> String {
        match kind {
            VariableKind::FunctionDeclaration => {
                // For functions, we need to find their actual scope (not the current scope)
                // The function itself is declared in the parent scope, but has its own child scope
                let function_scope_id = self
                    .scope_analyzer
                    .get_scopes()
                    .values()
                    .find(|scope| {
                        scope.parent.as_deref() == Some(scope_id)
                            && matches!(scope.scope_type, crate::scope::ScopeType::Function)
                            && scope.start_byte <= declaration_byte
                            && declaration_byte < scope.end_byte
                    })
                    .map(|scope| scope.id.clone());

                if let Some(fn_scope_id) = function_scope_id {
                    let base_hash = self.hash_function_scope_structure(&fn_scope_id);

                    // Check for collisions and add counter if needed
                    let counter = self
                        .counters
                        .function_hashes
                        .entry(base_hash.clone())
                        .and_modify(|c| *c += 1)
                        .or_insert(1);

                    if *counter == 1 {
                        format!("fn_{}", base_hash)
                    } else {
                        format!("fn_{}_{}", base_hash, counter)
                    }
                } else {
                    // Fallback - use sequential numbering
                    self.counters
                        .function_hashes
                        .entry("fallback".to_string())
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    format!("fn_{}", self.counters.function_hashes["fallback"])
                }
            }
            VariableKind::Parameter => {
                // Use scope-local counter for parameters
                let scope_counters = self
                    .counters
                    .scope_counters
                    .entry(scope_id.to_string())
                    .or_default();

                scope_counters.parameter_counter += 1;
                format!("param_{}", scope_counters.parameter_counter)
            }
            VariableKind::Var | VariableKind::Let | VariableKind::Const => {
                // Use scope-local counter for variables
                let scope_counters = self
                    .counters
                    .scope_counters
                    .entry(scope_id.to_string())
                    .or_default();

                scope_counters.variable_counter += 1;
                format!("var_{}", scope_counters.variable_counter)
            }
            VariableKind::ClassDeclaration => {
                self.counters.class_counter += 1;
                format!("class_{}", self.counters.class_counter)
            }
        }
    }

    pub fn apply_canonicalization(&self, tree: &Tree, source: &str) -> Result<String> {
        // Build a complete resolution map first to avoid repeated lookups
        let mut resolution_cache: HashMap<(String, String), String> = HashMap::new();

        let identifiers = self.extract_all_identifiers(tree.root_node(), source);

        // Pre-compute all canonical names
        for identifier in &identifiers {
            let key = (identifier.scope_id.clone(), identifier.text.clone());
            if let std::collections::hash_map::Entry::Vacant(entry) = resolution_cache.entry(key) {
                if let Some(canonical) =
                    self.find_canonical_name(&identifier.text, &identifier.scope_id)
                {
                    entry.insert(canonical);
                }
            }
        }

        // Now apply replacements in a single pass
        let mut output = String::with_capacity(source.len());
        let mut last_end = 0;

        for identifier in identifiers {
            let start = identifier.node.start_byte();
            let end = identifier.node.end_byte();

            // Skip if this identifier starts before our last position
            if start < last_end {
                continue;
            }

            output.push_str(&source[last_end..start]);

            let key = (identifier.scope_id.clone(), identifier.text.clone());
            if let Some(canonical_name) = resolution_cache.get(&key) {
                output.push_str(canonical_name);
            } else {
                output.push_str(&source[start..end]);
            }

            last_end = end;
        }

        output.push_str(&source[last_end..]);

        Ok(output)
    }

    pub fn extract_all_identifiers<'a>(
        &self,
        node: Node<'a>,
        source: &str,
    ) -> Vec<IdentifierInfo<'a>> {
        let mut identifiers = Vec::new();
        let mut scope_stack = vec!["global".to_string()];
        self.collect_identifiers_with_scope(node, source, &mut scope_stack, &mut identifiers);
        identifiers.sort_by_key(|id| id.node.start_byte());
        identifiers
    }

    fn collect_identifiers_with_scope<'a>(
        &self,
        node: Node<'a>,
        source: &str,
        scope_stack: &mut Vec<String>,
        identifiers: &mut Vec<IdentifierInfo<'a>>,
    ) {
        let current_scope = scope_stack.last().unwrap().clone();
        let mut new_scope = None;
        let mut should_process_current = true;

        // Check if this node creates a new scope
        match node.kind() {
            "class_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    identifiers.push(IdentifierInfo {
                        node: name_node,
                        text: source[name_node.byte_range()].to_string(),
                        scope_id: current_scope.clone(),
                    });
                }
                new_scope = self
                    .scope_analyzer
                    .child_scope_for_node(&current_scope, node);
            }
            "function_declaration" | "function_expression" | "method_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = &source[name_node.byte_range()];
                    new_scope = self
                        .scope_analyzer
                        .child_scope_for_node(&current_scope, node);
                    // Add function name to parent scope
                    if node.kind() != "method_definition" {
                        identifiers.push(IdentifierInfo {
                            node: name_node,
                            text: name.to_string(),
                            scope_id: current_scope.clone(),
                        });
                    }
                } else {
                    new_scope = self
                        .scope_analyzer
                        .child_scope_for_node(&current_scope, node);
                }
            }
            "arrow_function" | "for_in_statement" | "for_of_statement" | "catch_clause" => {
                new_scope = self
                    .scope_analyzer
                    .child_scope_for_node(&current_scope, node);
                should_process_current = false; // Will process children with new scope
            }
            "block_statement" => {
                // Only create scope for block statements that aren't function bodies
                if let Some(parent) = node.parent() {
                    if !matches!(
                        parent.kind(),
                        "function_declaration" | "function_expression" | "arrow_function"
                    ) {
                        new_scope = self
                            .scope_analyzer
                            .child_scope_for_node(&current_scope, node);
                    }
                }
                should_process_current = false;
            }
            _ => {}
        }

        if let Some(ref new_scope_id) = new_scope {
            scope_stack.push(new_scope_id.clone());
        }

        // Process this node with the appropriate scope
        if should_process_current {
            let scope_for_node = if new_scope.is_some() {
                scope_stack.last().unwrap()
            } else {
                &current_scope
            };
            self.collect_identifiers(node, source, scope_for_node, identifiers);
        }

        // Process children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.collect_identifiers_with_scope(
                    cursor.node(),
                    source,
                    scope_stack,
                    identifiers,
                );
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // Pop scope if we created one
        if new_scope.is_some() {
            scope_stack.pop();
        }
    }

    fn collect_identifiers<'a>(
        &self,
        node: Node<'a>,
        source: &str,
        current_scope_id: &str,
        identifiers: &mut Vec<IdentifierInfo<'a>>,
    ) {
        match node.kind() {
            "identifier" => {
                let text = source[node.byte_range()].to_string();
                let is_ref = self.is_identifier_reference(node);
                let is_param = self.is_parameter_declaration(node);
                let is_var = self.is_variable_declaration(node);

                if is_ref || is_param || is_var {
                    // For declarations, use position to find the correct scope
                    let scope_id = if is_param || is_var {
                        self.scope_analyzer.innermost_scope_at(node.start_byte())
                    } else {
                        current_scope_id.to_string()
                    };

                    identifiers.push(IdentifierInfo {
                        node,
                        text: text.clone(),
                        scope_id,
                    });
                }
            }
            "shorthand_property_identifier_pattern" => {
                // Handle { prop } in destructuring
                let scope_id = self.scope_analyzer.innermost_scope_at(node.start_byte());
                identifiers.push(IdentifierInfo {
                    node,
                    text: source[node.byte_range()].to_string(),
                    scope_id,
                });
            }
            _ => {}
        }
    }

    fn is_identifier_reference(&self, node: Node) -> bool {
        if let Some(parent) = node.parent() {
            match parent.kind() {
                "member_expression" => {
                    // Check if this is the object part of a member expression
                    parent.child_by_field_name("object") == Some(node)
                }
                "property_identifier" => false,
                "function_declaration" | "function_expression" => {
                    // Skip if this is the name of a function
                    parent.child_by_field_name("name") != Some(node)
                }
                "class_declaration" => parent.child_by_field_name("name") != Some(node),
                "variable_declarator" => {
                    // Skip if this is the name of a variable declarator
                    parent.child_by_field_name("name") != Some(node)
                }
                "formal_parameters" => false, // Parameters are handled separately
                _ => true,
            }
        } else {
            true
        }
    }

    fn is_parameter_declaration(&self, node: Node) -> bool {
        if let Some(parent) = node.parent() {
            match parent.kind() {
                "formal_parameters" => true,
                "catch_clause" => parent.child_by_field_name("parameter") == Some(node),
                "arrow_function" => {
                    // Single parameter without parentheses
                    parent.child_by_field_name("parameter") == Some(node)
                }
                _ => false,
            }
        } else {
            false
        }
    }

    fn is_variable_declaration(&self, node: Node) -> bool {
        if let Some(parent) = node.parent() {
            match parent.kind() {
                "variable_declarator" => parent.child_by_field_name("name") == Some(node),
                "pair_pattern" => parent.child_by_field_name("value") == Some(node),
                "array_pattern" => true, // identifiers in array patterns are declarations
                "for_in_statement" | "for_of_statement" => {
                    // Check if this identifier is the loop variable
                    if let Some(left) = parent.child_by_field_name("left") {
                        left == node
                    } else {
                        false
                    }
                }
                "namespace_import" => {
                    // import * as name - the identifier is the third child
                    parent.child(2) == Some(node) && node.kind() == "identifier"
                }
                "import_specifier" => {
                    // import { a as b } - the alias is a declaration
                    parent.child_by_field_name("alias") == Some(node)
                }
                _ => false,
            }
        } else {
            false
        }
    }

    pub fn find_canonical_name(&self, original_name: &str, scope_id: &str) -> Option<String> {
        let mut current_scope_id = scope_id;

        loop {
            let key = format!("{}:{}", current_scope_id, original_name);
            if let Some(mapping) = self.canonical_mappings.get(&key) {
                return Some(mapping.canonical_name.clone());
            }

            if let Some(scope) = self.scope_analyzer.get_scopes().get(current_scope_id) {
                if let Some(parent) = &scope.parent {
                    current_scope_id = parent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        None
    }

    pub fn get_mappings(&self) -> &HashMap<String, CanonicalMapping> {
        &self.canonical_mappings
    }
}

#[derive(Debug)]
pub struct IdentifierInfo<'a> {
    pub node: Node<'a>,
    pub text: String,
    pub scope_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::JsParser;

    #[test]
    fn test_simple_canonicalization() {
        let source = "function a(b, c) { return b + c; }";

        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();

        let mut analyzer = ScopeAnalyzer::new();
        analyzer.analyze(tree.root_node(), source).unwrap();

        let mut canonicalizer = Canonicalizer::new(analyzer);
        canonicalizer.canonicalize(&tree, source).unwrap();

        let canonical_source = canonicalizer.apply_canonicalization(&tree, source).unwrap();
        assert!(canonical_source.starts_with("function fn_"));
        assert!(canonical_source.contains("(param_1, param_2)"));
        assert!(canonical_source.contains("return param_1 + param_2"));
    }
}
