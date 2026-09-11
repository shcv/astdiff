use crate::scope::{Scope, ScopeAnalyzer, VariableKind};
use anyhow::Result;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use tree_sitter::{Node, Tree};

pub struct Canonicalizer {
    pub scope_analyzer: ScopeAnalyzer,
    canonical_mappings: HashMap<String, HashMap<String, String>>,
    counters: NameCounters,
    used_names: HashSet<String>,
}

#[derive(Default)]
struct NameCounters {
    function_hashes: HashMap<String, usize>,
    class_counter: usize,
    variable_counter: usize,
    parameter_counter: usize,
}

impl Canonicalizer {
    pub fn new(scope_analyzer: ScopeAnalyzer) -> Self {
        Self {
            scope_analyzer,
            canonical_mappings: HashMap::new(),
            counters: NameCounters::default(),
            used_names: HashSet::new(),
        }
    }

    /// Hash the function's scope structure (parameters and variables)
    fn hash_function_scope_structure(scope: &Scope) -> String {
        let mut hasher = DefaultHasher::new();

        {
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
        self.canonical_mappings.clear();
        self.counters = NameCounters::default();
        self.used_names.clear();
        let mut nodes = vec![tree.root_node()];
        while let Some(node) = nodes.pop() {
            if matches!(
                node.kind(),
                "identifier"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            ) {
                self.used_names
                    .insert(source[node.byte_range()].to_string());
            }
            nodes.extend(node.children(&mut node.walk()));
        }
        let scopes = self.scope_analyzer.get_scopes().clone();
        self.canonicalize_scope("global", &scopes)?;

        Ok(())
    }

    fn canonicalize_scope(
        &mut self,
        scope_id: &str,
        all_scopes: &HashMap<String, Scope>,
    ) -> Result<()> {
        let scope = all_scopes
            .get(scope_id)
            .ok_or_else(|| anyhow::anyhow!("Scope not found: {}", scope_id))?;

        let mut sorted_variables = scope.variables.clone();
        sorted_variables.sort_by_key(|v| (v.declaration_line, v.declaration_column));

        for variable in sorted_variables {
            let canonical_name = loop {
                let name = self.generate_canonical_name(
                    &variable.kind,
                    scope_id,
                    variable.declaration_byte,
                )?;
                if self.used_names.insert(name.clone()) {
                    break name;
                }
            };

            self.canonical_mappings
                .entry(scope_id.to_owned())
                .or_default()
                .insert(variable.name, canonical_name);
        }

        for child_scope_id in &scope.children {
            self.canonicalize_scope(child_scope_id, all_scopes)?;
        }

        Ok(())
    }

    fn generate_canonical_name(
        &mut self,
        kind: &VariableKind,
        scope_id: &str,
        declaration_byte: usize,
    ) -> Result<String> {
        Ok(match kind {
            VariableKind::FunctionDeclaration => {
                // A declaration belongs to the parent scope; a named expression
                // binds its own name inside its function scope.
                let function_scope = self
                    .scope_analyzer
                    .get_scopes()
                    .values()
                    .filter(|scope| {
                        (scope.parent.as_deref() == Some(scope_id) || scope.id == scope_id)
                            && matches!(scope.scope_type, crate::scope::ScopeType::Function)
                            && scope.start_byte <= declaration_byte
                            && declaration_byte < scope.end_byte
                    })
                    .min_by_key(|scope| scope.end_byte - scope.start_byte)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "function binding at byte {declaration_byte} has no function scope"
                        )
                    })?;
                let hash = Self::hash_function_scope_structure(function_scope);
                let counter = self
                    .counters
                    .function_hashes
                    .entry(hash.clone())
                    .or_default();
                *counter += 1;
                if *counter == 1 {
                    format!("fn_{hash}")
                } else {
                    format!("fn_{hash}_{counter}")
                }
            }
            VariableKind::Parameter => {
                self.counters.parameter_counter += 1;
                format!("param_{}", self.counters.parameter_counter)
            }
            VariableKind::Var | VariableKind::Let | VariableKind::Const => {
                self.counters.variable_counter += 1;
                format!("var_{}", self.counters.variable_counter)
            }
            VariableKind::ClassDeclaration => {
                self.counters.class_counter += 1;
                format!("class_{}", self.counters.class_counter)
            }
        })
    }

    pub fn apply_canonicalization(&self, tree: &Tree, source: &str) -> Result<String> {
        self.apply_names(tree, source, &HashMap::new())
    }

    pub fn apply_names(
        &self,
        tree: &Tree,
        source: &str,
        names: &HashMap<String, String>,
    ) -> Result<String> {
        let mut output = String::with_capacity(source.len());
        let mut end = 0;
        for identifier in self
            .scope_analyzer
            .resolved_identifiers(tree.root_node(), source)
        {
            let start = identifier.node.start_byte();
            if start < end {
                anyhow::bail!("canonical identifier spans overlap");
            }
            output.push_str(&source[end..start]);
            if let Some(canonical) =
                self.find_canonical_name(&identifier.text, &identifier.scope_id)
            {
                let renamed = names
                    .get(canonical)
                    .map(String::as_str)
                    .unwrap_or(canonical);
                output.push_str(&identifier_replacement(
                    identifier.node,
                    &identifier.text,
                    renamed,
                ));
            } else {
                output.push_str(&identifier.text);
            }
            end = identifier.node.end_byte();
        }
        output.push_str(&source[end..]);
        Ok(output)
    }

    /// Identifier collection has already resolved the binding's owning scope.
    pub fn find_canonical_name(&self, original_name: &str, scope_id: &str) -> Option<&str> {
        self.canonical_mappings
            .get(scope_id)?
            .get(original_name)
            .map(String::as_str)
    }
}

pub(crate) fn identifier_replacement(node: Node<'_>, original: &str, renamed: &str) -> String {
    if original == renamed {
        return original.to_string();
    }
    if matches!(
        node.kind(),
        "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
    ) {
        return format!("{original}: {renamed}");
    }
    if let Some(parent) = node.parent() {
        if parent.child_by_field_name("alias").is_none() {
            match parent.kind() {
                "import_specifier" => return format!("{original} as {renamed}"),
                "export_specifier" => return format!("{renamed} as {original}"),
                _ => {}
            }
        }
    }
    renamed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::JsParser;

    fn canonical(source: &str) -> String {
        let tree = JsParser::new().unwrap().parse(source).unwrap();
        let mut scopes = ScopeAnalyzer::new();
        scopes.analyze(tree.root_node(), source).unwrap();
        let mut canonicalizer = Canonicalizer::new(scopes);
        canonicalizer.canonicalize(&tree, source).unwrap();
        canonicalizer.apply_canonicalization(&tree, source).unwrap()
    }

    #[test]
    fn named_expressions_rename_the_binding_and_recursive_reference_together() {
        let output = canonical("const holder = function named(x){return x ? named(x-1) : 0;};");
        let tree = JsParser::new().unwrap().parse(&output).unwrap();
        let mut pending = vec![tree.root_node()];
        let mut definition = None;
        let mut call = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "function_expression" {
                definition = Some(&output[node.child_by_field_name("name").unwrap().byte_range()]);
            }
            if node.kind() == "call_expression" {
                call = Some(&output[node.child_by_field_name("function").unwrap().byte_range()]);
            }
            pending.extend(node.children(&mut node.walk()));
        }
        assert_eq!(definition, call);
        assert!(definition.unwrap().starts_with("fn_"));
    }

    #[test]
    fn generated_names_do_not_capture_outer_bindings_or_unresolved_names() {
        let output = canonical("function f(x){return function g(y){return x+y+param_1;};}");
        assert!(
            output.contains("return param_2+param_3+param_1;"),
            "{output}"
        );
    }

    #[test]
    fn shorthand_and_import_export_keys_survive_renaming() {
        let output = canonical(
            "import {readFile} from 'fs'; const x=1; const o={x}; export {x}; readFile(x);",
        );
        assert!(output.contains("readFile as var_1"), "{output}");
        assert!(output.contains("{x: var_2}"), "{output}");
        assert!(output.contains("{var_2 as x}"), "{output}");
        assert!(output.contains("var_1(var_2)"), "{output}");
    }

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
