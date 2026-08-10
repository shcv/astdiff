use anyhow::Result;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Debug, Clone)]
pub struct Scope {
    pub id: String,
    pub scope_type: ScopeType,
    pub parent: Option<String>,
    pub children: Vec<String>,
    pub variables: Vec<Variable>,
    pub depth: usize,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScopeType {
    Global,
    Function,
    Block,
    Class,
    Module,
}

#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub kind: VariableKind,
    pub declaration_line: usize,
    pub declaration_column: usize,
    pub declaration_byte: usize,
    pub is_hoisted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VariableKind {
    FunctionDeclaration,
    ClassDeclaration,
    Var,
    Let,
    Const,
    Parameter,
}

pub struct ScopeAnalyzer {
    scopes: HashMap<String, Scope>,
    current_scope_id: String,
    scope_counter: usize,
}

impl Default for ScopeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ScopeAnalyzer {
    pub fn new() -> Self {
        let mut scopes = HashMap::new();
        let global_scope = Scope {
            id: "global".to_string(),
            scope_type: ScopeType::Global,
            parent: None,
            children: Vec::new(),
            variables: Vec::new(),
            depth: 0,
            start_byte: 0,
            end_byte: usize::MAX,
        };
        scopes.insert("global".to_string(), global_scope);

        Self {
            scopes,
            current_scope_id: "global".to_string(),
            scope_counter: 0,
        }
    }

    pub fn analyze(&mut self, root: Node, source: &str) -> Result<()> {
        if let Some(global) = self.scopes.get_mut("global") {
            global.start_byte = root.start_byte();
            global.end_byte = root.end_byte();
        }
        self.visit_node(root, source)?;
        Ok(())
    }

    fn visit_node(&mut self, node: Node, source: &str) -> Result<()> {
        let mut scope_changed = false;
        let original_scope = self.current_scope_id.clone();

        match node.kind() {
            "variable_declaration" | "lexical_declaration" => {
                self.handle_variable_declaration(node, source)?;
            }
            "function_declaration" => {
                self.handle_function_declaration(node, source)?;
                scope_changed = true;
            }
            "function_expression" => {
                self.handle_function_expression(node, source)?;
                scope_changed = true;
            }
            "method_definition" => {
                self.handle_method_definition(node, source)?;
                scope_changed = true;
            }
            "arrow_function" => {
                self.handle_arrow_function(node, source)?;
                scope_changed = true;
            }
            "class_declaration" => {
                self.handle_class_declaration(node, source)?;
                scope_changed = true;
            }
            "block_statement" => {
                if self.should_create_block_scope(&node) {
                    let block_scope_id = self.create_scope(ScopeType::Block, node);
                    self.current_scope_id = block_scope_id;
                    scope_changed = true;
                }
            }
            "for_in_statement" => {
                self.handle_for_in_statement(node, source)?;
                scope_changed = true;
            }
            "for_of_statement" => {
                self.handle_for_of_statement(node, source)?;
                scope_changed = true;
            }
            "catch_clause" => {
                self.handle_catch_clause(node, source)?;
                scope_changed = true;
            }
            "import_statement" => {
                self.handle_import_statement(node, source)?;
            }
            _ => {}
        }

        // Visit children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.visit_node(cursor.node(), source)?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // Restore scope if we changed it
        if scope_changed {
            self.current_scope_id = original_scope;
        }

        Ok(())
    }

    fn handle_function_declaration(&mut self, node: Node, source: &str) -> Result<()> {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = &source[name_node.byte_range()];
            self.add_variable_to_current_scope(
                name.to_string(),
                VariableKind::FunctionDeclaration,
                name_node.start_position(),
                name_node.start_byte(),
                true, // functions are hoisted
            );
        }

        let function_scope_id = self.create_scope(ScopeType::Function, node);
        self.current_scope_id = function_scope_id;

        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_parameters(params, source)?;
        }

        Ok(())
    }

    fn handle_function_expression(&mut self, node: Node, source: &str) -> Result<()> {
        let function_scope_id = self.create_scope(ScopeType::Function, node);
        self.current_scope_id = function_scope_id;

        if let Some(name_node) = node.child_by_field_name("name") {
            let name = &source[name_node.byte_range()];
            self.add_variable_to_current_scope(
                name.to_string(),
                VariableKind::FunctionDeclaration,
                name_node.start_position(),
                name_node.start_byte(),
                false,
            );
        }

        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_parameters(params, source)?;
        }

        Ok(())
    }

    fn handle_arrow_function(&mut self, node: Node, source: &str) -> Result<()> {
        let function_scope_id = self.create_scope(ScopeType::Function, node);
        self.current_scope_id = function_scope_id;

        // Arrow functions can have parameters in two forms:
        // 1. With parentheses: (param) => expr
        // 2. Without parentheses: param => expr
        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_parameters(params, source)?;
        } else if let Some(param) = node.child_by_field_name("parameter") {
            // Single parameter without parentheses
            if param.kind() == "identifier" {
                let param_name = &source[param.byte_range()];
                self.add_variable_to_current_scope(
                    param_name.to_string(),
                    VariableKind::Parameter,
                    param.start_position(),
                    param.start_byte(),
                    false,
                );
            }
        }

        Ok(())
    }

    fn handle_method_definition(&mut self, node: Node, source: &str) -> Result<()> {
        let function_scope_id = self.create_scope(ScopeType::Function, node);
        self.current_scope_id = function_scope_id;

        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_parameters(params, source)?;
        }

        Ok(())
    }

    fn handle_parameters(&mut self, params_node: Node, source: &str) -> Result<()> {
        let mut cursor = params_node.walk();
        if cursor.goto_first_child() {
            loop {
                let node = cursor.node();
                match node.kind() {
                    "identifier" => {
                        let param_name = &source[node.byte_range()];
                        self.add_variable_to_current_scope(
                            param_name.to_string(),
                            VariableKind::Parameter,
                            node.start_position(),
                            node.start_byte(),
                            false,
                        );
                    }
                    "object_pattern" | "array_pattern" | "assignment_pattern" => {
                        // Handle destructuring in parameters
                        self.handle_pattern(node, source, VariableKind::Parameter)?;
                    }
                    _ => {}
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        Ok(())
    }

    fn handle_pattern(
        &mut self,
        pattern_node: Node,
        source: &str,
        kind: VariableKind,
    ) -> Result<()> {
        match pattern_node.kind() {
            "object_pattern" => {
                self.handle_object_pattern(pattern_node, source, kind)?;
            }
            "array_pattern" => {
                self.handle_array_pattern(pattern_node, source, kind)?;
            }
            "assignment_pattern" => {
                if let Some(left) = pattern_node.child_by_field_name("left") {
                    self.handle_pattern(left, source, kind)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_object_pattern(
        &mut self,
        node: Node,
        source: &str,
        kind: VariableKind,
    ) -> Result<()> {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                match child.kind() {
                    "pair_pattern" => {
                        if let Some(value) = child.child_by_field_name("value") {
                            match value.kind() {
                                "identifier" => {
                                    let name = &source[value.byte_range()];
                                    self.add_variable_to_current_scope(
                                        name.to_string(),
                                        kind.clone(),
                                        value.start_position(),
                                        value.start_byte(),
                                        false,
                                    );
                                }
                                "object_pattern" | "array_pattern" | "assignment_pattern" => {
                                    self.handle_pattern(value, source, kind.clone())?;
                                }
                                _ => {}
                            }
                        }
                    }
                    "shorthand_property_identifier_pattern" => {
                        let name = &source[child.byte_range()];
                        self.add_variable_to_current_scope(
                            name.to_string(),
                            kind.clone(),
                            child.start_position(),
                            child.start_byte(),
                            false,
                        );
                    }
                    _ => {}
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        Ok(())
    }

    fn handle_array_pattern(&mut self, node: Node, source: &str, kind: VariableKind) -> Result<()> {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                match child.kind() {
                    "identifier" => {
                        let name = &source[child.byte_range()];
                        self.add_variable_to_current_scope(
                            name.to_string(),
                            kind.clone(),
                            child.start_position(),
                            child.start_byte(),
                            false,
                        );
                    }
                    "object_pattern" | "array_pattern" | "assignment_pattern" => {
                        self.handle_pattern(child, source, kind.clone())?;
                    }
                    _ => {}
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        Ok(())
    }

    fn handle_variable_declaration(&mut self, node: Node, source: &str) -> Result<()> {
        let kind = match node.kind() {
            "variable_declaration" => VariableKind::Var,
            "lexical_declaration" => {
                // Check first token to determine let vs const
                if let Some(first_child) = node.child(0) {
                    if &source[first_child.byte_range()] == "const" {
                        VariableKind::Const
                    } else {
                        VariableKind::Let
                    }
                } else {
                    VariableKind::Let
                }
            }
            _ => return Ok(()),
        };

        // Find all variable declarators
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if cursor.node().kind() == "variable_declarator" {
                    if let Some(name_node) = cursor.node().child_by_field_name("name") {
                        match name_node.kind() {
                            "identifier" => {
                                let name = &source[name_node.byte_range()];
                                self.add_variable_to_current_scope(
                                    name.to_string(),
                                    kind.clone(),
                                    name_node.start_position(),
                                    name_node.start_byte(),
                                    matches!(kind, VariableKind::Var),
                                );
                            }
                            "object_pattern" | "array_pattern" => {
                                self.handle_pattern(name_node, source, kind.clone())?;
                            }
                            _ => {}
                        }
                    }
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        Ok(())
    }

    fn handle_class_declaration(&mut self, node: Node, source: &str) -> Result<()> {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = &source[name_node.byte_range()];
            self.add_variable_to_current_scope(
                name.to_string(),
                VariableKind::ClassDeclaration,
                name_node.start_position(),
                name_node.start_byte(),
                false,
            );
        }

        let class_scope_id = self.create_scope(ScopeType::Class, node);
        self.current_scope_id = class_scope_id;

        Ok(())
    }

    fn handle_for_in_statement(&mut self, node: Node, source: &str) -> Result<()> {
        let loop_scope_id = self.create_scope(ScopeType::Block, node);
        self.current_scope_id = loop_scope_id;

        // Handle the loop variable
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                let var_name = &source[left.byte_range()];
                self.add_variable_to_current_scope(
                    var_name.to_string(),
                    VariableKind::Var,
                    left.start_position(),
                    left.start_byte(),
                    false,
                );
            } else if let Some(declarator) = left.child(1) {
                if declarator.kind() == "variable_declarator" {
                    if let Some(name_node) = declarator.child_by_field_name("name") {
                        match name_node.kind() {
                            "identifier" => {
                                let name = &source[name_node.byte_range()];
                                let kind = if left.kind() == "lexical_declaration" {
                                    if let Some(first) = left.child(0) {
                                        if &source[first.byte_range()] == "const" {
                                            VariableKind::Const
                                        } else {
                                            VariableKind::Let
                                        }
                                    } else {
                                        VariableKind::Let
                                    }
                                } else {
                                    VariableKind::Var
                                };
                                self.add_variable_to_current_scope(
                                    name.to_string(),
                                    kind,
                                    name_node.start_position(),
                                    name_node.start_byte(),
                                    false,
                                );
                            }
                            "object_pattern" | "array_pattern" => {
                                let kind = if left.kind() == "lexical_declaration" {
                                    VariableKind::Let
                                } else {
                                    VariableKind::Var
                                };
                                self.handle_pattern(name_node, source, kind)?;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_for_of_statement(&mut self, node: Node, source: &str) -> Result<()> {
        // Same logic as for-in
        self.handle_for_in_statement(node, source)
    }

    fn handle_catch_clause(&mut self, node: Node, source: &str) -> Result<()> {
        let catch_scope_id = self.create_scope(ScopeType::Block, node);
        self.current_scope_id = catch_scope_id;

        if let Some(param) = node.child_by_field_name("parameter") {
            if param.kind() == "identifier" {
                let param_name = &source[param.byte_range()];
                self.add_variable_to_current_scope(
                    param_name.to_string(),
                    VariableKind::Parameter,
                    param.start_position(),
                    param.start_byte(),
                    false,
                );
            }
        }

        Ok(())
    }

    fn handle_import_statement(&mut self, node: Node, source: &str) -> Result<()> {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "import_clause" {
                    // Handle various import forms
                    let mut clause_cursor = child.walk();
                    if clause_cursor.goto_first_child() {
                        loop {
                            let import_child = clause_cursor.node();
                            match import_child.kind() {
                                "identifier" => {
                                    // default import
                                    let import_name = &source[import_child.byte_range()];
                                    self.add_variable_to_current_scope(
                                        import_name.to_string(),
                                        VariableKind::Const,
                                        import_child.start_position(),
                                        import_child.start_byte(),
                                        false,
                                    );
                                }
                                "namespace_import" => {
                                    // import * as name
                                    // The identifier is the third child (after * and as)
                                    if let Some(identifier) = import_child.child(2) {
                                        if identifier.kind() == "identifier" {
                                            let import_name = &source[identifier.byte_range()];
                                            self.add_variable_to_current_scope(
                                                import_name.to_string(),
                                                VariableKind::Const,
                                                identifier.start_position(),
                                                identifier.start_byte(),
                                                false,
                                            );
                                        }
                                    }
                                }
                                "named_imports" => {
                                    // import { a, b as c }
                                    for j in 0..import_child.child_count() {
                                        if let Some(import_spec) = import_child.child(j) {
                                            if import_spec.kind() == "import_specifier" {
                                                let name = if let Some(alias) =
                                                    import_spec.child_by_field_name("alias")
                                                {
                                                    &source[alias.byte_range()]
                                                } else if let Some(name) =
                                                    import_spec.child_by_field_name("name")
                                                {
                                                    &source[name.byte_range()]
                                                } else {
                                                    continue;
                                                };
                                                self.add_variable_to_current_scope(
                                                    name.to_string(),
                                                    VariableKind::Const,
                                                    import_spec.start_position(),
                                                    import_spec.start_byte(),
                                                    false,
                                                );
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                            if !clause_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        Ok(())
    }

    fn should_create_block_scope(&self, node: &Node) -> bool {
        if let Some(parent) = node.parent() {
            !matches!(
                parent.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
            )
        } else {
            false
        }
    }

    fn create_scope(&mut self, scope_type: ScopeType, node: Node) -> String {
        self.scope_counter += 1;
        let scope_id = format!("scope_{}", self.scope_counter);

        let current_scope = self.scopes.get(&self.current_scope_id).unwrap();
        let depth = current_scope.depth + 1;

        let new_scope = Scope {
            id: scope_id.clone(),
            scope_type,
            parent: Some(self.current_scope_id.clone()),
            children: Vec::new(),
            variables: Vec::new(),
            depth,
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        };

        self.scopes.insert(scope_id.clone(), new_scope);

        // Add to parent's children
        if let Some(parent_scope) = self.scopes.get_mut(&self.current_scope_id) {
            parent_scope.children.push(scope_id.clone());
        }

        scope_id
    }

    fn add_variable_to_current_scope(
        &mut self,
        name: String,
        kind: VariableKind,
        position: tree_sitter::Point,
        declaration_byte: usize,
        is_hoisted: bool,
    ) {
        // Add variable to current scope
        let target_scope_id = if matches!(kind, VariableKind::Var) {
            self.nearest_function_or_global_scope()
        } else {
            self.current_scope_id.clone()
        };

        if let Some(scope) = self.scopes.get_mut(&target_scope_id) {
            scope.variables.push(Variable {
                name,
                kind,
                declaration_line: position.row,
                declaration_column: position.column,
                declaration_byte,
                is_hoisted,
            });
        }
    }

    fn nearest_function_or_global_scope(&self) -> String {
        let mut scope_id = self.current_scope_id.as_str();
        loop {
            let Some(scope) = self.scopes.get(scope_id) else {
                return "global".to_string();
            };
            if matches!(scope.scope_type, ScopeType::Function | ScopeType::Global) {
                return scope.id.clone();
            }
            let Some(parent) = scope.parent.as_deref() else {
                return "global".to_string();
            };
            scope_id = parent;
        }
    }

    pub fn innermost_scope_at(&self, byte: usize) -> String {
        self.scopes
            .values()
            .filter(|scope| scope.start_byte <= byte && byte < scope.end_byte)
            .max_by_key(|scope| scope.depth)
            .map(|scope| scope.id.clone())
            .unwrap_or_else(|| "global".to_string())
    }

    pub fn child_scope_for_node(&self, parent_scope_id: &str, node: Node) -> Option<String> {
        self.scopes
            .values()
            .find(|scope| {
                scope.parent.as_deref() == Some(parent_scope_id)
                    && scope.start_byte == node.start_byte()
                    && scope.end_byte == node.end_byte()
            })
            .map(|scope| scope.id.clone())
    }

    pub fn get_scopes(&self) -> &HashMap<String, Scope> {
        &self.scopes
    }

    pub fn find_variable(&self, name: &str, from_scope_id: &str) -> Option<(String, &Variable)> {
        let mut current_scope_id = from_scope_id;

        while let Some(scope) = self.scopes.get(current_scope_id) {
            if let Some(var) = scope.variables.iter().find(|v| v.name == name) {
                return Some((current_scope_id.to_string(), var));
            }

            if let Some(parent) = &scope.parent {
                current_scope_id = parent;
            } else {
                break;
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::JsParser;

    #[test]
    fn test_simple_scope() {
        let source = "function add(a, b) { return a + b; }";

        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();

        let mut analyzer = ScopeAnalyzer::new();
        analyzer.analyze(tree.root_node(), source).unwrap();

        let scopes = analyzer.get_scopes();
        assert!(scopes.contains_key("global"));
        let fn_scope = scopes
            .values()
            .find(|scope| matches!(scope.scope_type, ScopeType::Function))
            .expect("function scope");
        assert_eq!(fn_scope.variables.len(), 2);
        assert_eq!(fn_scope.variables[0].name, "a");
        assert_eq!(fn_scope.variables[1].name, "b");
    }

    #[test]
    fn duplicate_function_names_have_distinct_scopes() {
        let source = "function a(x) { function a(y) { return y; } return a(x); }";
        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();
        let mut analyzer = ScopeAnalyzer::new();
        analyzer.analyze(tree.root_node(), source).unwrap();

        let function_scopes: Vec<_> = analyzer
            .get_scopes()
            .values()
            .filter(|scope| matches!(scope.scope_type, ScopeType::Function))
            .collect();
        assert_eq!(function_scopes.len(), 2);
        assert_ne!(function_scopes[0].id, function_scopes[1].id);
    }

    #[test]
    fn test_import_scope() {
        let source = r#"import * as WbB from "path";"#;

        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();

        let mut analyzer = ScopeAnalyzer::new();
        analyzer.analyze(tree.root_node(), source).unwrap();

        let scopes = analyzer.get_scopes();
        let global_scope = &scopes["global"];

        println!("Global scope variables: {:?}", global_scope.variables);
        assert!(global_scope.variables.iter().any(|v| v.name == "WbB"));
    }
}
