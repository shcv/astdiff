use tree_sitter::{Node, Tree};

pub struct PrettyPrinter {
    indent_size: usize,
}

impl Default for PrettyPrinter {
    fn default() -> Self {
        Self::new()
    }
}

impl PrettyPrinter {
    pub fn new() -> Self {
        Self { indent_size: 2 }
    }

    pub fn format(&self, tree: &Tree, source: &str) -> String {
        let mut output = String::new();
        self.format_node(tree.root_node(), source, 0, &mut output);
        output
    }

    fn format_node(&self, node: Node, source: &str, depth: usize, output: &mut String) {
        match node.kind() {
            "program" => {
                // Root node - format children
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.format_node(child, source, depth, output);
                        if i < node.child_count() - 1 {
                            output.push('\n');
                        }
                    }
                }
            }
            "function_declaration" => {
                self.add_indent(output, depth);
                output.push_str("function ");

                if let Some(name) = node.child_by_field_name("name") {
                    output.push_str(&source[name.byte_range()]);
                }

                if let Some(params) = node.child_by_field_name("parameters") {
                    self.format_node(params, source, depth, output);
                }

                output.push(' ');

                if let Some(body) = node.child_by_field_name("body") {
                    self.format_node(body, source, depth, output);
                }
            }
            "formal_parameters" => {
                output.push('(');
                let mut first_param = true;
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "identifier" {
                            if !first_param {
                                output.push_str(", ");
                            }
                            output.push_str(&source[child.byte_range()]);
                            first_param = false;
                        }
                    }
                }
                output.push(')');
            }
            "statement_block" => {
                output.push_str("{\n");
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "{" && child.kind() != "}" {
                            self.format_node(child, source, depth + 1, output);
                            output.push('\n');
                        }
                    }
                }
                self.add_indent(output, depth);
                output.push('}');
            }
            "variable_declaration" => {
                self.add_indent(output, depth);

                // Get declaration type (var, let, const)
                if let Some(first_child) = node.child(0) {
                    output.push_str(first_child.kind());
                    output.push(' ');
                }

                // Format declarators
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "variable_declarator" {
                            self.format_node(child, source, depth, output);
                            if i < node.child_count() - 1
                                && node.child(i + 1).map(|n| n.kind())
                                    == Some("variable_declarator")
                            {
                                output.push_str(", ");
                            }
                        }
                    }
                }
                output.push(';');
            }
            "variable_declarator" => {
                if let Some(name) = node.child_by_field_name("name") {
                    output.push_str(&source[name.byte_range()]);
                }
                if let Some(value) = node.child_by_field_name("value") {
                    output.push_str(" = ");
                    self.format_node(value, source, depth, output);
                }
            }
            "return_statement" => {
                self.add_indent(output, depth);
                output.push_str("return");
                if node.child_count() > 1 {
                    output.push(' ');
                    for i in 1..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() != ";" {
                                self.format_node(child, source, depth, output);
                            }
                        }
                    }
                }
                output.push(';');
            }
            "binary_expression" => {
                if let Some(left) = node.child_by_field_name("left") {
                    self.format_node(left, source, depth, output);
                }
                if let Some(op) = node.child_by_field_name("operator") {
                    output.push(' ');
                    output.push_str(&source[op.byte_range()]);
                    output.push(' ');
                }
                if let Some(right) = node.child_by_field_name("right") {
                    self.format_node(right, source, depth, output);
                }
            }
            "identifier" | "number" => {
                output.push_str(&source[node.byte_range()]);
            }
            _ => {
                // For other nodes, just output their text
                output.push_str(&source[node.byte_range()]);
            }
        }
    }

    fn add_indent(&self, output: &mut String, depth: usize) {
        for _ in 0..(depth * self.indent_size) {
            output.push(' ');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::JsParser;

    #[test]
    fn test_pretty_print() {
        let source = "function add(a,b){var result=a+b;return result;}";

        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();

        let printer = PrettyPrinter::new();
        let formatted = printer.format(&tree, source);

        assert!(formatted.contains("function add(a, b) {"));
        assert!(formatted.contains("  var result = a + b;"));
        assert!(formatted.contains("  return result;"));
        assert!(formatted.contains("}"));
    }
}
