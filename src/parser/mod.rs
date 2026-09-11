use anyhow::Result;
use tree_sitter::{Node, Parser};

pub struct JsParser {
    parser: Parser,
}

impl JsParser {
    pub fn new() -> Result<Self> {
        let language = tree_sitter_javascript::language();
        let mut parser = Parser::new();
        parser.set_language(language)?;

        Ok(Self { parser })
    }

    pub fn parse(&mut self, source: &str) -> Result<tree_sitter::Tree> {
        let tree = self
            .parser
            .parse(source, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse JavaScript"))?;
        if tree.root_node().has_error() {
            let point = first_error_position(tree.root_node())
                .unwrap_or_else(|| tree.root_node().start_position());
            anyhow::bail!(
                "JavaScript contains a syntax error near line {}, column {}",
                point.row + 1,
                point.column + 1
            );
        }
        Ok(tree)
    }
}

fn first_error_position(node: Node) -> Option<tree_sitter::Point> {
    if node.is_error() || node.is_missing() {
        return Some(node.start_position());
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if let Some(point) = first_error_position(cursor.node()) {
                return Some(point);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_function() {
        let mut parser = JsParser::new().unwrap();
        let source = "function hello(name) { return name; }";
        let tree = parser.parse(source).unwrap();
        assert_eq!(tree.root_node().kind(), "program");
    }

    #[test]
    fn rejects_syntax_errors() {
        let mut parser = JsParser::new().unwrap();
        let error = parser.parse("function broken( {").unwrap_err();
        assert!(error.to_string().contains("syntax error"));
    }
}
