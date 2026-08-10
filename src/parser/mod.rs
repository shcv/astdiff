use anyhow::Result;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor};

pub struct JsParser {
    parser: Parser,
    language: Language,
}

impl JsParser {
    pub fn new() -> Result<Self> {
        let language = tree_sitter_javascript::language();
        let mut parser = Parser::new();
        parser.set_language(language)?;

        Ok(Self { parser, language })
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

    pub(crate) fn parse_tolerant(&mut self, source: &str) -> Option<tree_sitter::Tree> {
        self.parser.parse(source, None)
    }

    pub fn get_language(&self) -> Language {
        self.language
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

pub struct IdentifierExtractor {
    query: Query,
}

impl IdentifierExtractor {
    pub fn new(language: Language) -> Result<Self> {
        let query_source = r#"
        ; Function declarations and expressions
        (function_declaration name: (identifier) @function-name)
        (function_expression name: (identifier) @function-name)
        (arrow_function) @arrow-function
        
        ; Variable declarations
        (variable_declarator name: (identifier) @variable-name)
        (formal_parameters (identifier) @parameter-name)
        
        ; All identifier references
        (identifier) @identifier
        
        ; Class declarations
        (class_declaration name: (identifier) @class-name)
        "#;

        let query = Query::new(language, query_source)?;
        Ok(Self { query })
    }

    pub fn extract_identifiers<'a>(
        &self,
        root_node: Node<'a>,
        source: &'a str,
    ) -> Vec<IdentifierMatch<'a>> {
        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&self.query, root_node, source.as_bytes());

        let mut results = Vec::new();
        for match_ in matches {
            for capture in match_.captures {
                let node = capture.node;
                let text = &source[node.byte_range()];
                let capture_name = self.query.capture_names()[capture.index as usize].as_str();

                results.push(IdentifierMatch {
                    node,
                    text,
                    capture_type: capture_name.to_string(),
                    start_position: node.start_position(),
                    end_position: node.end_position(),
                });
            }
        }

        results
    }
}

#[derive(Debug, Clone)]
pub struct IdentifierMatch<'a> {
    pub node: Node<'a>,
    pub text: &'a str,
    pub capture_type: String,
    pub start_position: tree_sitter::Point,
    pub end_position: tree_sitter::Point,
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
    fn test_extract_identifiers() {
        let mut parser = JsParser::new().unwrap();
        let source = "function add(a, b) { return a + b; }";
        let tree = parser.parse(source).unwrap();

        let extractor = IdentifierExtractor::new(parser.get_language()).unwrap();
        let identifiers = extractor.extract_identifiers(tree.root_node(), source);

        assert!(identifiers
            .iter()
            .any(|id| id.text == "add" && id.capture_type == "function-name"));
        assert!(identifiers
            .iter()
            .any(|id| id.text == "a" && id.capture_type == "parameter-name"));
        assert!(identifiers
            .iter()
            .any(|id| id.text == "b" && id.capture_type == "parameter-name"));
    }

    #[test]
    fn rejects_syntax_errors() {
        let mut parser = JsParser::new().unwrap();
        let error = parser.parse("function broken( {").unwrap_err();
        assert!(error.to_string().contains("syntax error"));
    }
}
