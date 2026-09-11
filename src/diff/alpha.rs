//! Compare syntax using resolved binding identities, never identifier spellings
//! alone. Syntax boundaries retain ASI-sensitive distinctions across line wraps.

use std::collections::HashMap;

use crate::scope::ScopeAnalyzer;
use tree_sitter::Node;

#[derive(Clone, Debug)]
enum Token {
    Open(&'static str),
    Close,
    Literal(&'static str, Box<str>),
    String(Box<str>),
    Binding {
        symbol: u32,
        local: bool,
        spelling: Box<str>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Normalized<'a> {
    Open(&'static str),
    Close,
    Literal(&'static str, &'a str),
    String(&'a str),
    Local(u32),
    External(u32),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Tokens {
    tokens: Vec<(Token, usize)>,
    lines: usize,
    pub symbol: Option<u32>,
}

pub(crate) struct Bindings {
    declarations: Vec<(usize, usize)>,
    by_span: HashMap<(usize, usize), u32>,
}

impl Bindings {
    pub fn new(root: Node<'_>, source: &str) -> anyhow::Result<Self> {
        let mut scopes = ScopeAnalyzer::new();
        scopes.analyze(root, source)?;
        let mut symbols = HashMap::new();
        let mut declarations = Vec::new();
        let mut by_span = HashMap::new();
        for identifier in scopes.resolved_identifiers(root, source) {
            let next = u32::try_from(declarations.len())?;
            let key = (identifier.scope_id, identifier.text);
            let symbol = *symbols.entry(key.clone()).or_insert_with(|| {
                declarations.push((
                    identifier.declaration_byte,
                    identifier.declaration_byte + key.1.len(),
                ));
                next
            });
            by_span.insert(
                (identifier.node.start_byte(), identifier.node.end_byte()),
                symbol,
            );
        }
        Ok(Self {
            declarations,
            by_span,
        })
    }

    pub fn tokenize(&self, node: Node<'_>, source: &str) -> Tokens {
        let mut output = Tokens {
            tokens: Vec::new(),
            lines: source[node.byte_range()].lines().count(),
            symbol: node.child_by_field_name("name").and_then(|name| {
                self.by_span
                    .get(&(name.start_byte(), name.end_byte()))
                    .copied()
            }),
        };
        if node.kind() == "variable_declarator" {
            if let Some(parent) = node.parent() {
                if let Some(keyword) = parent.child(0) {
                    output.tokens.push((
                        Token::Literal("declaration_kind", source[keyword.byte_range()].into()),
                        0,
                    ));
                }
            }
        }
        self.collect(node, node, source, &mut output);
        output
    }

    fn collect(&self, node: Node<'_>, root: Node<'_>, source: &str, output: &mut Tokens) {
        let kind = node.kind();
        if matches!(kind, "comment" | "hash_bang_line") {
            return;
        }
        let line = node.start_position().row - root.start_position().row;
        let text = &source[node.byte_range()];
        if kind == "string" {
            output.tokens.push((Token::String(text.into()), line));
            return;
        }
        if kind == "template_string" {
            output.tokens.push((Token::Open(kind), line));
            let mut start = node.start_byte() + 1;
            let mut chunk_line = line;
            for child in node.named_children(&mut node.walk()) {
                if child.kind() == "template_substitution" {
                    output.tokens.push((
                        Token::String(source[start..child.start_byte()].into()),
                        chunk_line,
                    ));
                    self.collect(child, root, source, output);
                    start = child.end_byte();
                    chunk_line = child.end_position().row - root.start_position().row;
                }
            }
            output.tokens.push((
                Token::String(source[start..node.end_byte() - 1].into()),
                chunk_line,
            ));
            output.tokens.push((
                Token::Close,
                node.end_position().row - root.start_position().row,
            ));
            return;
        }
        if let Some(&symbol) = self.by_span.get(&(node.start_byte(), node.end_byte())) {
            if matches!(
                kind,
                "identifier"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            ) {
                let (start, end) = self.declarations[symbol as usize];
                let local = start >= root.start_byte() && end <= root.end_byte();
                // A shorthand token carries both a binding and an external key.
                if kind.starts_with("shorthand_property_") || is_unaliased_name(node) {
                    output
                        .tokens
                        .push((Token::Literal("external_key", text.into()), line));
                }
                output.tokens.push((
                    Token::Binding {
                        symbol,
                        local,
                        spelling: text.into(),
                    },
                    line,
                ));
                return;
            }
        }
        if node.child_count() == 0 {
            output
                .tokens
                .push((Token::Literal(kind, text.into()), line));
            return;
        }
        output.tokens.push((Token::Open(kind), line));
        for child in node.children(&mut node.walk()) {
            self.collect(child, root, source, output);
        }
        output.tokens.push((
            Token::Close,
            node.end_position().row - root.start_position().row,
        ));
    }
}

fn is_unaliased_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "import_specifier" | "export_specifier")
            && parent.child_by_field_name("alias").is_none()
    })
}

pub(crate) struct NormalizedTokens<'a> {
    tokens: Vec<Normalized<'a>>,
    source: &'a Tokens,
}

impl Tokens {
    /// `external` contains only resolved declaration pairs accepted by matching.
    pub fn normalize(&self, external: &HashMap<u32, u32>) -> NormalizedTokens<'_> {
        let mut locals = HashMap::new();
        let mut tokens = Vec::with_capacity(self.tokens.len());
        for (token, _) in &self.tokens {
            let normalized = match token {
                Token::Open(kind) => Normalized::Open(kind),
                Token::Close => Normalized::Close,
                Token::Literal(kind, text) => Normalized::Literal(kind, text),
                Token::String(text) => Normalized::String(text),
                Token::Binding {
                    symbol,
                    local: true,
                    ..
                } => {
                    let next = locals.len() as u32;
                    Normalized::Local(*locals.entry(*symbol).or_insert(next))
                }
                Token::Binding {
                    symbol, spelling, ..
                } => match external.get(symbol) {
                    Some(common) => Normalized::External(*common),
                    None => Normalized::Literal("identifier", spelling),
                },
            };
            tokens.push(normalized);
        }
        NormalizedTokens {
            tokens,
            source: self,
        }
    }
}

impl NormalizedTokens<'_> {
    pub fn equal(&self, other: &Self) -> bool {
        self.tokens == other.tokens
    }

    pub fn equal_ignoring_strings(&self, other: &Self) -> bool {
        self.tokens.len() == other.tokens.len()
            && self.tokens.iter().zip(&other.tokens).all(|(left, right)| {
                matches!(
                    (left, right),
                    (Normalized::String(_), Normalized::String(_))
                ) || left == right
            })
    }

    pub fn lines(&self) -> Vec<String> {
        use std::fmt::Write;
        let mut lines = vec![String::new(); self.source.lines];
        for (normalized, (_, line)) in self.tokens.iter().zip(&self.source.tokens) {
            if let Normalized::String(text) = normalized {
                for (offset, part) in text.split('\n').enumerate() {
                    if let Some(line) = lines.get_mut(*line + offset) {
                        write!(line, "{:?} ", Normalized::String(part))
                            .expect("writing to String cannot fail");
                    }
                }
            } else if let Some(line) = lines.get_mut(*line) {
                write!(line, "{normalized:?} ").expect("writing to String cannot fail");
            }
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::JsParser;

    fn tokens(source: &str) -> Tokens {
        let tree = JsParser::new().unwrap().parse(source).unwrap();
        Bindings::new(tree.root_node(), source)
            .unwrap()
            .tokenize(tree.root_node(), source)
    }

    #[test]
    fn scoped_renames_ignore_spelling_reuse_and_line_wrapping() {
        let left = tokens("function f(x){return function g(y){return y;};}");
        let right = tokens("function a(b){\nreturn function c(b){return b;};\n}");
        assert!(left
            .normalize(&HashMap::new())
            .equal(&right.normalize(&HashMap::new())));
    }

    #[test]
    fn changed_globals_properties_imports_and_binding_targets_are_distinct() {
        for (left, right) in [
            (
                "function f(x){return fetch(x);}",
                "function f(x){return erase(x);}",
            ),
            ("function f(x,y){return x;}", "function f(x,y){return y;}"),
            (
                "function f(x){return x.push(1);}",
                "function f(x){return x.shift(1);}",
            ),
            (
                "import {readFile as f} from 'fs';",
                "import {writeFile as f} from 'fs';",
            ),
            ("const x=1; const o={x};", "const y=1; const o={y};"),
            ("function f(){return\nx;}", "function f(){return x;}"),
        ] {
            assert!(
                !tokens(left)
                    .normalize(&HashMap::new())
                    .equal(&tokens(right).normalize(&HashMap::new())),
                "{left} versus {right}"
            );
        }
    }

    #[test]
    fn literal_changes_are_distinct_and_string_only() {
        for (left, right) in [
            (
                "function f(){return 'a  b';}",
                "function f(){return 'a b';}",
            ),
            (
                "function f(x){return `got ${x} done`;}",
                "function g(y){return `${y}`;}",
            ),
            (
                "function f(){return '';}",
                "function f(){return 'new\\nvalue';}",
            ),
        ] {
            let left = tokens(left);
            let right = tokens(right);
            let left = left.normalize(&HashMap::new());
            let right = right.normalize(&HashMap::new());
            assert!(!left.equal(&right));
            assert!(left.equal_ignoring_strings(&right));
        }
    }
}
