//! Deterministic reconstruction of a target JavaScript artifact.
//!
//! Rendering is deliberately a separate output step.  The source artifact and
//! its analysis remain immutable; this module applies only approved semantic
//! names to lexical symbol occurrences and optionally reflows the resulting
//! JavaScript into a conservative, parse-checked format.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use tree_sitter::{Node, Tree};

use crate::analysis::Analysis;
use crate::naming::{NameState, SemanticNameDocument};
use crate::parser::JsParser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderFormat {
    Preserve,
    Pretty,
}

#[derive(Debug, Clone)]
struct Replacement {
    start: usize,
    end: usize,
    text: String,
}

#[derive(Debug, Clone)]
struct Token {
    kind: String,
    text: String,
}

/// Recreate a target artifact from an approved semantic-name document.
///
/// The input bytes are never changed.  The returned string is a new artifact
/// containing replacements for declarations and resolved references belonging
/// to approved target symbols.  Pretty output is generated from that renamed
/// string and parsed again before it is returned.
pub fn render_semantic_names(
    document: &SemanticNameDocument,
    analysis: &Analysis,
    source: &str,
    format: RenderFormat,
) -> Result<String> {
    document.validate_against(analysis)?;
    let renamed = apply_approved_names(document, analysis, source)?;
    match format {
        RenderFormat::Preserve => {
            let mut parser = JsParser::new()?;
            parser.parse(&renamed)?;
            Ok(renamed)
        }
        RenderFormat::Pretty => {
            let mut parser = JsParser::new()?;
            let tree = parser.parse(&renamed)?;
            let formatted = pretty_format(&tree, &renamed);
            parser.parse(&formatted).map_err(|error| {
                anyhow::anyhow!("pretty rendering produced invalid JavaScript: {error}")
            })?;
            Ok(formatted)
        }
    }
}

/// Write a reconstructed artifact with the same atomic publication rule used
/// by the review documents.  The target input is never used as the output
/// path implicitly; callers must provide an explicit destination.
pub fn write_output(path: &Path, contents: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid rendered output file name"))?;
    let temporary = PathBuf::from(parent).join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn apply_approved_names(
    document: &SemanticNameDocument,
    analysis: &Analysis,
    source: &str,
) -> Result<String> {
    if source.len() as u64 != analysis.source_length {
        bail!("target source length does not match its analysis artifact");
    }
    let mut symbols_by_id = HashMap::with_capacity(analysis.symbols.len());
    for (row, symbol) in analysis.symbols.iter().enumerate() {
        symbols_by_id.insert(symbol.id.to_hex(), row);
    }

    let mut replacements = Vec::new();
    for entry in &document.symbols {
        if entry.state != NameState::Approved {
            continue;
        }
        let name = entry
            .semantic_name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("approved symbol has no semantic name"))?;
        let row = *symbols_by_id
            .get(&entry.symbol_id)
            .ok_or_else(|| anyhow::anyhow!("semantic-name symbol is not in the target analysis"))?;
        let symbol = &analysis.symbols[row];
        let generated_name = analysis.strings[symbol.name as usize].as_str();
        add_replacement(
            &mut replacements,
            source,
            &analysis.nodes[symbol.declaration_node as usize],
            generated_name,
            name,
        )?;
        let first = symbol.reference_first as usize;
        let end = first
            .checked_add(symbol.reference_count as usize)
            .ok_or_else(|| anyhow::anyhow!("symbol reference range overflows"))?;
        for reference in &analysis.references[first..end] {
            let generated_reference = analysis.strings[reference.name as usize].as_str();
            add_replacement(
                &mut replacements,
                source,
                &analysis.nodes[reference.node as usize],
                generated_reference,
                name,
            )?;
        }
    }

    replacements.sort_by_key(|replacement| (replacement.start, replacement.end));
    let mut previous_end = 0;
    let mut output = String::with_capacity(source.len());
    for replacement in replacements {
        if replacement.start < previous_end {
            bail!("approved symbol replacements overlap");
        }
        output.push_str(&source[previous_end..replacement.start]);
        output.push_str(&replacement.text);
        previous_end = replacement.end;
    }
    output.push_str(&source[previous_end..]);
    Ok(output)
}

fn add_replacement(
    replacements: &mut Vec<Replacement>,
    source: &str,
    node: &crate::analysis::AnalysisNode,
    generated_name: &str,
    semantic_name: &str,
) -> Result<()> {
    let start = usize::try_from(node.start_byte)?;
    let end = usize::try_from(node.end_byte)?;
    let actual = source
        .get(start..end)
        .ok_or_else(|| anyhow::anyhow!("symbol span is not valid UTF-8 source"))?;
    if actual != generated_name {
        bail!("symbol span contains {actual:?}, expected generated identifier {generated_name:?}");
    }
    replacements.push(Replacement {
        start,
        end,
        text: semantic_name.to_string(),
    });
    Ok(())
}

fn pretty_format(tree: &Tree, source: &str) -> String {
    let mut tokens = Vec::new();
    collect_tokens(tree.root_node(), source, &mut tokens);
    let mut formatter = Formatter::default();
    for index in 0..tokens.len() {
        formatter.emit(&tokens[index], tokens.get(index + 1));
    }
    formatter.finish()
}

fn collect_tokens(node: Node<'_>, source: &str, output: &mut Vec<Token>) {
    if is_opaque(node) || node.child_count() == 0 {
        if node.start_byte() < node.end_byte() {
            output.push(Token {
                kind: node.kind().to_string(),
                text: source[node.byte_range()].to_string(),
            });
        }
        return;
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            collect_tokens(cursor.node(), source, output);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn is_opaque(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "string" | "template_string" | "regex" | "jsx_text"
    )
}

#[derive(Default)]
struct Formatter {
    output: String,
    indent: usize,
    line_start: bool,
    parens: Vec<bool>,
    braces: Vec<bool>,
    previous: Option<Token>,
}

impl Formatter {
    fn emit(&mut self, token: &Token, next: Option<&Token>) {
        let text = token.text.as_str();
        if text.starts_with("//") {
            self.space_if_needed();
            self.write(text);
            self.newline();
            self.previous = Some(token.clone());
            return;
        }
        if text.starts_with("/*") {
            self.space_if_needed();
            self.write(text);
            if text.contains('\n') || next.is_some() {
                self.newline();
            }
            self.previous = Some(token.clone());
            return;
        }

        match text {
            "{" => {
                self.space_before_brace();
                self.write("{");
                let nonempty = match next {
                    Some(next) => next.text != "}",
                    None => true,
                };
                self.braces.push(nonempty);
                if nonempty {
                    self.indent = self.indent.saturating_add(1);
                    self.newline();
                }
            }
            "}" => {
                let nonempty = self.braces.pop().unwrap_or(true);
                if nonempty {
                    if !self.line_start {
                        self.newline();
                    }
                    self.indent = self.indent.saturating_sub(1);
                }
                self.write("}");
                if !matches!(
                    next.map(|value| value.text.as_str()),
                    Some(";" | "," | ")" | "]" | "." | "?." | "else" | "catch" | "finally")
                ) {
                    self.newline();
                }
            }
            ";" => {
                self.write(";");
                if !self.parens.iter().any(|is_for| *is_for) {
                    self.newline();
                } else {
                    self.space_if_needed();
                }
            }
            "," => {
                self.write(",");
                if next.is_some_and(|next| matches!(next.text.as_str(), "}" | "]")) {
                    return;
                }
                self.space_if_needed();
            }
            "(" => {
                if self.previous.as_ref().is_some_and(|previous| {
                    matches!(
                        previous.text.as_str(),
                        "if" | "for" | "while" | "switch" | "catch" | "with"
                    )
                }) {
                    self.space_if_needed();
                }
                let is_for = self
                    .previous
                    .as_ref()
                    .is_some_and(|previous| previous.text == "for");
                self.write("(");
                self.parens.push(is_for);
            }
            ")" => {
                self.trim_space();
                self.write(")");
                self.parens.pop();
            }
            "[" => self.write("["),
            "]" => {
                self.trim_space();
                self.write("]");
            }
            "." | "?." => {
                self.trim_space();
                self.write(text);
            }
            ":" => {
                self.trim_space();
                self.write(":");
                self.space_if_needed();
            }
            "?" if next.is_some_and(|next| next.text == ".") => {
                self.trim_space();
                self.write("?");
            }
            "?" => {
                self.space_if_needed();
                self.write("?");
                self.space_if_needed();
            }
            "++" | "--" | "!" | "~" => self.write(text),
            "+" | "-" => {
                if self.previous.as_ref().is_some_and(is_value_ending) {
                    self.space_if_needed();
                    self.write(text);
                    self.space_if_needed();
                } else {
                    self.write(text);
                }
            }
            "*" if self
                .previous
                .as_ref()
                .is_some_and(|previous| previous.text == "function") =>
            {
                self.write("*");
            }
            value if is_operator(value) => {
                self.space_if_needed();
                self.write(value);
                self.space_if_needed();
            }
            _ => {
                if self
                    .previous
                    .as_ref()
                    .is_some_and(|previous| needs_space_between(previous, token))
                {
                    self.space_if_needed();
                }
                self.write(text);
            }
        }
        self.previous = Some(token.clone());
    }

    fn write(&mut self, text: &str) {
        if self.line_start {
            for _ in 0..self.indent.saturating_mul(2) {
                self.output.push(' ');
            }
            self.line_start = false;
        }
        self.output.push_str(text);
    }

    fn space_before_brace(&mut self) {
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| !matches!(previous.text.as_str(), "(" | "[" | "." | "?." | "{"))
        {
            self.space_if_needed();
        }
    }

    fn space_if_needed(&mut self) {
        if !self.line_start && !self.output.ends_with(' ') && !self.output.ends_with('\n') {
            self.output.push(' ');
        }
    }

    fn trim_space(&mut self) {
        while self.output.ends_with(' ') {
            self.output.pop();
        }
    }

    fn newline(&mut self) {
        self.trim_space();
        if !self.output.ends_with('\n') {
            self.output.push('\n');
        }
        self.line_start = true;
    }

    fn finish(mut self) -> String {
        self.trim_space();
        while self.output.ends_with('\n') {
            self.output.pop();
        }
        if !self.output.is_empty() {
            self.output.push('\n');
        }
        self.output
    }
}

fn is_value_ending(token: &Token) -> bool {
    is_atom(token) || matches!(token.text.as_str(), ")" | "]" | "}")
}

fn needs_space_between(previous: &Token, current: &Token) -> bool {
    if is_atom(previous) && is_atom(current) {
        return true;
    }
    if matches!(previous.text.as_str(), ")" | "]" | "}") && is_atom(current) {
        return true;
    }
    previous.text == "*"
}

fn is_atom(token: &Token) -> bool {
    token.kind == "identifier"
        || token.kind == "private_property_identifier"
        || token.kind == "number"
        || token.kind == "string"
        || token.kind == "template_string"
        || token.kind == "regex"
        || matches!(
            token.text.as_str(),
            "true" | "false" | "null" | "this" | "super" | "undefined"
        )
        || token.text.chars().next().is_some_and(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '$'
        })
}

fn is_operator(value: &str) -> bool {
    matches!(
        value,
        "=" | "+="
            | "-="
            | "*="
            | "/="
            | "%="
            | "&&="
            | "||="
            | "??="
            | "=="
            | "==="
            | "!="
            | "!=="
            | "<"
            | "<="
            | ">"
            | ">="
            | "&&"
            | "||"
            | "??"
            | "+"
            | "-"
            | "*"
            | "/"
            | "%"
            | "=>"
            | "&"
            | "|"
            | "^"
            | "<<"
            | ">>"
            | ">>>"
            | "**"
            | "in"
            | "instanceof"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::Analysis;
    use crate::naming::SemanticNameDocument;
    use crate::parser::JsParser;

    fn analysis(source: &str) -> Analysis {
        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();
        Analysis::from_javascript(source, &tree).unwrap()
    }

    #[test]
    fn approved_names_are_recreated_without_mutating_the_input() {
        let source = "function a(b){const c=b+1;return c}";
        let analysis = analysis(source);
        let mut document = SemanticNameDocument::from_analysis(&analysis, true).unwrap();
        let ids = analysis
            .symbols
            .iter()
            .map(|symbol| {
                (
                    analysis.strings[symbol.name as usize].clone(),
                    symbol.id.to_hex(),
                )
            })
            .collect::<HashMap<_, _>>();
        for (generated, semantic) in [("a", "calculate_total"), ("b", "items"), ("c", "total")] {
            let id = ids.get(generated).unwrap();
            document
                .suggest(id, semantic.to_string(), provenance())
                .unwrap();
            document
                .transition(id, NameState::Approved, provenance())
                .unwrap();
        }
        let rendered =
            render_semantic_names(&document, &analysis, source, RenderFormat::Pretty).unwrap();
        assert_eq!(source, "function a(b){const c=b+1;return c}");
        assert_eq!(
            rendered,
            "function calculate_total(items) {\n  const total = items + 1;\n  return total\n}\n"
        );
        assert!(rendered.contains("calculate_total"));
        assert!(rendered.contains("const total = items + 1;"));
        assert!(!rendered.contains("function a"));
    }

    fn provenance() -> crate::naming::NameProvenance {
        crate::naming::NameProvenance {
            origin: "test".to_string(),
            actor: None,
            evidence_digest: None,
        }
    }
}
