//! Whitespace-only formatting, checked against the original syntax tree.

use anyhow::Result;
use sha2::{Digest, Sha256};
use tree_sitter::{Node, Tree};

#[derive(Debug, Clone)]
struct Token {
    kind: &'static str,
    text: String,
    start: usize,
    end: usize,
}

fn syntax_hash(tree: &Tree, source: &str) -> [u8; 32] {
    fn visit(node: Node<'_>, source: &str, hash: &mut Sha256) {
        if node.kind() == "comment" {
            return;
        }
        hash.update((node.kind().len() as u64).to_le_bytes());
        hash.update(node.kind().as_bytes());
        if node.child_count() == 0 {
            hash.update((node.byte_range().len() as u64).to_le_bytes());
            hash.update(&source.as_bytes()[node.byte_range()]);
        }
        for child in node.children(&mut node.walk()) {
            visit(child, source, hash);
        }
        hash.update([0xff]);
    }
    let mut hash = Sha256::new();
    visit(tree.root_node(), source, &mut hash);
    hash.finalize().into()
}

pub fn format(tree: &Tree, source: &str) -> Result<String> {
    let mut tokens = Vec::new();
    collect_tokens(tree.root_node(), source, &mut tokens);
    let mut formatter = Formatter::default();
    for index in 0..tokens.len() {
        if index > 0
            && source[tokens[index - 1].end..tokens[index].start]
                .contains(['\n', '\r', '\u{2028}', '\u{2029}'])
        {
            formatter.newline();
        }
        formatter.emit(&tokens[index], tokens.get(index + 1));
    }
    let formatted = formatter.finish();
    let parsed = crate::parser::JsParser::new()?.parse(&formatted)?;
    if syntax_hash(tree, source) != syntax_hash(&parsed, &formatted) {
        anyhow::bail!("formatting would change JavaScript syntax");
    }
    Ok(formatted)
}

fn collect_tokens(node: Node<'_>, source: &str, output: &mut Vec<Token>) {
    if is_opaque(node) || node.child_count() == 0 {
        if node.start_byte() < node.end_byte() {
            output.push(Token {
                kind: node.kind(),
                start: node.start_byte(),
                end: node.end_byte(),
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
        "string"
            | "template_string"
            | "regex"
            | "jsx_element"
            | "jsx_self_closing_element"
            | "jsx_text"
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
            if text.contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
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
                    Some(
                        ";" | ","
                            | ")"
                            | "]"
                            | "."
                            | "?."
                            | "else"
                            | "catch"
                            | "finally"
                            | "of"
                            | "in"
                    )
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

    #[test]
    fn formatting_preserves_parameters_modifiers_literals_and_asi() {
        for source in [
            "for(let {spec:Y,note:U} of values){console.log(Y,U);}",
            "async function f(x=1,...rest){return x;}",
            "function* f({x},[y],...rest){yield x+y;}",
            "function f(x){return\nx;}",
            "function f(x){return /* inline */ x;}",
            "let x=1,y=2; x\n++y;",
            "for(let i=0;i<3;i++){console.log(i);}",
            "const pattern=/[a-z]+/gi; const text=`line ${pattern}\nnext`;",
            "const view=<div> keep  this <b>text</b> </div>;",
            "// leading\nfunction f(){// comment\nreturn 1;}",
        ] {
            let tree = crate::parser::JsParser::new()
                .unwrap()
                .parse(source)
                .unwrap();
            let formatted = format(&tree, source).unwrap();
            let parsed = crate::parser::JsParser::new()
                .unwrap()
                .parse(&formatted)
                .unwrap();
            assert_eq!(
                syntax_hash(&tree, source),
                syntax_hash(&parsed, &formatted),
                "{source}"
            );
        }
    }
}
