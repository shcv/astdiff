//! Deterministic reconstruction of a target JavaScript artifact.
//!
//! Rendering is deliberately a separate output step.  The source artifact and
//! its analysis remain immutable; this module applies only approved semantic
//! names to lexical symbol occurrences and optionally reflows the resulting
//! JavaScript into a conservative, parse-checked format.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Result};

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
            crate::pretty::format(&tree, &renamed)
        }
    }
}

/// Write a reconstructed artifact with the same atomic publication rule used
/// by the review documents.  The target input is never used as the output
/// path implicitly; callers must provide an explicit destination.
pub fn write_output(path: &Path, contents: &str) -> Result<()> {
    crate::atomic_file::write(path, &[contents.as_bytes()])
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
