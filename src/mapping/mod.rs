use crate::canonicalizer::Canonicalizer;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tree_sitter::Tree;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingEntry {
    pub first_line: usize,
    pub first_col: usize,
    pub last_line: usize,
    pub last_col: usize,
    pub entry_type: String, // func, param, var
    pub scope_id: String,   // scope where variable is defined
    pub original: String,   // original identifier
    pub canonical: String,  // fn_1, param_1, etc.
    pub new_name: String,   // user-editable semantic name
}

pub struct MappingGenerator {
    canonicalizer: Canonicalizer,
    source: String,
}

impl MappingGenerator {
    pub fn new(canonicalizer: Canonicalizer, source: String) -> Self {
        Self {
            canonicalizer,
            source,
        }
    }

    pub fn generate_mapping_file(&self, tree: &Tree) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str("# FIRST LAST TYPE SCOPE CANONICAL NEW\n");

        // Collect all identifiers and group by (scope, original_name) to ensure uniqueness
        let mut identifier_groups: HashMap<
            (String, String, String),
            Vec<crate::scope::IdentifierInfo>,
        > = HashMap::new();
        let canonicalizer_identifiers = self
            .canonicalizer
            .scope_analyzer
            .resolved_identifiers(tree.root_node(), &self.source);

        for identifier in canonicalizer_identifiers {
            if let Some(canonical_name) = self
                .canonicalizer
                .find_canonical_name(&identifier.text, &identifier.scope_id)
            {
                // Group by scope and original name to handle variables with same name in different scopes
                let key = (
                    identifier.scope_id.clone(),
                    identifier.text.clone(),
                    canonical_name.to_owned(),
                );
                identifier_groups.entry(key).or_default().push(identifier);
            }
        }

        // Create entries with first and last positions
        let mut entries = Vec::new();
        for ((scope_id, original_name, canonical_name), identifiers) in identifier_groups {
            if identifiers.is_empty() {
                continue;
            }

            // Find first and last positions
            let first = identifiers
                .iter()
                .min_by_key(|id| id.node.start_byte())
                .unwrap();
            let last = identifiers
                .iter()
                .max_by_key(|id| id.node.start_byte())
                .unwrap();

            // Determine type from canonical name prefix
            let entry_type = if canonical_name.starts_with("fn_") {
                "func".to_string()
            } else if canonical_name.starts_with("param_") {
                "param".to_string()
            } else {
                "var".to_string()
            };

            entries.push(MappingEntry {
                first_line: first.node.start_position().row + 1,
                first_col: first.node.start_position().column + 1,
                last_line: last.node.start_position().row + 1,
                last_col: last.node.start_position().column + 1,
                entry_type,
                scope_id: scope_id.clone(),
                original: original_name.clone(),
                canonical: canonical_name.clone(),
                new_name: canonical_name,
            });
        }

        // Sort by first occurrence
        entries.sort_by_key(|e| (e.first_line, e.first_col));

        // Format entries
        for entry in entries {
            output.push_str(&format!(
                "{}:{} {}:{} {} {} {} {}\n",
                entry.first_line,
                entry.first_col,
                entry.last_line,
                entry.last_col,
                entry.entry_type,
                entry.scope_id,
                entry.canonical,
                entry.new_name
            ));
        }

        Ok(output)
    }

    pub fn parse_mapping_file(content: &str) -> Result<HashMap<String, String>> {
        let mut mappings = HashMap::new();

        for line in content.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                // Format: first:col last:col type scope canonical new
                let canonical = parts[4];
                let new_name = parts[5];
                mappings.insert(canonical.to_string(), new_name.to_string());
            }
        }

        Ok(mappings)
    }

    pub fn apply_mappings(&self, tree: &Tree, mappings: HashMap<String, String>) -> Result<String> {
        self.canonicalizer
            .apply_names(tree, &self.source, &mappings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalizer::Canonicalizer;
    use crate::parser::JsParser;
    use crate::scope::ScopeAnalyzer;

    #[test]
    fn test_mapping_generation() {
        let source = "function add(a, b) { return a + b; }";

        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();

        let mut analyzer = ScopeAnalyzer::new();
        analyzer.analyze(tree.root_node(), source).unwrap();

        let mut canonicalizer = Canonicalizer::new(analyzer);
        canonicalizer.canonicalize(&tree, source).unwrap();

        let generator = MappingGenerator::new(canonicalizer, source.to_string());
        let mapping_file = generator.generate_mapping_file(&tree).unwrap();

        assert!(mapping_file.contains("# FIRST LAST TYPE SCOPE CANONICAL NEW"));
        assert!(mapping_file.contains("fn_"));

        let mappings = MappingGenerator::parse_mapping_file(&mapping_file).unwrap();
        assert!(mappings.keys().any(|key| key.starts_with("fn_")));
    }
}
