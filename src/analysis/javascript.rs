//! JavaScript binding, reference, def-use, and call extraction.
//!
//! Scope discovery is shared with the canonicalizer for now.  This adapter
//! turns the analyzer's exact binding positions into language-neutral symbol
//! rows, then performs a separate deterministic lexical-resolution pass.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use tree_sitter::Node;

use crate::scope::{is_lexical_reference, ScopeAnalyzer, VariableKind};

use super::{
    stable_id, AnalysisCall, AnalysisCallKind, AnalysisDefUse, AnalysisNode, AnalysisReference,
    AnalysisReferenceRole, AnalysisResolution, AnalysisSymbol, AnalysisSymbolKind, StableId,
    StringInterner,
};

const NO_ROW: u32 = u32::MAX;

pub(super) struct SymbolGraph {
    pub symbols: Vec<AnalysisSymbol>,
    pub references: Vec<AnalysisReference>,
    pub def_uses: Vec<AnalysisDefUse>,
    pub calls: Vec<AnalysisCall>,
}

struct PendingReference {
    node: u32,
    scope: u32,
    name: u32,
    role: AnalysisReferenceRole,
    target: Option<u32>,
    resolution: AnalysisResolution,
}

pub(super) fn extract_graph(
    root: Node<'_>,
    source: &str,
    analyzer: &ScopeAnalyzer,
    scope_rows: &HashMap<String, u32>,
    nodes: &[AnalysisNode],
    node_lookup: &HashMap<usize, u32>,
    strings: &mut StringInterner,
) -> Result<SymbolGraph> {
    let (mut symbols, binding_nodes, symbols_by_name) =
        collect_symbols(analyzer, scope_rows, nodes, strings)?;
    let scope_parents = analyzer
        .get_scopes()
        .values()
        .map(|scope| {
            let row = scope_rows[&scope.id];
            let parent = scope
                .parent
                .as_ref()
                .and_then(|parent| scope_rows.get(parent))
                .copied();
            (row, parent)
        })
        .collect::<HashMap<_, _>>();
    let scope_by_span = analyzer
        .get_scopes()
        .values()
        .filter_map(|scope| {
            let parent = scope
                .parent
                .as_ref()
                .and_then(|parent| scope_rows.get(parent))
                .copied()?;
            Some((
                (parent, scope.start_byte, scope.end_byte),
                scope_rows[&scope.id],
            ))
        })
        .collect::<HashMap<_, _>>();
    let root_scope = scope_rows.get("global").copied().unwrap_or(0);

    let mut pending = Vec::new();
    collect_references(
        root,
        source,
        root_scope,
        &scope_by_span,
        node_lookup,
        strings,
        &binding_nodes,
        &symbols_by_name,
        &scope_parents,
        &mut pending,
    )?;

    // Group resolved references by symbol. This makes each symbol's def-use
    // neighborhood one O(1)-located contiguous slice.
    pending.sort_by_key(|reference| {
        let node = &nodes[reference.node as usize];
        (
            reference.target.unwrap_or(NO_ROW),
            node.start_byte,
            node.end_byte,
            reference.role as u8,
        )
    });

    let mut references = Vec::with_capacity(pending.len());
    let mut def_uses = Vec::with_capacity(pending.len());
    let mut reference_by_node = HashMap::new();
    for (row, pending) in pending.into_iter().enumerate() {
        let row = u32::try_from(row)?;
        let node_id = nodes[pending.node as usize].id;
        let reference_id = stable_id(
            b"astdiff/reference/v1",
            &[&node_id.0, &[pending.role as u8]],
        );
        let target_id = pending
            .target
            .map(|target| symbols[target as usize].id)
            .unwrap_or(StableId([0; 32]));
        let def_use_id = stable_id(
            b"astdiff/def-use/v1",
            &[&reference_id.0, &target_id.0, &[pending.resolution as u8]],
        );
        references.push(AnalysisReference {
            id: reference_id,
            node: pending.node,
            scope: pending.scope,
            name: pending.name,
            role: pending.role,
        });
        def_uses.push(AnalysisDefUse {
            id: def_use_id,
            reference: row,
            symbol: pending.target,
            resolution: pending.resolution,
        });
        reference_by_node.insert(pending.node, row);
    }

    let mut next_reference = 0usize;
    for (symbol_row, symbol) in symbols.iter_mut().enumerate() {
        while next_reference < def_uses.len()
            && def_uses[next_reference]
                .symbol
                .is_some_and(|target| (target as usize) < symbol_row)
        {
            next_reference += 1;
        }
        let first = next_reference;
        while next_reference < def_uses.len()
            && def_uses[next_reference].symbol == Some(symbol_row as u32)
        {
            next_reference += 1;
        }
        symbol.reference_first = u32::try_from(first)?;
        symbol.reference_count = u32::try_from(next_reference - first)?;
    }

    let mut calls = Vec::new();
    collect_calls(
        root,
        source,
        nodes,
        node_lookup,
        strings,
        &reference_by_node,
        &def_uses,
        &symbols,
        &mut calls,
    )?;
    calls.sort_by_key(|call| {
        let node = &nodes[call.node as usize];
        (node.start_byte, node.end_byte, call.kind as u8)
    });

    Ok(SymbolGraph {
        symbols,
        references,
        def_uses,
        calls,
    })
}

type SymbolsByName = HashMap<u32, HashMap<String, Vec<u32>>>;

fn collect_symbols(
    analyzer: &ScopeAnalyzer,
    scope_rows: &HashMap<String, u32>,
    nodes: &[AnalysisNode],
    strings: &mut StringInterner,
) -> Result<(Vec<AnalysisSymbol>, HashSet<u32>, SymbolsByName)> {
    let import_spans = spans_for_kind("import_statement", nodes, &strings.values);
    let catch_spans = spans_for_kind("catch_clause", nodes, &strings.values);
    let mut nodes_by_start: HashMap<u64, Vec<u32>> = HashMap::new();
    for (row, node) in nodes.iter().enumerate() {
        nodes_by_start
            .entry(node.start_byte)
            .or_default()
            .push(u32::try_from(row)?);
    }
    let mut candidates = Vec::new();
    for scope in analyzer.get_scopes().values() {
        let scope_row = scope_rows[&scope.id];
        let is_catch_scope =
            catch_spans.contains(&(scope.start_byte as u64, scope.end_byte as u64));
        for variable in &scope.variables {
            let declaration_node = smallest_node_starting_at(
                variable.declaration_byte,
                nodes,
                &strings.values,
                &nodes_by_start,
            )
            .ok_or_else(|| {
                anyhow!(
                    "binding '{}' at byte {} has no syntax node",
                    variable.name,
                    variable.declaration_byte
                )
            })?;
            let kind = symbol_kind(
                variable.kind.clone(),
                declaration_node,
                nodes,
                &import_spans,
                is_catch_scope,
            );
            candidates.push((
                scope_row,
                variable.declaration_byte,
                variable.name.clone(),
                declaration_node,
                kind,
            ));
        }
    }
    candidates.sort_by_key(|(scope, byte, name, node, kind)| {
        (*scope, *byte, *node, *kind as u8, name.clone())
    });
    candidates.dedup();

    let mut symbols = Vec::with_capacity(candidates.len());
    let mut binding_nodes = HashSet::new();
    let mut symbols_by_name: SymbolsByName = HashMap::new();
    let mut kinds_by_binding: HashMap<(u32, String), Vec<AnalysisSymbolKind>> = HashMap::new();
    for candidate in &candidates {
        kinds_by_binding
            .entry((candidate.0, candidate.2.clone()))
            .or_default()
            .push(candidate.4);
    }
    let mut merged_rows: HashMap<(u32, String), u32> = HashMap::new();
    for (scope, _, name_text, declaration_node, kind) in candidates {
        binding_nodes.insert(declaration_node);
        let binding_key = (scope, name_text.clone());
        let group_kinds = &kinds_by_binding[&binding_key];
        let merge_redeclarations = group_kinds.len() > 1
            && (group_kinds.iter().all(|kind| {
                matches!(kind, AnalysisSymbolKind::Var | AnalysisSymbolKind::Function)
            }) || group_kinds
                .iter()
                .all(|kind| *kind == AnalysisSymbolKind::Parameter));
        if merge_redeclarations && merged_rows.contains_key(&binding_key) {
            continue;
        }
        let merged_kind =
            if merge_redeclarations && group_kinds.contains(&AnalysisSymbolKind::Function) {
                AnalysisSymbolKind::Function
            } else {
                kind
            };
        let name = strings.intern(&name_text)?;
        let id = stable_id(
            b"astdiff/symbol/v1",
            &[&nodes[declaration_node as usize].id.0, &[merged_kind as u8]],
        );
        let row = u32::try_from(symbols.len())?;
        symbols.push(AnalysisSymbol {
            id,
            declaration_node,
            scope,
            name,
            kind: merged_kind,
            reference_first: 0,
            reference_count: 0,
        });
        symbols_by_name
            .entry(scope)
            .or_default()
            .entry(name_text.clone())
            .or_default()
            .push(row);
        if merge_redeclarations {
            merged_rows.insert(binding_key, row);
        }
    }

    Ok((symbols, binding_nodes, symbols_by_name))
}

fn smallest_node_starting_at(
    byte: usize,
    nodes: &[AnalysisNode],
    strings: &[String],
    nodes_by_start: &HashMap<u64, Vec<u32>>,
) -> Option<u32> {
    nodes_by_start
        .get(&(byte as u64))?
        .iter()
        .copied()
        .filter(|row| nodes[*row as usize].flags & 1 != 0)
        .min_by_key(|row| {
            let node = &nodes[*row as usize];
            let kind = strings[node.kind as usize].as_str();
            let binding_leaf = matches!(
                kind,
                "identifier"
                    | "shorthand_property_identifier_pattern"
                    | "shorthand_property_identifier"
            );
            (
                node.end_byte.saturating_sub(node.start_byte),
                u8::from(!binding_leaf),
            )
        })
}

fn symbol_kind(
    kind: VariableKind,
    declaration_node: u32,
    nodes: &[AnalysisNode],
    import_spans: &[(u64, u64)],
    is_catch_scope: bool,
) -> AnalysisSymbolKind {
    let byte = nodes[declaration_node as usize].start_byte;
    // ScopeAnalyzer currently represents imports as const and catch bindings
    // as parameters. Their containing syntax nodes disambiguate the portable
    // symbol kind without making spelling part of identity.
    if within_span(byte, import_spans) {
        return AnalysisSymbolKind::Import;
    }
    if is_catch_scope && kind == VariableKind::Parameter {
        return AnalysisSymbolKind::Catch;
    }
    match kind {
        VariableKind::FunctionDeclaration => AnalysisSymbolKind::Function,
        VariableKind::ClassDeclaration => AnalysisSymbolKind::Class,
        VariableKind::Var => AnalysisSymbolKind::Var,
        VariableKind::Let => AnalysisSymbolKind::Let,
        VariableKind::Const => AnalysisSymbolKind::Const,
        VariableKind::Parameter => AnalysisSymbolKind::Parameter,
    }
}

fn spans_for_kind(kind: &str, nodes: &[AnalysisNode], strings: &[String]) -> Vec<(u64, u64)> {
    nodes
        .iter()
        .filter(|node| strings[node.kind as usize] == kind)
        .map(|node| (node.start_byte, node.end_byte))
        .collect()
}

fn within_span(byte: u64, spans: &[(u64, u64)]) -> bool {
    spans
        .iter()
        .any(|(start, end)| *start <= byte && byte < *end)
}

#[allow(clippy::too_many_arguments)]
fn collect_references(
    node: Node<'_>,
    source: &str,
    current_scope: u32,
    scope_by_span: &HashMap<(u32, usize, usize), u32>,
    node_lookup: &HashMap<usize, u32>,
    strings: &mut StringInterner,
    binding_nodes: &HashSet<u32>,
    symbols_by_name: &SymbolsByName,
    scope_parents: &HashMap<u32, Option<u32>>,
    output: &mut Vec<PendingReference>,
) -> Result<()> {
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
    ) {
        let row = node_row(node, node_lookup)?;
        if !binding_nodes.contains(&row) && is_lexical_reference(node) {
            let name_text = source[node.byte_range()].to_string();
            let name = strings.intern(&name_text)?;
            let role = reference_role(node);
            let (target, resolution) =
                resolve(current_scope, &name_text, scope_parents, symbols_by_name);
            output.push(PendingReference {
                node: row,
                scope: current_scope,
                name,
                role,
                target,
                resolution,
            });
        }
    }

    let mut cursor = node.walk();
    let child_scope = scope_by_span
        .get(&(current_scope, node.start_byte(), node.end_byte()))
        .copied()
        .unwrap_or(current_scope);
    if cursor.goto_first_child() {
        loop {
            collect_references(
                cursor.node(),
                source,
                child_scope,
                scope_by_span,
                node_lookup,
                strings,
                binding_nodes,
                symbols_by_name,
                scope_parents,
                output,
            )?;
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    Ok(())
}

fn resolve(
    scope: u32,
    name: &str,
    scope_parents: &HashMap<u32, Option<u32>>,
    symbols_by_name: &SymbolsByName,
) -> (Option<u32>, AnalysisResolution) {
    let mut current = Some(scope);
    while let Some(scope_row) = current {
        if let Some(candidates) = symbols_by_name
            .get(&scope_row)
            .and_then(|symbols| symbols.get(name))
        {
            return match candidates.as_slice() {
                [symbol] => (Some(*symbol), AnalysisResolution::Resolved),
                _ => (None, AnalysisResolution::Ambiguous),
            };
        }
        current = scope_parents.get(&scope_row).copied().flatten();
    }
    (None, AnalysisResolution::Unresolved)
}

fn reference_role(node: Node<'_>) -> AnalysisReferenceRole {
    let mut ancestor = node.parent();
    while let Some(parent) = ancestor {
        let left = parent.child_by_field_name("left");
        let is_target = left.is_some_and(|left| is_direct_assignment_target(left, node));
        match parent.kind() {
            "assignment_expression" if is_target => return AnalysisReferenceRole::Write,
            "augmented_assignment_expression" if is_target => {
                return AnalysisReferenceRole::ReadWrite;
            }
            "for_in_statement" | "for_of_statement" if is_target => {
                return AnalysisReferenceRole::Write;
            }
            "update_expression" if is_direct_assignment_target(parent, node) => {
                return AnalysisReferenceRole::ReadWrite;
            }
            _ => ancestor = parent.parent(),
        }
    }

    let mut current = node;
    while let Some(parent) = current.parent() {
        let field = child_field_name(parent, current);
        match parent.kind() {
            "call_expression" if field == Some("function") => {
                return AnalysisReferenceRole::Call;
            }
            "new_expression" if field == Some("constructor") => {
                return AnalysisReferenceRole::Construct;
            }
            "export_specifier" if field == Some("name") => {
                return AnalysisReferenceRole::Export;
            }
            "parenthesized_expression"
            | "object_pattern"
            | "array_pattern"
            | "pair_pattern"
            | "rest_pattern"
            | "assignment_pattern" => current = parent,
            _ => break,
        }
    }
    AnalysisReferenceRole::Read
}

fn is_direct_assignment_target(container: Node<'_>, node: Node<'_>) -> bool {
    if !contains_node(container, node) {
        return false;
    }
    let mut current = node;
    while current.id() != container.id() {
        let Some(parent) = current.parent() else {
            return false;
        };
        if matches!(parent.kind(), "member_expression" | "subscript_expression") {
            return false;
        }
        if !matches!(
            parent.kind(),
            "parenthesized_expression"
                | "object_pattern"
                | "array_pattern"
                | "pair_pattern"
                | "rest_pattern"
                | "assignment_pattern"
                | "update_expression"
        ) && parent.id() != container.id()
        {
            return false;
        }
        current = parent;
    }
    true
}

fn contains_node(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}

#[allow(clippy::too_many_arguments)]
fn collect_calls(
    node: Node<'_>,
    source: &str,
    nodes: &[AnalysisNode],
    node_lookup: &HashMap<usize, u32>,
    strings: &mut StringInterner,
    reference_by_node: &HashMap<u32, u32>,
    def_uses: &[AnalysisDefUse],
    symbols: &[AnalysisSymbol],
    output: &mut Vec<AnalysisCall>,
) -> Result<()> {
    if matches!(node.kind(), "call_expression" | "new_expression") {
        let call_row = node_row(node, node_lookup)?;
        let callee = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("constructor"));
        let (kind, callee_reference, target_symbol, property) = if let Some(callee) = callee {
            let leaf = unwrap_parenthesized(callee);
            if matches!(leaf.kind(), "identifier" | "shorthand_property_identifier") {
                let leaf_row = node_row(leaf, node_lookup)?;
                let reference = reference_by_node.get(&leaf_row).copied();
                let target = reference
                    .and_then(|reference| def_uses.get(reference as usize))
                    .and_then(|def_use| def_use.symbol);
                let kind = if node.kind() == "new_expression" {
                    AnalysisCallKind::Construct
                } else {
                    AnalysisCallKind::Direct
                };
                (kind, reference, target, None)
            } else if leaf.kind() == "member_expression" {
                let object = leaf.child_by_field_name("object");
                let reference = object
                    .map(unwrap_parenthesized)
                    .filter(|object| {
                        matches!(
                            object.kind(),
                            "identifier" | "shorthand_property_identifier"
                        )
                    })
                    .and_then(|object| node_row(object, node_lookup).ok())
                    .and_then(|row| reference_by_node.get(&row).copied());
                let property = leaf
                    .child_by_field_name("property")
                    .map(|property| strings.intern(&source[property.byte_range()]))
                    .transpose()?;
                (AnalysisCallKind::Member, reference, None, property)
            } else {
                (AnalysisCallKind::Dynamic, None, None, None)
            }
        } else {
            (AnalysisCallKind::Dynamic, None, None, None)
        };
        let callee_id = callee_reference
            .and_then(|reference| def_uses.get(reference as usize))
            .map(|def_use| def_use.id)
            .unwrap_or(StableId([0; 32]));
        let target_id = target_symbol
            .and_then(|symbol| symbols.get(symbol as usize))
            .map(|symbol| symbol.id)
            .unwrap_or(StableId([0; 32]));
        let property_row = property.unwrap_or(NO_ROW);
        let id = stable_id(
            b"astdiff/call/v1",
            &[
                &nodes[call_row as usize].id.0,
                &[kind as u8],
                &callee_id.0,
                &target_id.0,
                &property_row.to_le_bytes(),
            ],
        );
        output.push(AnalysisCall {
            id,
            node: call_row,
            callee_reference,
            target_symbol,
            property,
            kind,
        });
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            collect_calls(
                cursor.node(),
                source,
                nodes,
                node_lookup,
                strings,
                reference_by_node,
                def_uses,
                symbols,
                output,
            )?;
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    Ok(())
}

fn unwrap_parenthesized(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let Some(child) = node.named_child(0) else {
            break;
        };
        node = child;
    }
    node
}

fn node_row(node: Node<'_>, lookup: &HashMap<usize, u32>) -> Result<u32> {
    lookup
        .get(&node.id())
        .copied()
        .ok_or_else(|| anyhow!("{} node has no analysis row", node.kind()))
}

fn child_field_name<'a>(parent: Node<'a>, child: Node<'a>) -> Option<&'static str> {
    for index in 0..parent.child_count() {
        if parent
            .child(index)
            .is_some_and(|candidate| candidate.id() == child.id())
        {
            return parent.field_name_for_child(index as u32);
        }
    }
    None
}
