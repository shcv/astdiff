//! Language-neutral analysis data and persistence.
//!
//! The current JavaScript diff remains independent of this module.  This is
//! the first Phase-5 adapter: it records the complete tree shape, lexical
//! scopes, declarations, stable artifact-local identities, provenance, and an
//! explicit loss report in deterministic column order.

mod cache;
mod javascript;

pub use cache::{
    AnalysisCacheView, CachedCall, CachedDefUse, CachedLoss, CachedNode, CachedReference,
    CachedScope, CachedSymbol, MappedAnalysis,
};

use std::collections::{HashMap, HashSet};
use std::fmt;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tree_sitter::{Node, Tree};

use crate::scope::{ScopeAnalyzer, ScopeType};

/// Version of the language-neutral analysis model.
pub const ANALYSIS_VERSION: u32 = 1;
/// Identity of the first persisted analysis profile.
pub const ANALYSIS_PROFILE: &str = "astdiff.analysis.v1";
/// Parser identity pinned by this adapter.
pub const JAVASCRIPT_FRONTEND: &str = "tree-sitter-javascript";
/// Grammar crate version pinned in `Cargo.lock`.
pub const JAVASCRIPT_FRONTEND_VERSION: &str = "0.20.4";

/// A deterministic 256-bit identity, kept distinct from row indexes and names.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StableId(pub [u8; 32]);

impl StableId {
    /// Lowercase hexadecimal representation for logs and JSON views.
    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }
}

impl fmt::Debug for StableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for StableId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

/// Supported source-language identities.  The persisted numeric value is an
/// explicit contract rather than a Rust enum discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Language {
    /// ECMAScript parsed by the JavaScript tree-sitter grammar.
    JavaScript = 1,
}

/// One syntax node in deterministic pre-order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisNode {
    pub id: StableId,
    pub parent: Option<u32>,
    pub child_ordinal: u32,
    pub kind: u32,
    pub start_byte: u64,
    pub end_byte: u64,
    pub flags: u8,
}

/// Language-neutral lexical-scope categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum AnalysisScopeKind {
    Global = 1,
    Function = 2,
    Block = 3,
    Class = 4,
    Module = 5,
}

/// One lexical scope. Row indexes are local references; `id` is the durable
/// artifact-local identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisScope {
    pub id: StableId,
    pub parent: Option<u32>,
    pub kind: AnalysisScopeKind,
    pub depth: u32,
    pub start_byte: u64,
    pub end_byte: u64,
}

/// Language-neutral symbol categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum AnalysisSymbolKind {
    Function = 1,
    Var = 2,
    Let = 3,
    Const = 4,
    Parameter = 5,
    Class = 6,
    Import = 7,
    Catch = 8,
}

/// One lexical binding. Its identity never contains its spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisSymbol {
    pub id: StableId,
    pub declaration_node: u32,
    pub scope: u32,
    pub name: u32,
    pub kind: AnalysisSymbolKind,
    pub reference_first: u32,
    pub reference_count: u32,
}

/// The lexical operation performed by an identifier occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum AnalysisReferenceRole {
    Read = 1,
    Write = 2,
    ReadWrite = 3,
    Call = 4,
    Construct = 5,
    Export = 6,
}

/// One lexical identifier occurrence, ordered by resolved symbol then source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisReference {
    pub id: StableId,
    pub node: u32,
    pub scope: u32,
    pub name: u32,
    pub role: AnalysisReferenceRole,
}

/// Result of resolving a reference through lexical scope parents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum AnalysisResolution {
    Resolved = 1,
    Unresolved = 2,
    Ambiguous = 3,
}

/// One reference-to-symbol resolution record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisDefUse {
    pub id: StableId,
    pub reference: u32,
    pub symbol: Option<u32>,
    pub resolution: AnalysisResolution,
}

/// Static shape of a call expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum AnalysisCallKind {
    Direct = 1,
    Member = 2,
    Construct = 3,
    Dynamic = 4,
}

/// One direct, member, constructor, or dynamic call site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisCall {
    pub id: StableId,
    pub node: u32,
    pub callee_reference: Option<u32>,
    pub target_symbol: Option<u32>,
    pub property: Option<u32>,
    pub kind: AnalysisCallKind,
}

/// A capability deliberately absent from this first adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u16)]
pub enum LossCode {
    SourceMapLineageUnavailable = 1,
    FingerprintEvidenceUnavailable = 2,
    DynamicCallTargetUnavailable = 3,
    TdzAndFlowResolutionUnavailable = 4,
    DynamicScopeUnavailable = 5,
}

/// Machine-readable loss record. `message` indexes the shared string table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LossRecord {
    pub code: LossCode,
    pub message: u32,
}

/// Deterministic language-neutral analysis of one source artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Analysis {
    pub version: u32,
    pub profile: String,
    pub producer: String,
    pub producer_version: String,
    pub language: Language,
    pub frontend: String,
    pub frontend_version: String,
    pub source_digest: [u8; 32],
    pub source_length: u64,
    pub strings: Vec<String>,
    pub nodes: Vec<AnalysisNode>,
    pub scopes: Vec<AnalysisScope>,
    pub symbols: Vec<AnalysisSymbol>,
    pub references: Vec<AnalysisReference>,
    pub def_uses: Vec<AnalysisDefUse>,
    pub calls: Vec<AnalysisCall>,
    pub losses: Vec<LossRecord>,
}

impl Analysis {
    /// Build the Phase-5 JavaScript analysis without changing the current diff
    /// or dump pipeline.
    pub fn from_javascript(source: &str, tree: &Tree) -> Result<Self> {
        let source_digest = digest(source.as_bytes());
        let mut strings = StringInterner::default();
        for metadata in [
            ANALYSIS_PROFILE,
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            JAVASCRIPT_FRONTEND,
            JAVASCRIPT_FRONTEND_VERSION,
        ] {
            strings.intern(metadata)?;
        }
        let mut nodes = Vec::new();
        let mut node_lookup = HashMap::new();
        collect_nodes(
            tree.root_node(),
            None,
            0,
            &mut strings,
            &mut nodes,
            &mut node_lookup,
        )?;

        let mut scope_analyzer = ScopeAnalyzer::new();
        scope_analyzer.analyze(tree.root_node(), source)?;
        let (scopes, scope_rows) = collect_scopes(&scope_analyzer)?;

        let graph = javascript::extract_graph(
            tree.root_node(),
            source,
            &scope_analyzer,
            &scope_rows,
            &nodes,
            &node_lookup,
            &mut strings,
        )?;

        let losses = [
            (
                LossCode::SourceMapLineageUnavailable,
                "source-map lineage is deferred to analysis phase 6",
            ),
            (
                LossCode::FingerprintEvidenceUnavailable,
                "legacy matcher fingerprints are not part of analysis v1",
            ),
            (
                LossCode::DynamicCallTargetUnavailable,
                "member and dynamic call targets require a later flow-analysis pass",
            ),
            (
                LossCode::TdzAndFlowResolutionUnavailable,
                "analysis v1 lexical resolution does not model temporal dead zones or assignments",
            ),
            (
                LossCode::DynamicScopeUnavailable,
                "with and direct eval can invalidate static lexical resolution",
            ),
        ]
        .into_iter()
        .map(|(code, message)| {
            Ok(LossRecord {
                code,
                message: strings.intern(message)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

        let analysis = Self {
            version: ANALYSIS_VERSION,
            profile: ANALYSIS_PROFILE.to_string(),
            producer: env!("CARGO_PKG_NAME").to_string(),
            producer_version: env!("CARGO_PKG_VERSION").to_string(),
            language: Language::JavaScript,
            frontend: JAVASCRIPT_FRONTEND.to_string(),
            frontend_version: JAVASCRIPT_FRONTEND_VERSION.to_string(),
            source_digest,
            source_length: u64::try_from(source.len())?,
            strings: strings.values,
            nodes,
            scopes,
            symbols: graph.symbols,
            references: graph.references,
            def_uses: graph.def_uses,
            calls: graph.calls,
            losses,
        };
        analysis.validate()?;
        Ok(analysis)
    }

    /// Validate application-level relationships which Isoform's structural
    /// verifier intentionally cannot know about.
    pub fn validate(&self) -> Result<()> {
        if self.version != ANALYSIS_VERSION
            || self.profile != ANALYSIS_PROFILE
            || self.producer != env!("CARGO_PKG_NAME")
            || self.producer_version != env!("CARGO_PKG_VERSION")
            || self.frontend != JAVASCRIPT_FRONTEND
            || self.frontend_version != JAVASCRIPT_FRONTEND_VERSION
        {
            bail!("unsupported analysis version or profile");
        }
        if self.source_length > u64::from(u32::MAX) {
            bail!("analysis v1 supports source artifacts smaller than 4 GiB");
        }
        if self.nodes.is_empty() || self.scopes.is_empty() {
            bail!("analysis requires a syntax root and global scope");
        }
        let mut next_child_ordinal = vec![0u32; self.nodes.len()];
        let mut open_nodes = Vec::new();
        for (index, node) in self.nodes.iter().enumerate() {
            if node.start_byte > node.end_byte || node.end_byte > self.source_length {
                bail!("node {index} has an invalid source span");
            }
            if node.flags & !0x0f != 0 {
                bail!("node {index} has unknown flags");
            }
            if node.parent.is_some_and(|parent| parent as usize >= index) {
                bail!("node {index} has an invalid parent");
            }
            if index > 0 {
                while open_nodes.last().copied() != node.parent {
                    if open_nodes.pop().is_none() {
                        bail!("node {index} is not in syntax-tree pre-order");
                    }
                }
            }
            if let Some(parent) = node.parent {
                let parent = &self.nodes[parent as usize];
                if node.start_byte < parent.start_byte || node.end_byte > parent.end_byte {
                    bail!("node {index} is outside its parent span");
                }
                if node.child_ordinal != next_child_ordinal[node.parent.unwrap() as usize] {
                    bail!("node {index} has an invalid child ordinal");
                }
                let parent_row = node.parent.unwrap() as usize;
                next_child_ordinal[parent_row] = next_child_ordinal[parent_row]
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("node {parent_row} has too many children"))?;
            } else if index != 0 || node.child_ordinal != 0 {
                bail!("node {index} has an invalid root ordinal");
            }
            if node.kind as usize >= self.strings.len() {
                bail!("node {index} has an invalid kind string");
            }
            if index == 0
                && (node.start_byte != 0
                    || node.end_byte != self.source_length
                    || self.strings[node.kind as usize] != "program")
            {
                bail!("analysis has an invalid JavaScript syntax root");
            }
            let parent_row = node.parent.unwrap_or(u32::MAX);
            let expected_id = stable_id(
                b"astdiff/node/v1",
                &[
                    &parent_row.to_le_bytes(),
                    &node.child_ordinal.to_le_bytes(),
                    self.strings[node.kind as usize].as_bytes(),
                    &[node.flags],
                ],
            );
            if node.id != expected_id {
                bail!("node {index} has an invalid stable ID");
            }
            open_nodes.push(u32::try_from(index)?);
        }
        let mut seen_scope_ids = HashSet::with_capacity(self.scopes.len());
        for (index, scope) in self.scopes.iter().enumerate() {
            if scope.start_byte > scope.end_byte || scope.end_byte > self.source_length {
                bail!("scope {index} has an invalid source span");
            }
            if scope.parent.is_some_and(|parent| parent as usize >= index) {
                bail!("scope {index} has an invalid parent");
            }
            if index == 0 {
                if scope.parent.is_some()
                    || scope.kind != AnalysisScopeKind::Global
                    || scope.depth != 0
                    || scope.start_byte != 0
                    || scope.end_byte != self.source_length
                {
                    bail!("analysis has an invalid global scope");
                }
            } else {
                let parent_row = scope
                    .parent
                    .ok_or_else(|| anyhow::anyhow!("scope {index} has no parent"))?;
                let parent = &self.scopes[parent_row as usize];
                if Some(scope.depth) != parent.depth.checked_add(1)
                    || scope.start_byte < parent.start_byte
                    || scope.end_byte > parent.end_byte
                {
                    bail!("scope {index} is inconsistent with its parent");
                }
            }
            let parent_row = scope.parent.unwrap_or(u32::MAX);
            let expected_id = stable_id(
                b"astdiff/scope/v1",
                &[
                    &parent_row.to_le_bytes(),
                    &[scope.kind as u8],
                    &scope.depth.to_le_bytes(),
                    &scope.start_byte.to_le_bytes(),
                    &scope.end_byte.to_le_bytes(),
                ],
            );
            if scope.id != expected_id {
                bail!("scope {index} has an invalid stable ID");
            }
            if !seen_scope_ids.insert(scope.id) {
                bail!("scope {index} duplicates another scope identity");
            }
        }
        let mut next_symbol_reference = 0usize;
        let mut seen_symbol_nodes = vec![false; self.nodes.len()];
        for (index, symbol) in self.symbols.iter().enumerate() {
            if symbol.declaration_node as usize >= self.nodes.len()
                || symbol.scope as usize >= self.scopes.len()
                || symbol.name as usize >= self.strings.len()
            {
                bail!("symbol {index} contains an invalid row reference");
            }
            let declaration = &self.nodes[symbol.declaration_node as usize];
            if std::mem::replace(
                &mut seen_symbol_nodes[symbol.declaration_node as usize],
                true,
            ) {
                bail!("symbol {index} reuses another symbol's declaration node");
            }
            let scope = &self.scopes[symbol.scope as usize];
            if declaration.start_byte < scope.start_byte || declaration.end_byte > scope.end_byte {
                bail!("symbol {index} is outside its declared scope");
            }
            let expected_id = stable_id(
                b"astdiff/symbol/v1",
                &[
                    &self.nodes[symbol.declaration_node as usize].id.0,
                    &[symbol.kind as u8],
                ],
            );
            if symbol.id != expected_id {
                bail!("symbol {index} has an invalid stable ID");
            }
            let end = symbol
                .reference_first
                .checked_add(symbol.reference_count)
                .ok_or_else(|| anyhow::anyhow!("symbol {index} reference range overflows"))?;
            if symbol.reference_first as usize != next_symbol_reference
                || end as usize > self.references.len()
            {
                bail!("symbol {index} has an invalid reference range");
            }
            next_symbol_reference = end as usize;
        }
        if self.references.len() != self.def_uses.len() {
            bail!("reference and def-use row counts differ");
        }
        let mut seen_reference_nodes = vec![false; self.nodes.len()];
        for (index, reference) in self.references.iter().enumerate() {
            if reference.node as usize >= self.nodes.len()
                || reference.scope as usize >= self.scopes.len()
                || reference.name as usize >= self.strings.len()
            {
                bail!("reference {index} contains an invalid row reference");
            }
            let node = &self.nodes[reference.node as usize];
            if std::mem::replace(&mut seen_reference_nodes[reference.node as usize], true) {
                bail!("reference {index} reuses another reference node");
            }
            let scope = &self.scopes[reference.scope as usize];
            if node.start_byte < scope.start_byte || node.end_byte > scope.end_byte {
                bail!("reference {index} is outside its recorded scope");
            }
            let expected_id = stable_id(
                b"astdiff/reference/v1",
                &[
                    &self.nodes[reference.node as usize].id.0,
                    &[reference.role as u8],
                ],
            );
            if reference.id != expected_id {
                bail!("reference {index} has an invalid stable ID");
            }
            let def_use = &self.def_uses[index];
            if def_use.reference as usize != index
                || def_use
                    .symbol
                    .is_some_and(|symbol| symbol as usize >= self.symbols.len())
                || (def_use.resolution == AnalysisResolution::Resolved && def_use.symbol.is_none())
                || (def_use.resolution != AnalysisResolution::Resolved && def_use.symbol.is_some())
            {
                bail!("def-use {index} contains an invalid resolution");
            }
            let target_id = def_use
                .symbol
                .map(|symbol| self.symbols[symbol as usize].id)
                .unwrap_or(StableId([0; 32]));
            let expected_id = stable_id(
                b"astdiff/def-use/v1",
                &[&reference.id.0, &target_id.0, &[def_use.resolution as u8]],
            );
            if def_use.id != expected_id {
                bail!("def-use {index} has an invalid stable ID");
            }
        }
        for (symbol_row, symbol) in self.symbols.iter().enumerate() {
            let first = symbol.reference_first as usize;
            let end = first
                .checked_add(symbol.reference_count as usize)
                .ok_or_else(|| anyhow::anyhow!("symbol {symbol_row} reference range overflows"))?;
            if self.def_uses[first..end]
                .iter()
                .any(|edge| edge.symbol != Some(symbol_row as u32))
            {
                bail!("symbol {symbol_row} reference range contains another symbol");
            }
        }
        if self.def_uses[next_symbol_reference..]
            .iter()
            .any(|edge| edge.symbol.is_some())
        {
            bail!("resolved def-use row is outside its symbol reference range");
        }
        let mut seen_call_nodes = vec![false; self.nodes.len()];
        for (index, call) in self.calls.iter().enumerate() {
            if call.node as usize >= self.nodes.len()
                || call
                    .callee_reference
                    .is_some_and(|reference| reference as usize >= self.references.len())
                || call
                    .target_symbol
                    .is_some_and(|symbol| symbol as usize >= self.symbols.len())
                || call
                    .property
                    .is_some_and(|property| property as usize >= self.strings.len())
            {
                bail!("call {index} contains an invalid row reference");
            }
            if std::mem::replace(&mut seen_call_nodes[call.node as usize], true) {
                bail!("call {index} reuses another call node");
            }
            let call_node = &self.nodes[call.node as usize];
            let call_node_kind = self.strings[call_node.kind as usize].as_str();
            let valid_node_kind = match call.kind {
                AnalysisCallKind::Direct => call_node_kind == "call_expression",
                AnalysisCallKind::Construct => call_node_kind == "new_expression",
                AnalysisCallKind::Member | AnalysisCallKind::Dynamic => {
                    matches!(call_node_kind, "call_expression" | "new_expression")
                }
            };
            if !valid_node_kind {
                bail!("call {index} has an invalid syntax node kind");
            }
            if let Some(callee) = call.callee_reference {
                let callee_node = &self.nodes[self.references[callee as usize].node as usize];
                if callee_node.start_byte < call_node.start_byte
                    || callee_node.end_byte > call_node.end_byte
                {
                    bail!("call {index} callee is outside the call expression");
                }
            }
            validate_call_shape(
                index,
                call.kind,
                call.callee_reference,
                call.target_symbol,
                call.property,
                &self.references,
                &self.def_uses,
            )?;
            let callee_id = call
                .callee_reference
                .map(|reference| self.def_uses[reference as usize].id)
                .unwrap_or(StableId([0; 32]));
            let target_id = call
                .target_symbol
                .map(|symbol| self.symbols[symbol as usize].id)
                .unwrap_or(StableId([0; 32]));
            let property = call.property.unwrap_or(u32::MAX);
            let expected_id = stable_id(
                b"astdiff/call/v1",
                &[
                    &self.nodes[call.node as usize].id.0,
                    &[call.kind as u8],
                    &callee_id.0,
                    &target_id.0,
                    &property.to_le_bytes(),
                ],
            );
            if call.id != expected_id {
                bail!("call {index} has an invalid stable ID");
            }
        }
        for (index, loss) in self.losses.iter().enumerate() {
            if loss.message as usize >= self.strings.len() {
                bail!("loss {index} contains an invalid message reference");
            }
        }
        Ok(())
    }
}

fn validate_call_shape(
    index: usize,
    kind: AnalysisCallKind,
    callee: Option<u32>,
    target: Option<u32>,
    property: Option<u32>,
    references: &[AnalysisReference],
    def_uses: &[AnalysisDefUse],
) -> Result<()> {
    match kind {
        AnalysisCallKind::Direct | AnalysisCallKind::Construct => {
            let callee = callee.ok_or_else(|| anyhow::anyhow!("call {index} has no callee"))?;
            if property.is_some() || def_uses[callee as usize].symbol != target {
                bail!("call {index} has inconsistent direct-call relationships");
            }
            let expected_role = if kind == AnalysisCallKind::Construct {
                AnalysisReferenceRole::Construct
            } else {
                AnalysisReferenceRole::Call
            };
            if references[callee as usize].role != expected_role {
                bail!("call {index} has an invalid callee role");
            }
        }
        AnalysisCallKind::Member => {
            if property.is_none() || target.is_some() {
                bail!("call {index} has inconsistent member-call relationships");
            }
        }
        AnalysisCallKind::Dynamic => {
            if callee.is_some() || target.is_some() || property.is_some() {
                bail!("call {index} has inconsistent dynamic-call relationships");
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct StringInterner {
    values: Vec<String>,
    indexes: HashMap<String, u32>,
}

impl StringInterner {
    fn intern(&mut self, value: &str) -> Result<u32> {
        if let Some(index) = self.indexes.get(value) {
            return Ok(*index);
        }
        let index = u32::try_from(self.values.len())?;
        self.values.push(value.to_string());
        self.indexes.insert(value.to_string(), index);
        Ok(index)
    }
}

fn collect_nodes(
    node: Node<'_>,
    parent: Option<u32>,
    child_ordinal: u32,
    strings: &mut StringInterner,
    nodes: &mut Vec<AnalysisNode>,
    lookup: &mut HashMap<usize, u32>,
) -> Result<u32> {
    let index = u32::try_from(nodes.len())?;
    let kind = strings.intern(node.kind())?;
    let start_byte = u64::try_from(node.start_byte())?;
    let end_byte = u64::try_from(node.end_byte())?;
    let flags = u8::from(node.is_named())
        | (u8::from(node.is_extra()) << 1)
        | (u8::from(node.is_error()) << 2)
        | (u8::from(node.is_missing()) << 3);
    let parent_row = parent.unwrap_or(u32::MAX);
    let id = stable_id(
        b"astdiff/node/v1",
        &[
            &parent_row.to_le_bytes(),
            &child_ordinal.to_le_bytes(),
            node.kind().as_bytes(),
            &[flags],
        ],
    );
    nodes.push(AnalysisNode {
        id,
        parent,
        child_ordinal,
        kind,
        start_byte,
        end_byte,
        flags,
    });
    lookup.insert(node.id(), index);

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        let mut ordinal = 0u32;
        loop {
            collect_nodes(cursor.node(), Some(index), ordinal, strings, nodes, lookup)?;
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("syntax node has too many children"))?;
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    Ok(index)
}

fn collect_scopes(analyzer: &ScopeAnalyzer) -> Result<(Vec<AnalysisScope>, HashMap<String, u32>)> {
    let mut source_scopes = analyzer.get_scopes().values().collect::<Vec<_>>();
    source_scopes.sort_by_key(|scope| {
        (
            scope.depth,
            scope.start_byte,
            scope.end_byte,
            scope_kind(&scope.scope_type) as u8,
            scope.id.as_str(),
        )
    });
    let mut rows = HashMap::new();
    let mut scopes = Vec::with_capacity(source_scopes.len());
    for scope in source_scopes {
        let row = u32::try_from(scopes.len())?;
        let kind = scope_kind(&scope.scope_type);
        let parent = scope
            .parent
            .as_ref()
            .and_then(|parent| rows.get(parent).copied());
        let parent_row = parent.unwrap_or(u32::MAX);
        let start = u64::try_from(scope.start_byte)?;
        let end = u64::try_from(scope.end_byte)?;
        let depth = u32::try_from(scope.depth)?;
        let id = stable_id(
            b"astdiff/scope/v1",
            &[
                &parent_row.to_le_bytes(),
                &[kind as u8],
                &depth.to_le_bytes(),
                &start.to_le_bytes(),
                &end.to_le_bytes(),
            ],
        );
        rows.insert(scope.id.clone(), row);
        scopes.push(AnalysisScope {
            id,
            parent,
            kind,
            depth,
            start_byte: start,
            end_byte: end,
        });
    }
    Ok((scopes, rows))
}

fn scope_kind(kind: &ScopeType) -> AnalysisScopeKind {
    match kind {
        ScopeType::Global => AnalysisScopeKind::Global,
        ScopeType::Function => AnalysisScopeKind::Function,
        ScopeType::Block => AnalysisScopeKind::Block,
        ScopeType::Class => AnalysisScopeKind::Class,
        ScopeType::Module => AnalysisScopeKind::Module,
    }
}

pub(super) fn stable_id(domain: &[u8], parts: &[&[u8]]) -> StableId {
    let mut hasher = Sha256::new();
    hasher.update(u64::try_from(domain.len()).unwrap().to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(u64::try_from(part.len()).unwrap().to_le_bytes());
        hasher.update(part);
    }
    StableId(hasher.finalize().into())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::JsParser;

    fn analyze(source: &str) -> Analysis {
        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();
        Analysis::from_javascript(source, &tree).unwrap()
    }

    #[test]
    fn javascript_analysis_is_deterministic_and_name_is_not_symbol_identity_input() {
        let source = "function alpha(value) { return value + 1; }";
        let first = analyze(source);
        let second = analyze(source);
        assert_eq!(first, second);
        assert_eq!(first.symbols.len(), 2);
        let function = first
            .symbols
            .iter()
            .find(|symbol| symbol.kind == AnalysisSymbolKind::Function)
            .unwrap();
        assert_eq!(first.strings[function.name as usize], "alpha");

        let renamed = analyze("function x(value) { return value + 1; }");
        let renamed_function = renamed
            .symbols
            .iter()
            .find(|symbol| symbol.kind == AnalysisSymbolKind::Function)
            .unwrap();
        assert_eq!(function.id, renamed_function.id);
        assert_ne!(first.source_digest, renamed.source_digest);
    }

    #[test]
    fn analysis_records_explicit_phase_five_losses() {
        let analysis = analyze("const answer = 42;");
        assert_eq!(analysis.losses.len(), 5);
        assert!(analysis.validate().is_ok());
    }

    #[test]
    fn analysis_rejects_ids_that_do_not_match_their_structural_inputs() {
        let mut analysis = analyze("function answer() { return 42; }");
        analysis.symbols[0].id.0[0] ^= 0x01;
        assert!(analysis
            .validate()
            .unwrap_err()
            .to_string()
            .contains("invalid stable ID"));
    }

    #[test]
    fn javascript_graph_covers_bindings_shadowing_roles_and_calls() {
        let analysis = analyze(
            r#"import {a as imported} from "m";
               const outer = 1;
               function run({value}, ...rest) {
                   let local = value;
                   local += outer;
                   return helper(local) + rest.length + imported;
               }
               new Widget();
               console.log(outer);"#,
        );
        let symbol_names = analysis
            .symbols
            .iter()
            .map(|symbol| analysis.strings[symbol.name as usize].as_str())
            .collect::<Vec<_>>();
        for expected in ["imported", "outer", "run", "value", "rest", "local"] {
            assert!(
                symbol_names.contains(&expected),
                "missing symbol {expected}"
            );
        }
        assert!(analysis.references.iter().any(|reference| {
            analysis.strings[reference.name as usize] == "local"
                && reference.role == AnalysisReferenceRole::ReadWrite
        }));
        assert!(analysis
            .calls
            .iter()
            .any(|call| call.kind == AnalysisCallKind::Direct));
        assert!(analysis
            .calls
            .iter()
            .any(|call| call.kind == AnalysisCallKind::Construct));
        assert!(analysis.calls.iter().any(|call| {
            call.kind == AnalysisCallKind::Member
                && call
                    .property
                    .is_some_and(|property| analysis.strings[property as usize] == "log")
        }));
        assert!(analysis
            .def_uses
            .iter()
            .any(|edge| { edge.resolution == AnalysisResolution::Unresolved }));
        assert!(analysis.validate().is_ok());
    }

    #[test]
    fn javascript_graph_covers_patterns_imports_and_property_boundaries() {
        let analysis = analyze(
            r#"import d, * as ns from "m";
               import {a as b, c} from "m2";
               const {x: y, z, ...rest} = obj;
               let outer = 1;
               function f({p: alias, q, ...spread}, [first, , ...items], ...args) {
                   let {q: local, r} = alias;
                   const fn = () => local + outer;
                   local += q;
                   return fn(local) + ns.f(b);
               }
               class C extends Base { method(param) { return param.foo; } }
               export {f as run};"#,
        );
        let mut names = analysis
            .symbols
            .iter()
            .map(|symbol| analysis.strings[symbol.name as usize].clone())
            .collect::<Vec<_>>();
        names.sort();
        for expected in [
            "d", "ns", "b", "c", "y", "z", "rest", "outer", "f", "alias", "q", "spread", "first",
            "items", "args", "local", "r", "fn", "C", "param",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "missing {expected}: {names:?}"
            );
        }
        assert!(!names.iter().any(|name| name == "x"));
        let reference_names = analysis
            .references
            .iter()
            .map(|reference| analysis.strings[reference.name as usize].as_str())
            .collect::<Vec<_>>();
        assert!(!reference_names.contains(&"foo"));
        assert!(!reference_names.contains(&"run"));
        assert!(reference_names.contains(&"f"));
        assert!(analysis.calls.iter().any(|call| {
            call.kind == AnalysisCallKind::Member
                && call
                    .property
                    .is_some_and(|property| analysis.strings[property as usize] == "f")
        }));
        assert!(analysis.validate().is_ok());
    }

    #[test]
    fn javascript_def_use_resolution_obeys_lexical_shadowing() {
        let source = r#"let value = 0;
            function f(value) {
                let inner = value;
                { let value = 2; inner = value; }
                return value;
            }"#;
        let analysis = analyze(source);
        let value_symbols = analysis
            .symbols
            .iter()
            .enumerate()
            .filter(|(_, symbol)| analysis.strings[symbol.name as usize] == "value")
            .map(|(row, symbol)| (row as u32, analysis.scopes[symbol.scope as usize].depth))
            .collect::<Vec<_>>();
        assert_eq!(value_symbols.len(), 3);

        let mut resolved_depths = analysis
            .references
            .iter()
            .zip(&analysis.def_uses)
            .filter(|(reference, _)| analysis.strings[reference.name as usize] == "value")
            .map(|(_, edge)| {
                let symbol = &analysis.symbols[edge
                    .symbol
                    .unwrap_or_else(|| panic!("unexpected value resolution: {:?}", edge.resolution))
                    as usize];
                analysis.scopes[symbol.scope as usize].depth
            })
            .collect::<Vec<_>>();
        resolved_depths.sort_unstable();
        assert_eq!(resolved_depths, vec![1, 1, 2]);
    }

    #[test]
    fn javascript_assignment_patterns_and_for_of_are_writes_not_bindings() {
        let analysis =
            analyze("let value; ({value} = source); for (value of values) { consume(value); }");
        let value_symbols = analysis
            .symbols
            .iter()
            .filter(|symbol| analysis.strings[symbol.name as usize] == "value")
            .count();
        assert_eq!(value_symbols, 1);
        let roles = analysis
            .references
            .iter()
            .filter(|reference| analysis.strings[reference.name as usize] == "value")
            .map(|reference| reference.role)
            .collect::<Vec<_>>();
        assert_eq!(
            roles
                .iter()
                .filter(|role| **role == AnalysisReferenceRole::Write)
                .count(),
            2,
            "{roles:?}"
        );
        assert!(roles.contains(&AnalysisReferenceRole::Read));
    }

    #[test]
    fn javascript_member_bases_remain_reads_when_members_are_written() {
        let analysis =
            analyze("let obj = {}, key = 'x'; obj.x = 1; obj.x++; obj[key] = 2; obj[key]++;");
        let obj_roles = analysis
            .references
            .iter()
            .filter(|reference| analysis.strings[reference.name as usize] == "obj")
            .map(|reference| reference.role)
            .collect::<Vec<_>>();
        assert_eq!(obj_roles.len(), 4);
        assert!(obj_roles
            .iter()
            .all(|role| *role == AnalysisReferenceRole::Read));
        let key_roles = analysis
            .references
            .iter()
            .filter(|reference| analysis.strings[reference.name as usize] == "key")
            .map(|reference| reference.role)
            .collect::<Vec<_>>();
        assert_eq!(key_roles, vec![AnalysisReferenceRole::Read; 2]);
    }

    #[test]
    fn javascript_catch_kind_is_limited_to_the_catch_binding() {
        let analysis = analyze(
            "try { work(); } catch (error) { let body = 1; function nested(param) { return error + body + param; } }",
        );
        let kind = |name: &str| {
            analysis
                .symbols
                .iter()
                .find(|symbol| analysis.strings[symbol.name as usize] == name)
                .map(|symbol| symbol.kind)
                .unwrap()
        };
        assert_eq!(kind("error"), AnalysisSymbolKind::Catch);
        assert_eq!(kind("body"), AnalysisSymbolKind::Let);
        assert_eq!(kind("nested"), AnalysisSymbolKind::Function);
        assert_eq!(kind("param"), AnalysisSymbolKind::Parameter);
    }

    #[test]
    fn javascript_legal_redeclarations_share_one_binding() {
        let analysis = analyze(
            "var repeated; var repeated; repeated = 1; function same() {} function same() {} same();",
        );
        for name in ["repeated", "same"] {
            assert_eq!(
                analysis
                    .symbols
                    .iter()
                    .filter(|symbol| analysis.strings[symbol.name as usize] == name)
                    .count(),
                1
            );
            assert!(analysis
                .references
                .iter()
                .zip(&analysis.def_uses)
                .any(|(reference, edge)| {
                    analysis.strings[reference.name as usize] == name
                        && edge.resolution == AnalysisResolution::Resolved
                }));
        }
    }

    #[test]
    fn javascript_optional_calls_use_the_normal_call_shape() {
        let analysis =
            analyze("let fn = () => {}; let obj = {m: fn}; fn?.(); obj?.m(); obj.m?.();");
        assert_eq!(analysis.calls.len(), 3);
        assert!(analysis
            .calls
            .iter()
            .any(|call| call.kind == AnalysisCallKind::Direct));
        assert_eq!(
            analysis
                .calls
                .iter()
                .filter(|call| call.kind == AnalysisCallKind::Member)
                .count(),
            2
        );
    }
}
