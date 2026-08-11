//! Strict, bounded JSON documents for semantic-name review and propagation.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analysis::{Analysis, AnalysisCallKind, AnalysisReferenceRole, AnalysisResolution};
use crate::lineage::{semantic_container, LineageReport, MatchDecision};
use crate::sourcemap::SourceMap;

const FORMAT: &str = "astdiff.semantic-name-review.v1";
const INSTRUCTIONS: &str = "Assign suggestions with the names set command; suggestions require explicit approval before propagation.";
const MAX_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_SYMBOLS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum NameState {
    Unknown,
    Suggested,
    Approved,
    Rejected,
    Cleared,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NameProvenance {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamingIdentity {
    pub profile: String,
    pub format_version: u32,
    pub source_digest: String,
    pub analysis_digest: String,
    pub producer: String,
    pub producer_version: String,
    pub language: String,
    pub frontend: String,
    pub frontend_version: String,
    pub source_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NameEvent {
    pub operation_id: String,
    pub revision: u64,
    pub symbol_id: String,
    pub previous_state: NameState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_name: Option<String>,
    pub new_state: NameState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    pub provenance: NameProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamingScope {
    pub id: String,
    pub kind: String,
    pub depth: u32,
    pub ancestor_kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamingDeclaration {
    pub node_id: String,
    pub kind: String,
    pub start_byte: u64,
    pub end_byte: u64,
    pub ancestor_kinds: Vec<String>,
    pub child_kinds: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamingUsage {
    pub reference_count: u32,
    pub read: u32,
    pub write: u32,
    pub read_write: u32,
    pub call: u32,
    pub construct: u32,
    pub export: u32,
    pub resolved: u32,
    pub unresolved: u32,
    pub ambiguous: u32,
    pub direct_calls: u32,
    pub member_calls: u32,
    pub constructor_calls: u32,
    pub dynamic_calls: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamingReferenceContext {
    pub node_id: String,
    pub role: String,
    pub resolution: String,
    pub parent_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_symbol_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamingCallContext {
    pub node_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_symbol_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticNameEntry {
    pub symbol_id: String,
    pub state: NameState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_name: Option<String>,
    pub kind: String,
    pub scope: NamingScope,
    pub declaration: NamingDeclaration,
    pub usage: NamingUsage,
    pub references: Vec<NamingReferenceContext>,
    pub references_truncated: bool,
    pub calls: Vec<NamingCallContext>,
    pub calls_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<NameProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticNameDocument {
    pub format: String,
    pub revision: u64,
    pub instructions: String,
    pub analysis: NamingIdentity,
    pub redacted: bool,
    pub symbols: Vec<SemanticNameEntry>,
    pub events: Vec<NameEvent>,
}

impl SemanticNameDocument {
    pub fn from_analysis(analysis: &Analysis, include_generated: bool) -> Result<Self> {
        analysis.validate()?;
        let mut symbols = Vec::with_capacity(analysis.symbols.len());
        for (row, symbol) in analysis.symbols.iter().enumerate() {
            let declaration_row = semantic_container(analysis, symbol.declaration_node as usize);
            let declaration = &analysis.nodes[declaration_row];
            let scope = &analysis.scopes[symbol.scope as usize];
            let mut scope_ancestors = Vec::new();
            let mut parent_scope = scope.parent;
            while let Some(parent) = parent_scope {
                let value = &analysis.scopes[parent as usize];
                scope_ancestors.push(label(value.kind));
                parent_scope = value.parent;
            }
            let mut ancestors = Vec::new();
            let mut parent_node = declaration.parent;
            while let Some(parent) = parent_node {
                if ancestors.len() == 6 {
                    break;
                }
                let value = &analysis.nodes[parent as usize];
                ancestors.push(analysis.strings[value.kind as usize].clone());
                parent_node = value.parent;
            }
            let all_children = analysis
                .nodes
                .iter()
                .filter(|node| node.parent == Some(declaration_row as u32))
                .collect::<Vec<_>>();
            let child_kinds = all_children
                .iter()
                .take(12)
                .map(|node| analysis.strings[node.kind as usize].clone())
                .collect();
            symbols.push(SemanticNameEntry {
                symbol_id: symbol.id.to_hex(),
                state: NameState::Unknown,
                semantic_name: None,
                generated_name: include_generated
                    .then(|| analysis.strings[symbol.name as usize].clone()),
                kind: label(symbol.kind),
                scope: NamingScope {
                    id: scope.id.to_hex(),
                    kind: label(scope.kind),
                    depth: scope.depth,
                    ancestor_kinds: scope_ancestors,
                },
                declaration: NamingDeclaration {
                    node_id: declaration.id.to_hex(),
                    kind: analysis.strings[declaration.kind as usize].clone(),
                    start_byte: declaration.start_byte,
                    end_byte: declaration.end_byte,
                    ancestor_kinds: ancestors,
                    child_kinds,
                    truncated: all_children.len() > 12,
                },
                usage: usage(
                    analysis,
                    row as u32,
                    symbol.reference_first,
                    symbol.reference_count,
                ),
                references: reference_contexts(
                    analysis,
                    symbol.reference_first,
                    symbol.reference_count,
                ),
                references_truncated: symbol.reference_count > 24,
                calls: call_contexts(analysis, row as u32),
                calls_truncated: analysis
                    .calls
                    .iter()
                    .filter(|call| {
                        call.target_symbol == Some(row as u32)
                            || call.callee_reference.is_some_and(|reference| {
                                reference >= symbol.reference_first
                                    && reference < symbol.reference_first + symbol.reference_count
                            })
                    })
                    .count()
                    > 16,
                provenance: None,
            });
        }
        symbols.sort_by(|left, right| left.symbol_id.cmp(&right.symbol_id));
        let document = Self {
            format: FORMAT.to_string(),
            revision: 0,
            instructions: INSTRUCTIONS.to_string(),
            analysis: NamingIdentity {
                profile: analysis.profile.clone(),
                format_version: analysis.version,
                source_digest: hex(&analysis.source_digest),
                analysis_digest: analysis_digest(analysis)?,
                producer: analysis.producer.clone(),
                producer_version: analysis.producer_version.clone(),
                language: label(analysis.language),
                frontend: analysis.frontend.clone(),
                frontend_version: analysis.frontend_version.clone(),
                source_length: analysis.source_length,
            },
            redacted: !include_generated,
            symbols,
            events: Vec::new(),
        };
        document.validate()?;
        Ok(document)
    }

    pub fn read(path: &Path) -> Result<Self> {
        let length = fs::metadata(path)
            .with_context(|| format!("failed to inspect {}", path.display()))?
            .len();
        if length > MAX_DOCUMENT_BYTES {
            bail!("semantic-name document exceeds the read limit");
        }
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let document: Self = serde_json::from_slice(&bytes)?;
        document.validate()?;
        Ok(document)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        write_atomic(path, &bytes)
    }

    pub fn validate_against(&self, analysis: &Analysis) -> Result<()> {
        self.validate()?;
        analysis.validate()?;
        if self.analysis.profile != analysis.profile
            || self.analysis.format_version != analysis.version
            || self.analysis.source_digest != hex(&analysis.source_digest)
            || self.analysis.analysis_digest != analysis_digest(analysis)?
            || self.analysis.producer != analysis.producer
            || self.analysis.producer_version != analysis.producer_version
            || self.analysis.language != label(analysis.language)
            || self.analysis.frontend != analysis.frontend
            || self.analysis.frontend_version != analysis.frontend_version
            || self.analysis.source_length != analysis.source_length
        {
            bail!("semantic-name document is for a different analysis artifact");
        }
        let ids = analysis
            .symbols
            .iter()
            .map(|symbol| symbol.id.to_hex())
            .collect::<HashSet<_>>();
        if ids.len() != self.symbols.len()
            || self
                .symbols
                .iter()
                .any(|entry| !ids.contains(&entry.symbol_id))
        {
            bail!("semantic-name symbol set disagrees with its analysis artifact");
        }
        let baseline = Self::from_analysis(analysis, !self.redacted)?;
        for (entry, expected) in self.symbols.iter().zip(&baseline.symbols) {
            let mut immutable = entry.clone();
            immutable.state = NameState::Unknown;
            immutable.semantic_name = None;
            immutable.provenance = None;
            if immutable != *expected {
                bail!("semantic-name structural context was modified");
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != FORMAT || self.instructions != INSTRUCTIONS {
            bail!("unsupported semantic-name document");
        }
        validate_hex(&self.analysis.source_digest)?;
        validate_hex(&self.analysis.analysis_digest)?;
        for value in [
            &self.analysis.profile,
            &self.analysis.producer,
            &self.analysis.producer_version,
            &self.analysis.language,
            &self.analysis.frontend,
            &self.analysis.frontend_version,
        ] {
            validate_token(value)?;
        }
        if self.symbols.len() > MAX_SYMBOLS || self.events.len() > MAX_SYMBOLS.saturating_mul(8) {
            bail!("semantic-name document exceeds its row limits");
        }

        let mut prior = None;
        let mut approved = HashSet::new();
        let mut replay = HashMap::new();
        for entry in &self.symbols {
            validate_hex(&entry.symbol_id)?;
            validate_hex(&entry.scope.id)?;
            validate_hex(&entry.declaration.node_id)?;
            if prior.is_some_and(|value: &str| value >= entry.symbol_id.as_str()) {
                bail!("semantic-name symbols are not strictly ID-sorted");
            }
            prior = Some(entry.symbol_id.as_str());
            validate_state_name(entry.state, entry.semantic_name.as_deref())?;
            if let Some(name) = &entry.semantic_name {
                validate_text(name)?;
                if entry.state == NameState::Approved
                    && !approved.insert((entry.scope.id.clone(), name.clone()))
                {
                    bail!("approved semantic name collides in one scope");
                }
            }
            if let Some(name) = &entry.generated_name {
                validate_text(name)?;
            }
            if self.redacted && entry.generated_name.is_some() {
                bail!("redacted semantic-name document contains a generated name");
            }
            for value in [
                entry.kind.as_str(),
                entry.scope.kind.as_str(),
                entry.declaration.kind.as_str(),
            ] {
                validate_token(value)?;
            }
            for kind in entry
                .scope
                .ancestor_kinds
                .iter()
                .chain(&entry.declaration.ancestor_kinds)
                .chain(&entry.declaration.child_kinds)
            {
                validate_token(kind)?;
            }
            if entry.declaration.start_byte > entry.declaration.end_byte
                || entry.declaration.end_byte > self.analysis.source_length
                || entry.declaration.ancestor_kinds.len() > 6
                || entry.declaration.child_kinds.len() > 12
                || entry.references.len() > 24
                || entry.calls.len() > 16
            {
                bail!("semantic-name declaration context is invalid");
            }
            for reference in &entry.references {
                validate_hex(&reference.node_id)?;
                validate_token(&reference.role)?;
                validate_token(&reference.resolution)?;
                validate_token(&reference.parent_kind)?;
                if let Some(target) = &reference.target_symbol_id {
                    validate_hex(target)?;
                }
            }
            for call in &entry.calls {
                validate_hex(&call.node_id)?;
                validate_token(&call.kind)?;
                if let Some(target) = &call.target_symbol_id {
                    validate_hex(target)?;
                }
            }
            if entry.state != NameState::Unknown && entry.provenance.is_none() {
                bail!("edited semantic-name entry has no provenance");
            }
            if let Some(provenance) = &entry.provenance {
                validate_provenance(provenance)?;
            }
            replay.insert(
                entry.symbol_id.clone(),
                (NameState::Unknown, None::<String>, None::<NameProvenance>),
            );
        }

        let mut operation_ids = HashSet::new();
        for (index, event) in self.events.iter().enumerate() {
            if event.revision != index as u64 + 1 || !operation_ids.insert(&event.operation_id) {
                bail!("semantic-name event history is not canonical");
            }
            validate_hex(&event.operation_id)?;
            validate_hex(&event.symbol_id)?;
            validate_provenance(&event.provenance)?;
            if let Some(name) = &event.previous_name {
                validate_text(name)?;
            }
            if let Some(name) = &event.new_name {
                validate_text(name)?;
            }
            validate_state_name(event.new_state, event.new_name.as_deref())?;
            let current = replay
                .get_mut(&event.symbol_id)
                .ok_or_else(|| anyhow!("semantic-name event references an unknown symbol"))?;
            if current.0 != event.previous_state || current.1 != event.previous_name {
                bail!("semantic-name event history has a stale precondition");
            }
            current.0 = event.new_state;
            current.1 = event.new_name.clone();
            current.2 = Some(event.provenance.clone());
        }
        if self.revision != self.events.len() as u64 {
            bail!("semantic-name revision disagrees with event history");
        }
        for entry in &self.symbols {
            let current = replay
                .get(&entry.symbol_id)
                .expect("every symbol has replay state");
            if current.0 != entry.state
                || current.1 != entry.semantic_name
                || current.2 != entry.provenance
            {
                bail!("semantic-name materialized state disagrees with event history");
            }
        }
        Ok(())
    }

    pub fn suggest(
        &mut self,
        symbol_id: &str,
        name: String,
        provenance: NameProvenance,
    ) -> Result<()> {
        validate_text(&name)?;
        self.apply_event(symbol_id, NameState::Suggested, Some(name), provenance)
    }

    pub fn transition(
        &mut self,
        symbol_id: &str,
        state: NameState,
        provenance: NameProvenance,
    ) -> Result<()> {
        let entry = self.entry(symbol_id)?;
        let name = match state {
            NameState::Approved if entry.state == NameState::Suggested => {
                entry.semantic_name.clone()
            }
            NameState::Rejected if entry.state == NameState::Suggested => None,
            NameState::Cleared
                if matches!(entry.state, NameState::Suggested | NameState::Approved) =>
            {
                None
            }
            _ => bail!("invalid semantic-name state transition"),
        };
        self.apply_event(symbol_id, state, name, provenance)
    }

    fn entry(&self, symbol_id: &str) -> Result<&SemanticNameEntry> {
        validate_hex(symbol_id)?;
        self.symbols
            .iter()
            .find(|entry| entry.symbol_id == symbol_id)
            .ok_or_else(|| anyhow!("unknown symbol ID"))
    }

    fn entry_mut(&mut self, symbol_id: &str) -> Result<&mut SemanticNameEntry> {
        validate_hex(symbol_id)?;
        self.symbols
            .iter_mut()
            .find(|entry| entry.symbol_id == symbol_id)
            .ok_or_else(|| anyhow!("unknown symbol ID"))
    }

    fn apply_event(
        &mut self,
        symbol_id: &str,
        state: NameState,
        name: Option<String>,
        provenance: NameProvenance,
    ) -> Result<()> {
        validate_provenance(&provenance)?;
        validate_state_name(state, name.as_deref())?;
        let entry = self.entry(symbol_id)?;
        if entry.state == state && entry.semantic_name == name {
            return Ok(());
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow!("revision overflow"))?;
        let operation_id = operation_id(symbol_id, state, name.as_deref(), &provenance);
        if self
            .events
            .iter()
            .any(|event| event.operation_id == operation_id)
        {
            return Ok(());
        }
        let event = NameEvent {
            operation_id,
            revision,
            symbol_id: symbol_id.to_string(),
            previous_state: entry.state,
            previous_name: entry.semantic_name.clone(),
            new_state: state,
            new_name: name.clone(),
            provenance: provenance.clone(),
        };
        let entry = self.entry_mut(symbol_id)?;
        entry.semantic_name = name;
        entry.state = state;
        entry.provenance = Some(provenance);
        self.revision = revision;
        self.events.push(event);
        self.symbols
            .sort_by(|left, right| left.symbol_id.cmp(&right.symbol_id));
        self.validate()
    }
}

pub fn propagate_approved_names(
    source: &SemanticNameDocument,
    lineage: &LineageReport,
    source_analysis: &Analysis,
    target: &Analysis,
) -> Result<SemanticNameDocument> {
    source.validate_against(source_analysis)?;
    lineage.validate_against(source_analysis, target)?;
    propagate_validated_names(source, lineage, target)
}

/// Propagate approved names through a lineage report bound to exact generated
/// JavaScript and exact raw Source Map v3 inputs.
pub struct SourceMapPropagationInputs<'a> {
    pub source_text: &'a str,
    pub target_text: &'a str,
    pub source_map: &'a SourceMap,
    pub target_map: &'a SourceMap,
}

pub fn propagate_approved_names_with_source_maps(
    source: &SemanticNameDocument,
    lineage: &LineageReport,
    source_analysis: &Analysis,
    target: &Analysis,
    maps: SourceMapPropagationInputs<'_>,
) -> Result<SemanticNameDocument> {
    source.validate_against(source_analysis)?;
    lineage.validate_against_with_source_maps(
        source_analysis,
        target,
        maps.source_text,
        maps.target_text,
        maps.source_map,
        maps.target_map,
    )?;
    propagate_validated_names(source, lineage, target)
}

fn propagate_validated_names(
    source: &SemanticNameDocument,
    lineage: &LineageReport,
    target: &Analysis,
) -> Result<SemanticNameDocument> {
    let approved = source
        .symbols
        .iter()
        .filter(|entry| entry.state == NameState::Approved)
        .map(|entry| (entry.symbol_id.as_str(), entry))
        .collect::<HashMap<_, _>>();
    let mut output = SemanticNameDocument::from_analysis(target, false)?;
    for matched in &lineage.matches {
        if matched.decision != MatchDecision::Accepted {
            continue;
        }
        let (Some(source), Some(target_id)) = (
            approved.get(matched.source_symbol_id.as_str()),
            matched.target_symbol_id.as_ref(),
        ) else {
            continue;
        };
        output.apply_event(
            target_id,
            NameState::Approved,
            source.semantic_name.clone(),
            NameProvenance {
                origin: "lineage".to_string(),
                actor: None,
                evidence_digest: Some(lineage.config_digest.clone()),
            },
        )?;
    }
    output.validate()?;
    Ok(output)
}

fn reference_contexts(analysis: &Analysis, first: u32, count: u32) -> Vec<NamingReferenceContext> {
    (first..first + count)
        .take(24)
        .map(|row| {
            let reference = &analysis.references[row as usize];
            let def_use = &analysis.def_uses[row as usize];
            let node = &analysis.nodes[reference.node as usize];
            let parent_kind = node.parent.map_or("program", |parent| {
                let parent = &analysis.nodes[parent as usize];
                analysis.strings[parent.kind as usize].as_str()
            });
            NamingReferenceContext {
                node_id: node.id.to_hex(),
                role: label(reference.role),
                resolution: label(def_use.resolution),
                parent_kind: parent_kind.to_string(),
                target_symbol_id: def_use
                    .symbol
                    .map(|symbol| analysis.symbols[symbol as usize].id.to_hex()),
            }
        })
        .collect()
}

fn call_contexts(analysis: &Analysis, symbol: u32) -> Vec<NamingCallContext> {
    let binding = &analysis.symbols[symbol as usize];
    let reference_end = binding.reference_first + binding.reference_count;
    analysis
        .calls
        .iter()
        .filter(|call| {
            call.target_symbol == Some(symbol)
                || call.callee_reference.is_some_and(|reference| {
                    reference >= binding.reference_first && reference < reference_end
                })
        })
        .take(16)
        .map(|call| NamingCallContext {
            node_id: analysis.nodes[call.node as usize].id.to_hex(),
            kind: label(call.kind),
            target_symbol_id: call
                .target_symbol
                .map(|target| analysis.symbols[target as usize].id.to_hex()),
        })
        .collect()
}

fn usage(analysis: &Analysis, symbol: u32, first: u32, count: u32) -> NamingUsage {
    let mut value = NamingUsage {
        reference_count: count,
        ..NamingUsage::default()
    };
    for row in first..first + count {
        match analysis.references[row as usize].role {
            AnalysisReferenceRole::Read => value.read += 1,
            AnalysisReferenceRole::Write => value.write += 1,
            AnalysisReferenceRole::ReadWrite => value.read_write += 1,
            AnalysisReferenceRole::Call => value.call += 1,
            AnalysisReferenceRole::Construct => value.construct += 1,
            AnalysisReferenceRole::Export => value.export += 1,
        }
        match analysis.def_uses[row as usize].resolution {
            AnalysisResolution::Resolved => value.resolved += 1,
            AnalysisResolution::Unresolved => value.unresolved += 1,
            AnalysisResolution::Ambiguous => value.ambiguous += 1,
        }
    }
    for call in analysis
        .calls
        .iter()
        .filter(|call| call.target_symbol == Some(symbol))
    {
        match call.kind {
            AnalysisCallKind::Direct => value.direct_calls += 1,
            AnalysisCallKind::Member => value.member_calls += 1,
            AnalysisCallKind::Construct => value.constructor_calls += 1,
            AnalysisCallKind::Dynamic => value.dynamic_calls += 1,
        }
    }
    value
}

fn validate_state_name(state: NameState, name: Option<&str>) -> Result<()> {
    let named = matches!(state, NameState::Suggested | NameState::Approved);
    if named != name.is_some() {
        bail!("semantic name and state disagree");
    }
    Ok(())
}

fn validate_provenance(value: &NameProvenance) -> Result<()> {
    validate_token(&value.origin)?;
    if let Some(actor) = &value.actor {
        validate_token(actor)?;
    }
    if let Some(digest) = &value.evidence_digest {
        validate_hex(digest)?;
    }
    Ok(())
}

fn validate_token(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        bail!("metadata token contains unsupported characters");
    }
    Ok(())
}

fn operation_id(
    symbol_id: &str,
    state: NameState,
    name: Option<&str>,
    provenance: &NameProvenance,
) -> String {
    let mut hasher = Sha256::new();
    for value in [
        symbol_id.as_bytes(),
        &[state as u8],
        name.unwrap_or("").as_bytes(),
        provenance.origin.as_bytes(),
        provenance.actor.as_deref().unwrap_or("").as_bytes(),
        provenance
            .evidence_digest
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    hex(&hasher.finalize().into())
}

fn analysis_digest(analysis: &Analysis) -> Result<String> {
    Ok(hex(&Sha256::digest(serde_json::to_vec(analysis)?).into()))
}

fn validate_hex(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("expected a lowercase 256-bit hexadecimal value");
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("name is empty, too long, padded, or contains control characters");
    }
    Ok(())
}

fn label(value: impl std::fmt::Debug) -> String {
    format!("{value:?}").to_ascii_lowercase()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("invalid output file name"))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::AnalysisSymbolKind;
    use crate::lineage::{match_analyses, MatcherConfig};
    use crate::parser::JsParser;

    fn analyze(source: &str) -> Analysis {
        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();
        Analysis::from_javascript(source, &tree).unwrap()
    }

    #[test]
    fn redacted_review_is_deterministic_and_contains_no_source_text() {
        let analysis = analyze("function generated(value) { return value + 1; }");
        let first = SemanticNameDocument::from_analysis(&analysis, false).unwrap();
        let second = SemanticNameDocument::from_analysis(&analysis, false).unwrap();
        let json = serde_json::to_string(&first).unwrap();
        assert_eq!(first, second);
        assert!(!json.contains("generated"));
        assert!(!json.contains("return value"));
    }

    #[test]
    fn only_approved_names_propagate() {
        let source = analyze("function descriptive(value) { return value + 1; }");
        let target = analyze("function a(b) { return b + 1; }");
        let lineage = match_analyses(&source, &target, MatcherConfig::default()).unwrap();
        let function = source
            .symbols
            .iter()
            .find(|symbol| symbol.kind == AnalysisSymbolKind::Function)
            .unwrap();
        let mut names = SemanticNameDocument::from_analysis(&source, false).unwrap();
        let provenance = NameProvenance {
            origin: "agent".to_string(),
            actor: None,
            evidence_digest: None,
        };
        names
            .suggest(
                &function.id.to_hex(),
                "increment".to_string(),
                provenance.clone(),
            )
            .unwrap();
        assert!(propagate_approved_names(&names, &lineage, &source, &target)
            .unwrap()
            .symbols
            .iter()
            .all(|entry| entry.semantic_name.is_none()));
        names
            .transition(&function.id.to_hex(), NameState::Approved, provenance)
            .unwrap();
        assert!(propagate_approved_names(&names, &lineage, &source, &target)
            .unwrap()
            .symbols
            .iter()
            .any(|entry| entry.semantic_name.as_deref() == Some("increment")));
    }

    #[test]
    fn event_history_requires_explicit_approval_and_detects_tampering() {
        let analysis = analyze("function a(value) { return value; }");
        let symbol = analysis.symbols[0].id.to_hex();
        let provenance = NameProvenance {
            origin: "agent".to_string(),
            actor: Some("model.v1".to_string()),
            evidence_digest: None,
        };
        let mut names = SemanticNameDocument::from_analysis(&analysis, false).unwrap();
        assert!(names
            .transition(&symbol, NameState::Approved, provenance.clone())
            .is_err());
        names
            .suggest(&symbol, "semantic_label".to_string(), provenance.clone())
            .unwrap();
        names
            .transition(&symbol, NameState::Approved, provenance)
            .unwrap();
        assert_eq!(names.revision, 2);
        assert_eq!(names.events.len(), 2);
        let mut forged = names.clone();
        forged.events[1].previous_state = NameState::Unknown;
        assert!(forged.validate().is_err());
    }

    #[test]
    fn review_document_is_bound_to_exact_analysis_content() {
        let first = analyze("function a(value) { return value; }");
        let second = analyze("function a(value) { return value + 1; }");
        let names = SemanticNameDocument::from_analysis(&first, false).unwrap();
        names.validate_against(&first).unwrap();
        assert!(names.validate_against(&second).is_err());
        let mut forged = names;
        forged.symbols[0].usage.reference_count += 1;
        assert!(forged.validate_against(&first).is_err());
    }
}
