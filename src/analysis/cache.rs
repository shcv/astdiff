//! Isoform positioned persistence for [`super::Analysis`].
//!
//! Files carry an application envelope followed by one canonical positioned
//! message. Opening checks the envelope and payload digest. `verify()` then
//! performs Isoform's mandatory O(payload) structural pass plus the
//! application-level column checks and returns a borrowed view. Keep that view
//! alive for allocation-free O(1) fixed-row and string-location lookup.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use isoform::{
    artifact, encode_owned_positioned, verify, Budgets, CanonicalView, ElementLayout, FieldKind,
    LayoutSet, MessageBuilder, OwnedValue, Schema, Verified,
};
use memmap2::{Mmap, MmapOptions};
use sha2::{Digest, Sha256};

use super::{
    stable_id, Analysis, AnalysisCallKind, AnalysisReferenceRole, AnalysisResolution,
    AnalysisScopeKind, AnalysisSymbolKind, Language, LossCode, StableId, ANALYSIS_PROFILE,
    ANALYSIS_VERSION, JAVASCRIPT_FRONTEND, JAVASCRIPT_FRONTEND_VERSION,
};

const SCHEMA_ARTIFACT: &[u8] = include_bytes!("../../schemas/analysis-v1.isf");
const CACHE_MAGIC: &[u8; 8] = b"ASTIR\0\0\0";
const CACHE_VERSION: u16 = 1;
const CACHE_FLAGS_POSITIONED: u16 = 1;
const HEADER_SIZE: usize = 128;
const ID_SIZE: usize = 32;
const NO_ROW: u32 = u32::MAX;
const MAX_CACHE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CACHE_ROWS: u64 = 20_000_000;

// Generated schema-order field indexes. Their exact layout is pinned by the
// envelope's layout hash and checked-in schema artifact.
mod field {
    pub const FORMAT_VERSION: usize = 0;
    pub const PROFILE: usize = 1;
    pub const PRODUCER: usize = 2;
    pub const PRODUCER_VERSION: usize = 3;
    pub const LANGUAGE: usize = 4;
    pub const FRONTEND: usize = 5;
    pub const FRONTEND_VERSION: usize = 6;
    pub const SOURCE_DIGEST: usize = 7;
    pub const SOURCE_LENGTH: usize = 8;
    pub const NODE_COUNT: usize = 9;
    pub const SCOPE_COUNT: usize = 10;
    pub const SYMBOL_COUNT: usize = 11;
    pub const REFERENCE_COUNT: usize = 12;
    pub const DEF_USE_COUNT: usize = 13;
    pub const CALL_COUNT: usize = 14;
    pub const LOSS_COUNT: usize = 15;
    pub const STRINGS: usize = 16;
    pub const NODE_PARENT: usize = 17;
    pub const NODE_CHILD_ORDINAL: usize = 18;
    pub const NODE_KIND: usize = 19;
    pub const NODE_START_BYTE: usize = 20;
    pub const NODE_END_BYTE: usize = 21;
    pub const NODE_FLAGS: usize = 22;
    pub const SCOPE_PARENT: usize = 23;
    pub const SCOPE_KIND: usize = 24;
    pub const SCOPE_DEPTH: usize = 25;
    pub const SCOPE_START_BYTE: usize = 26;
    pub const SCOPE_END_BYTE: usize = 27;
    pub const SYMBOL_IDS: usize = 28;
    pub const SYMBOL_DECLARATION_NODE: usize = 29;
    pub const SYMBOL_SCOPE: usize = 30;
    pub const SYMBOL_NAME: usize = 31;
    pub const SYMBOL_KIND: usize = 32;
    pub const SYMBOL_REFERENCE_FIRST: usize = 33;
    pub const SYMBOL_REFERENCE_COUNT: usize = 34;
    pub const REFERENCE_IDS: usize = 35;
    pub const REFERENCE_NODE: usize = 36;
    pub const REFERENCE_SCOPE: usize = 37;
    pub const REFERENCE_NAME: usize = 38;
    pub const REFERENCE_ROLE: usize = 39;
    pub const DEF_USE_IDS: usize = 40;
    pub const DEF_USE_REFERENCE: usize = 41;
    pub const DEF_USE_SYMBOL: usize = 42;
    pub const DEF_USE_RESOLUTION: usize = 43;
    pub const CALL_IDS: usize = 44;
    pub const CALL_NODE: usize = 45;
    pub const CALL_CALLEE_REFERENCE: usize = 46;
    pub const CALL_TARGET_SYMBOL: usize = 47;
    pub const CALL_PROPERTY: usize = 48;
    pub const CALL_KIND: usize = 49;
    pub const LOSS_CODE: usize = 50;
    pub const LOSS_MESSAGE: usize = 51;
}

const EXPECTED_FIELDS: [&str; 52] = [
    "format_version",
    "profile",
    "producer",
    "producer_version",
    "language",
    "frontend",
    "frontend_version",
    "source_digest",
    "source_length",
    "node_count",
    "scope_count",
    "symbol_count",
    "reference_count",
    "def_use_count",
    "call_count",
    "loss_count",
    "strings",
    "node_parent",
    "node_child_ordinal",
    "node_kind",
    "node_start_byte",
    "node_end_byte",
    "node_flags",
    "scope_parent",
    "scope_kind",
    "scope_depth",
    "scope_start_byte",
    "scope_end_byte",
    "symbol_ids",
    "symbol_declaration_node",
    "symbol_scope",
    "symbol_name",
    "symbol_kind",
    "symbol_reference_first",
    "symbol_reference_count",
    "reference_ids",
    "reference_node",
    "reference_scope",
    "reference_name",
    "reference_role",
    "def_use_ids",
    "def_use_reference",
    "def_use_symbol",
    "def_use_resolution",
    "call_ids",
    "call_node",
    "call_callee_reference",
    "call_target_symbol",
    "call_property",
    "call_kind",
    "loss_code",
    "loss_message",
];

struct SchemaState {
    schema: Schema,
    layouts: LayoutSet,
    layout_hash: [u8; 32],
}

static SCHEMA: OnceLock<std::result::Result<SchemaState, String>> = OnceLock::new();

fn schema_state() -> Result<&'static SchemaState> {
    SCHEMA
        .get_or_init(|| {
            let schema = artifact::decode(SCHEMA_ARTIFACT).map_err(|error| error.to_string())?;
            let message = schema
                .message("Analysis")
                .ok_or_else(|| "embedded schema has no Analysis message".to_string())?;
            let actual_fields = message
                .fields()
                .iter()
                .map(|field| field.name())
                .collect::<Vec<_>>();
            if actual_fields != EXPECTED_FIELDS {
                return Err(
                    "embedded Analysis schema does not match generated field indexes".to_string(),
                );
            }
            let layout_hash =
                artifact::layout_hash(&schema, "Analysis").map_err(|error| error.to_string())?;
            let layouts = LayoutSet::compile(&schema).map_err(|error| format!("{error:?}"))?;
            validate_layout_contract(&layouts)?;
            Ok(SchemaState {
                schema,
                layouts,
                layout_hash,
            })
        })
        .as_ref()
        .map_err(|error| anyhow!("invalid embedded analysis schema: {error}"))
}

fn validate_layout_contract(layouts: &LayoutSet) -> std::result::Result<(), String> {
    let region = layouts
        .region("Analysis")
        .ok_or_else(|| "embedded schema has no Analysis layout".to_string())?;
    if region.fields.len() != EXPECTED_FIELDS.len()
        || region.fields.iter().any(|field| field.optional)
    {
        return Err("embedded Analysis layout has unexpected fields or optionality".to_string());
    }
    let check_fixed = |index: usize, width: u8| match region.fields[index].kind {
        FieldKind::Fixed { width: actual } if actual == width => Ok(()),
        _ => Err(format!(
            "Analysis field {} has an unexpected fixed layout",
            EXPECTED_FIELDS[index]
        )),
    };
    let check_repetition = |index: usize, width: u8| match &region.fields[index].kind {
        FieldKind::Repetition {
            element: ElementLayout::Fixed { width: actual },
            element_offset_width: None,
            ..
        } if *actual == width => Ok(()),
        _ => Err(format!(
            "Analysis field {} has an unexpected repetition layout",
            EXPECTED_FIELDS[index]
        )),
    };
    for index in [0, 1, 2, 3, 5, 6, 9, 10, 11, 12, 13, 14, 15] {
        check_fixed(index, 4)?;
    }
    check_fixed(field::LANGUAGE, 1)?;
    check_fixed(field::SOURCE_LENGTH, 8)?;
    for index in [
        field::SOURCE_DIGEST,
        field::SYMBOL_IDS,
        field::REFERENCE_IDS,
        field::DEF_USE_IDS,
        field::CALL_IDS,
    ] {
        if !matches!(region.fields[index].kind, FieldKind::Blob { .. }) {
            return Err(format!(
                "Analysis field {} has an unexpected blob layout",
                EXPECTED_FIELDS[index]
            ));
        }
    }
    if !matches!(
        &region.fields[field::STRINGS].kind,
        FieldKind::Repetition {
            element: ElementLayout::Blob {
                size_prefix: 4,
                message: None,
            },
            element_offset_width: Some(4),
            ..
        }
    ) {
        return Err("Analysis strings field lacks its required indexed layout".to_string());
    }
    for index in [
        field::NODE_PARENT,
        field::NODE_CHILD_ORDINAL,
        field::NODE_KIND,
        field::NODE_START_BYTE,
        field::NODE_END_BYTE,
        field::SCOPE_PARENT,
        field::SCOPE_DEPTH,
        field::SCOPE_START_BYTE,
        field::SCOPE_END_BYTE,
        field::SYMBOL_DECLARATION_NODE,
        field::SYMBOL_SCOPE,
        field::SYMBOL_NAME,
        field::SYMBOL_REFERENCE_FIRST,
        field::SYMBOL_REFERENCE_COUNT,
        field::REFERENCE_NODE,
        field::REFERENCE_SCOPE,
        field::REFERENCE_NAME,
        field::DEF_USE_REFERENCE,
        field::DEF_USE_SYMBOL,
        field::CALL_NODE,
        field::CALL_CALLEE_REFERENCE,
        field::CALL_TARGET_SYMBOL,
        field::CALL_PROPERTY,
        field::LOSS_MESSAGE,
    ] {
        check_repetition(index, 4)?;
    }
    for index in [
        field::NODE_FLAGS,
        field::SCOPE_KIND,
        field::SYMBOL_KIND,
        field::REFERENCE_ROLE,
        field::DEF_USE_RESOLUTION,
        field::CALL_KIND,
    ] {
        check_repetition(index, 1)?;
    }
    check_repetition(field::LOSS_CODE, 2)?;
    Ok(())
}

fn cache_budgets(payload_len: usize) -> Budgets {
    Budgets::default()
        .with_max_message_size(payload_len)
        .with_max_count(MAX_CACHE_ROWS)
}

impl Analysis {
    /// Encode this analysis as a canonical Isoform positioned payload.
    pub fn encode_positioned(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let state = schema_state()?;
        let mut builder = MessageBuilder::new(&state.schema, "Analysis")?;

        let profile = self.string_index(&self.profile)?;
        let producer = self.string_index(&self.producer)?;
        let producer_version = self.string_index(&self.producer_version)?;
        let frontend = self.string_index(&self.frontend)?;
        let frontend_version = self.string_index(&self.frontend_version)?;

        builder
            .set_at(field::FORMAT_VERSION, fixed_u32(self.version))?
            .set_at(field::PROFILE, fixed_u32(profile))?
            .set_at(field::PRODUCER, fixed_u32(producer))?
            .set_at(field::PRODUCER_VERSION, fixed_u32(producer_version))?
            .set_at(field::LANGUAGE, fixed_u8(self.language as u8))?
            .set_at(field::FRONTEND, fixed_u32(frontend))?
            .set_at(field::FRONTEND_VERSION, fixed_u32(frontend_version))?
            .set_at(
                field::SOURCE_DIGEST,
                OwnedValue::Blob(self.source_digest.to_vec()),
            )?
            .set_at(field::SOURCE_LENGTH, fixed_u64(self.source_length))?
            .set_at(field::NODE_COUNT, fixed_count(self.nodes.len())?)?
            .set_at(field::SCOPE_COUNT, fixed_count(self.scopes.len())?)?
            .set_at(field::SYMBOL_COUNT, fixed_count(self.symbols.len())?)?
            .set_at(field::REFERENCE_COUNT, fixed_count(self.references.len())?)?
            .set_at(field::DEF_USE_COUNT, fixed_count(self.def_uses.len())?)?
            .set_at(field::CALL_COUNT, fixed_count(self.calls.len())?)?
            .set_at(field::LOSS_COUNT, fixed_count(self.losses.len())?)?
            .set_at(
                field::STRINGS,
                OwnedValue::Repetition(
                    self.strings
                        .iter()
                        .map(|value| OwnedValue::Blob(value.as_bytes().to_vec()))
                        .collect(),
                ),
            )?
            .set_at(
                field::NODE_PARENT,
                repetition_u32(self.nodes.iter().map(|node| node.parent.unwrap_or(NO_ROW))),
            )?
            .set_at(
                field::NODE_CHILD_ORDINAL,
                repetition_u32(self.nodes.iter().map(|node| node.child_ordinal)),
            )?
            .set_at(
                field::NODE_KIND,
                repetition_u32(self.nodes.iter().map(|node| node.kind)),
            )?
            .set_at(
                field::NODE_START_BYTE,
                repetition_u32_from_u64(self.nodes.iter().map(|node| node.start_byte))?,
            )?
            .set_at(
                field::NODE_END_BYTE,
                repetition_u32_from_u64(self.nodes.iter().map(|node| node.end_byte))?,
            )?
            .set_at(
                field::NODE_FLAGS,
                repetition_u8(self.nodes.iter().map(|node| node.flags)),
            )?
            .set_at(
                field::SCOPE_PARENT,
                repetition_u32(
                    self.scopes
                        .iter()
                        .map(|scope| scope.parent.unwrap_or(NO_ROW)),
                ),
            )?
            .set_at(
                field::SCOPE_KIND,
                repetition_u8(self.scopes.iter().map(|scope| scope.kind as u8)),
            )?
            .set_at(
                field::SCOPE_DEPTH,
                repetition_u32(self.scopes.iter().map(|scope| scope.depth)),
            )?
            .set_at(
                field::SCOPE_START_BYTE,
                repetition_u32_from_u64(self.scopes.iter().map(|scope| scope.start_byte))?,
            )?
            .set_at(
                field::SCOPE_END_BYTE,
                repetition_u32_from_u64(self.scopes.iter().map(|scope| scope.end_byte))?,
            )?
            .set_at(
                field::SYMBOL_IDS,
                OwnedValue::Blob(flatten_ids(self.symbols.iter().map(|symbol| symbol.id))),
            )?
            .set_at(
                field::SYMBOL_DECLARATION_NODE,
                repetition_u32(self.symbols.iter().map(|symbol| symbol.declaration_node)),
            )?
            .set_at(
                field::SYMBOL_SCOPE,
                repetition_u32(self.symbols.iter().map(|symbol| symbol.scope)),
            )?
            .set_at(
                field::SYMBOL_NAME,
                repetition_u32(self.symbols.iter().map(|symbol| symbol.name)),
            )?
            .set_at(
                field::SYMBOL_KIND,
                repetition_u8(self.symbols.iter().map(|symbol| symbol.kind as u8)),
            )?
            .set_at(
                field::SYMBOL_REFERENCE_FIRST,
                repetition_u32(self.symbols.iter().map(|symbol| symbol.reference_first)),
            )?
            .set_at(
                field::SYMBOL_REFERENCE_COUNT,
                repetition_u32(self.symbols.iter().map(|symbol| symbol.reference_count)),
            )?
            .set_at(
                field::REFERENCE_IDS,
                OwnedValue::Blob(flatten_ids(
                    self.references.iter().map(|reference| reference.id),
                )),
            )?
            .set_at(
                field::REFERENCE_NODE,
                repetition_u32(self.references.iter().map(|reference| reference.node)),
            )?
            .set_at(
                field::REFERENCE_SCOPE,
                repetition_u32(self.references.iter().map(|reference| reference.scope)),
            )?
            .set_at(
                field::REFERENCE_NAME,
                repetition_u32(self.references.iter().map(|reference| reference.name)),
            )?
            .set_at(
                field::REFERENCE_ROLE,
                repetition_u8(self.references.iter().map(|reference| reference.role as u8)),
            )?
            .set_at(
                field::DEF_USE_IDS,
                OwnedValue::Blob(flatten_ids(self.def_uses.iter().map(|edge| edge.id))),
            )?
            .set_at(
                field::DEF_USE_REFERENCE,
                repetition_u32(self.def_uses.iter().map(|edge| edge.reference)),
            )?
            .set_at(
                field::DEF_USE_SYMBOL,
                repetition_u32(
                    self.def_uses
                        .iter()
                        .map(|edge| edge.symbol.unwrap_or(NO_ROW)),
                ),
            )?
            .set_at(
                field::DEF_USE_RESOLUTION,
                repetition_u8(self.def_uses.iter().map(|edge| edge.resolution as u8)),
            )?
            .set_at(
                field::CALL_IDS,
                OwnedValue::Blob(flatten_ids(self.calls.iter().map(|call| call.id))),
            )?
            .set_at(
                field::CALL_NODE,
                repetition_u32(self.calls.iter().map(|call| call.node)),
            )?
            .set_at(
                field::CALL_CALLEE_REFERENCE,
                repetition_u32(
                    self.calls
                        .iter()
                        .map(|call| call.callee_reference.unwrap_or(NO_ROW)),
                ),
            )?
            .set_at(
                field::CALL_TARGET_SYMBOL,
                repetition_u32(
                    self.calls
                        .iter()
                        .map(|call| call.target_symbol.unwrap_or(NO_ROW)),
                ),
            )?
            .set_at(
                field::CALL_PROPERTY,
                repetition_u32(
                    self.calls
                        .iter()
                        .map(|call| call.property.unwrap_or(NO_ROW)),
                ),
            )?
            .set_at(
                field::CALL_KIND,
                repetition_u8(self.calls.iter().map(|call| call.kind as u8)),
            )?
            .set_at(
                field::LOSS_CODE,
                repetition_u16(self.losses.iter().map(|loss| loss.code as u16)),
            )?
            .set_at(
                field::LOSS_MESSAGE,
                repetition_u32(self.losses.iter().map(|loss| loss.message)),
            )?;

        let message = builder.build()?;
        encode_owned_positioned(
            &state.schema,
            &state.layouts,
            &message,
            cache_budgets(MAX_CACHE_BYTES as usize),
        )
        .map_err(|error| anyhow!("failed to encode analysis: {error:?}"))
    }

    /// Write an integrity-protected positioned analysis file.
    pub fn write_positioned(&self, path: &Path) -> Result<()> {
        let payload = self.encode_positioned()?;
        let state = schema_state()?;
        let payload_len = u64::try_from(payload.len())?;
        if payload_len > MAX_CACHE_BYTES {
            bail!("analysis payload exceeds the 4 GiB cache limit");
        }
        let payload_digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut header = [0u8; HEADER_SIZE];
        header[0..8].copy_from_slice(CACHE_MAGIC);
        header[8..10].copy_from_slice(&CACHE_VERSION.to_le_bytes());
        header[10..12].copy_from_slice(&CACHE_FLAGS_POSITIONED.to_le_bytes());
        header[12..16].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        header[16..48].copy_from_slice(&state.layout_hash);
        header[48..80].copy_from_slice(&self.source_digest);
        header[80..112].copy_from_slice(&payload_digest);
        header[112..120].copy_from_slice(&payload_len.to_le_bytes());

        write_atomic(path, &header, &payload)
    }

    fn string_index(&self, value: &str) -> Result<u32> {
        self.strings
            .iter()
            .position(|candidate| candidate == value)
            .map(u32::try_from)
            .transpose()?
            .ok_or_else(|| anyhow!("metadata string '{value}' is missing from the string table"))
    }
}

/// An opened analysis file. The memory map owns the bytes; no borrowed field
/// access is possible until [`Self::verify`] establishes structural and
/// semantic trust.
#[derive(Debug)]
pub struct MappedAnalysis {
    mmap: Mmap,
    payload: Range<usize>,
    source_digest: [u8; 32],
}

impl MappedAnalysis {
    /// Map and validate the fixed envelope and whole-payload digest.
    ///
    /// The recorded source digest is metadata until a caller compares it or
    /// uses [`Self::open_for_source`].
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)
            .with_context(|| format!("failed to open analysis file {}", path.display()))?;
        let length = usize::try_from(file.metadata()?.len())?;
        if length < HEADER_SIZE {
            bail!("analysis file is shorter than its fixed header");
        }
        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header)?;
        validate_header(&header, length)?;

        // SAFETY: the map remains owned by this value and every access is
        // bounds-checked. Callers must not concurrently truncate or rewrite the
        // mapped path, the same external invariant required by any file mmap.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let payload = HEADER_SIZE..length;
        let expected_digest = array::<32>(&header[80..112]);
        let actual_digest: [u8; 32] = Sha256::digest(&mmap[payload.clone()]).into();
        if expected_digest != actual_digest {
            bail!("analysis payload digest mismatch");
        }
        Ok(Self {
            mmap,
            payload,
            source_digest: array::<32>(&header[48..80]),
        })
    }

    /// Open a cache and bind it to the exact source bytes supplied by the
    /// caller before any payload view can be verified.
    pub fn open_for_source(path: &Path, source: &[u8]) -> Result<Self> {
        let mapped = Self::open(path)?;
        let actual: [u8; 32] = Sha256::digest(source).into();
        if actual != mapped.source_digest {
            bail!("analysis source digest mismatch");
        }
        Ok(mapped)
    }

    /// Perform the mandatory full Isoform verification and application-level
    /// column validation, returning the O(1)-access borrowed view.
    pub fn verify(&self) -> Result<AnalysisCacheView<'_>> {
        let state = schema_state()?;
        let payload = &self.mmap[self.payload.clone()];
        let verified = verify(
            &state.layouts,
            "Analysis",
            payload,
            cache_budgets(payload.len()),
        )
        .map_err(|error| anyhow!("invalid positioned analysis: {error:?}"))?;
        let Verified::Canonical(root) = verified else {
            bail!("bare analysis schema unexpectedly produced a bounded view");
        };
        AnalysisCacheView::new(root, self.source_digest)
    }
}

/// Borrowed, semantically verified access to one mapped analysis.
pub struct AnalysisCacheView<'a> {
    root: CanonicalView<'static, 'a>,
    node_count: usize,
    scope_count: usize,
    symbol_count: usize,
    reference_count: usize,
    def_use_count: usize,
    call_count: usize,
    loss_count: usize,
    source_length: u64,
    source_digest: [u8; 32],
}

impl<'a> AnalysisCacheView<'a> {
    fn new(root: CanonicalView<'static, 'a>, envelope_source_digest: [u8; 32]) -> Result<Self> {
        let version = read_fixed_u32(&root, field::FORMAT_VERSION)?;
        if version != ANALYSIS_VERSION {
            bail!("unsupported analysis format version {version}");
        }
        let language = read_fixed_u8(&root, field::LANGUAGE)?;
        if language != Language::JavaScript as u8 {
            bail!("unsupported analysis language code {language}");
        }
        let source_digest = exact_blob::<32>(&root, field::SOURCE_DIGEST, "source_digest")?;
        if source_digest != envelope_source_digest {
            bail!("analysis envelope and payload source digests disagree");
        }
        let source_length = read_fixed_u64(&root, field::SOURCE_LENGTH)?;
        if source_length > u64::from(u32::MAX) {
            bail!("analysis v1 supports source artifacts smaller than 4 GiB");
        }
        let node_count = usize::try_from(read_fixed_u32(&root, field::NODE_COUNT)?)?;
        let scope_count = usize::try_from(read_fixed_u32(&root, field::SCOPE_COUNT)?)?;
        let symbol_count = usize::try_from(read_fixed_u32(&root, field::SYMBOL_COUNT)?)?;
        let reference_count = usize::try_from(read_fixed_u32(&root, field::REFERENCE_COUNT)?)?;
        let def_use_count = usize::try_from(read_fixed_u32(&root, field::DEF_USE_COUNT)?)?;
        let call_count = usize::try_from(read_fixed_u32(&root, field::CALL_COUNT)?)?;
        let loss_count = usize::try_from(read_fixed_u32(&root, field::LOSS_COUNT)?)?;
        if node_count == 0 || scope_count == 0 {
            bail!("analysis requires a syntax root and global scope");
        }

        let strings = repetition(&root, field::STRINGS, "strings")?;
        if !strings.has_materialized_index() {
            bail!("analysis string table lacks its materialized offset index");
        }
        for index in 0..strings.count() {
            let value = strings
                .blob(index)
                .ok_or_else(|| anyhow!("missing string row {index}"))?;
            std::str::from_utf8(value)
                .with_context(|| format!("string row {index} is not valid UTF-8"))?;
        }

        validate_metadata_string(&root, field::PROFILE, strings.count(), "profile")?;
        validate_metadata_string(&root, field::PRODUCER, strings.count(), "producer")?;
        validate_metadata_string(
            &root,
            field::PRODUCER_VERSION,
            strings.count(),
            "producer_version",
        )?;
        validate_metadata_string(&root, field::FRONTEND, strings.count(), "frontend")?;
        validate_metadata_string(
            &root,
            field::FRONTEND_VERSION,
            strings.count(),
            "frontend_version",
        )?;
        for (field, expected, label) in [
            (field::PROFILE, ANALYSIS_PROFILE, "profile"),
            (field::FRONTEND, JAVASCRIPT_FRONTEND, "frontend"),
            (
                field::FRONTEND_VERSION,
                JAVASCRIPT_FRONTEND_VERSION,
                "frontend_version",
            ),
        ] {
            let row = read_fixed_u32(&root, field)? as usize;
            let actual = strings
                .blob(row)
                .and_then(|value| std::str::from_utf8(value).ok());
            if actual != Some(expected) {
                bail!("unsupported analysis {label}");
            }
        }

        for column in [
            field::NODE_PARENT,
            field::NODE_CHILD_ORDINAL,
            field::NODE_KIND,
            field::NODE_START_BYTE,
            field::NODE_END_BYTE,
            field::NODE_FLAGS,
        ] {
            validate_count(&root, column, node_count, "node")?;
        }
        let mut next_child_ordinal = vec![0u32; node_count];
        let mut open_nodes = Vec::new();
        for index in 0..node_count {
            let parent = read_rep_u32(&root, field::NODE_PARENT, index)?;
            if parent != NO_ROW && parent as usize >= index {
                bail!("node {index} has an invalid parent row");
            }
            if index > 0 {
                while open_nodes.last().copied() != optional_row(parent) {
                    if open_nodes.pop().is_none() {
                        bail!("node {index} is not in syntax-tree pre-order");
                    }
                }
            }
            let child_ordinal = read_rep_u32(&root, field::NODE_CHILD_ORDINAL, index)?;
            if parent == NO_ROW {
                if index != 0 || child_ordinal != 0 {
                    bail!("node {index} has an invalid root ordinal");
                }
            } else if child_ordinal != next_child_ordinal[parent as usize] {
                bail!("node {index} has an invalid child ordinal");
            } else {
                next_child_ordinal[parent as usize] = next_child_ordinal[parent as usize]
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("node {parent} has too many children"))?;
            }
            let kind = read_rep_u32(&root, field::NODE_KIND, index)?;
            if kind as usize >= strings.count() {
                bail!("node {index} has an invalid kind string");
            }
            let start = u64::from(read_rep_u32(&root, field::NODE_START_BYTE, index)?);
            let end = u64::from(read_rep_u32(&root, field::NODE_END_BYTE, index)?);
            if start > end || end > source_length {
                bail!("node {index} has an invalid source span");
            }
            if index == 0 {
                let root_kind = strings
                    .blob(kind as usize)
                    .and_then(|value| std::str::from_utf8(value).ok());
                if start != 0 || end != source_length || root_kind != Some("program") {
                    bail!("analysis has an invalid JavaScript syntax root");
                }
            }
            if parent != NO_ROW {
                let parent_start = u64::from(read_rep_u32(
                    &root,
                    field::NODE_START_BYTE,
                    parent as usize,
                )?);
                let parent_end =
                    u64::from(read_rep_u32(&root, field::NODE_END_BYTE, parent as usize)?);
                if start < parent_start || end > parent_end {
                    bail!("node {index} is outside its parent span");
                }
            }
            if read_rep_u8(&root, field::NODE_FLAGS, index)? & !0x0f != 0 {
                bail!("node {index} has unknown flags");
            }
            open_nodes.push(u32::try_from(index)?);
        }

        for column in [
            field::SCOPE_PARENT,
            field::SCOPE_KIND,
            field::SCOPE_DEPTH,
            field::SCOPE_START_BYTE,
            field::SCOPE_END_BYTE,
        ] {
            validate_count(&root, column, scope_count, "scope")?;
        }
        let mut seen_scope_ids = HashSet::with_capacity(scope_count);
        for index in 0..scope_count {
            let parent = read_rep_u32(&root, field::SCOPE_PARENT, index)?;
            if parent != NO_ROW && parent as usize >= index {
                bail!("scope {index} has an invalid parent row");
            }
            let kind = AnalysisScopeKind::from_code(read_rep_u8(&root, field::SCOPE_KIND, index)?)?;
            let depth = read_rep_u32(&root, field::SCOPE_DEPTH, index)?;
            let start = u64::from(read_rep_u32(&root, field::SCOPE_START_BYTE, index)?);
            let end = u64::from(read_rep_u32(&root, field::SCOPE_END_BYTE, index)?);
            if start > end || end > source_length {
                bail!("scope {index} has an invalid source span");
            }
            if index == 0 {
                if parent != NO_ROW
                    || kind != AnalysisScopeKind::Global
                    || depth != 0
                    || start != 0
                    || end != source_length
                {
                    bail!("analysis has an invalid global scope");
                }
            } else {
                if parent == NO_ROW {
                    bail!("scope {index} has no parent");
                }
                let parent_depth = read_rep_u32(&root, field::SCOPE_DEPTH, parent as usize)?;
                let parent_start = u64::from(read_rep_u32(
                    &root,
                    field::SCOPE_START_BYTE,
                    parent as usize,
                )?);
                let parent_end =
                    u64::from(read_rep_u32(&root, field::SCOPE_END_BYTE, parent as usize)?);
                if Some(depth) != parent_depth.checked_add(1)
                    || start < parent_start
                    || end > parent_end
                {
                    bail!("scope {index} is inconsistent with its parent");
                }
            }
            let parent_row = parent;
            let expected_scope_id = stable_id(
                b"astdiff/scope/v1",
                &[
                    &parent_row.to_le_bytes(),
                    &[kind as u8],
                    &depth.to_le_bytes(),
                    &start.to_le_bytes(),
                    &end.to_le_bytes(),
                ],
            );
            if !seen_scope_ids.insert(expected_scope_id) {
                bail!("scope {index} duplicates another scope identity");
            }
        }

        validate_id_blob(&root, field::SYMBOL_IDS, symbol_count, "symbol_ids")?;
        for column in [
            field::SYMBOL_DECLARATION_NODE,
            field::SYMBOL_SCOPE,
            field::SYMBOL_NAME,
            field::SYMBOL_KIND,
            field::SYMBOL_REFERENCE_FIRST,
            field::SYMBOL_REFERENCE_COUNT,
        ] {
            validate_count(&root, column, symbol_count, "symbol")?;
        }
        let mut next_symbol_reference = 0usize;
        let mut seen_symbol_nodes = vec![false; node_count];
        for index in 0..symbol_count {
            if read_rep_u32(&root, field::SYMBOL_DECLARATION_NODE, index)? as usize >= node_count
                || read_rep_u32(&root, field::SYMBOL_SCOPE, index)? as usize >= scope_count
                || read_rep_u32(&root, field::SYMBOL_NAME, index)? as usize >= strings.count()
            {
                bail!("symbol {index} contains an invalid row reference");
            }
            let declaration = read_rep_u32(&root, field::SYMBOL_DECLARATION_NODE, index)? as usize;
            if std::mem::replace(&mut seen_symbol_nodes[declaration], true) {
                bail!("symbol {index} reuses another symbol's declaration node");
            }
            let scope = read_rep_u32(&root, field::SYMBOL_SCOPE, index)? as usize;
            let node_start = read_rep_u32(&root, field::NODE_START_BYTE, declaration)?;
            let node_end = read_rep_u32(&root, field::NODE_END_BYTE, declaration)?;
            let scope_start = read_rep_u32(&root, field::SCOPE_START_BYTE, scope)?;
            let scope_end = read_rep_u32(&root, field::SCOPE_END_BYTE, scope)?;
            if node_start < scope_start || node_end > scope_end {
                bail!("symbol {index} is outside its declared scope");
            }
            AnalysisSymbolKind::from_code(read_rep_u8(&root, field::SYMBOL_KIND, index)?)?;
            let first = read_rep_u32(&root, field::SYMBOL_REFERENCE_FIRST, index)?;
            let count = read_rep_u32(&root, field::SYMBOL_REFERENCE_COUNT, index)?;
            let Some(end) = first.checked_add(count) else {
                bail!("symbol {index} reference range overflows");
            };
            if first as usize != next_symbol_reference || end as usize > reference_count {
                bail!("symbol {index} has an invalid reference range");
            }
            next_symbol_reference = end as usize;
        }

        validate_id_blob(
            &root,
            field::REFERENCE_IDS,
            reference_count,
            "reference_ids",
        )?;
        for column in [
            field::REFERENCE_NODE,
            field::REFERENCE_SCOPE,
            field::REFERENCE_NAME,
            field::REFERENCE_ROLE,
        ] {
            validate_count(&root, column, reference_count, "reference")?;
        }
        let mut seen_reference_nodes = vec![false; node_count];
        for index in 0..reference_count {
            if read_rep_u32(&root, field::REFERENCE_NODE, index)? as usize >= node_count
                || read_rep_u32(&root, field::REFERENCE_SCOPE, index)? as usize >= scope_count
                || read_rep_u32(&root, field::REFERENCE_NAME, index)? as usize >= strings.count()
            {
                bail!("reference {index} contains an invalid row reference");
            }
            let node = read_rep_u32(&root, field::REFERENCE_NODE, index)? as usize;
            if std::mem::replace(&mut seen_reference_nodes[node], true) {
                bail!("reference {index} reuses another reference node");
            }
            let scope = read_rep_u32(&root, field::REFERENCE_SCOPE, index)? as usize;
            let node_start = read_rep_u32(&root, field::NODE_START_BYTE, node)?;
            let node_end = read_rep_u32(&root, field::NODE_END_BYTE, node)?;
            let scope_start = read_rep_u32(&root, field::SCOPE_START_BYTE, scope)?;
            let scope_end = read_rep_u32(&root, field::SCOPE_END_BYTE, scope)?;
            if node_start < scope_start || node_end > scope_end {
                bail!("reference {index} is outside its recorded scope");
            }
            AnalysisReferenceRole::from_code(read_rep_u8(&root, field::REFERENCE_ROLE, index)?)?;
        }

        if def_use_count != reference_count {
            bail!("reference and def-use row counts differ");
        }
        validate_id_blob(&root, field::DEF_USE_IDS, def_use_count, "def_use_ids")?;
        for column in [
            field::DEF_USE_REFERENCE,
            field::DEF_USE_SYMBOL,
            field::DEF_USE_RESOLUTION,
        ] {
            validate_count(&root, column, def_use_count, "def-use")?;
        }
        for index in 0..def_use_count {
            let reference = read_rep_u32(&root, field::DEF_USE_REFERENCE, index)?;
            let symbol = read_rep_u32(&root, field::DEF_USE_SYMBOL, index)?;
            let resolution = AnalysisResolution::from_code(read_rep_u8(
                &root,
                field::DEF_USE_RESOLUTION,
                index,
            )?)?;
            if reference as usize != index
                || (symbol != NO_ROW && symbol as usize >= symbol_count)
                || (resolution == AnalysisResolution::Resolved) != (symbol != NO_ROW)
            {
                bail!("def-use {index} contains an invalid resolution");
            }
        }
        for symbol in 0..symbol_count {
            let first = read_rep_u32(&root, field::SYMBOL_REFERENCE_FIRST, symbol)? as usize;
            let count = read_rep_u32(&root, field::SYMBOL_REFERENCE_COUNT, symbol)? as usize;
            let end = first
                .checked_add(count)
                .ok_or_else(|| anyhow!("symbol {symbol} reference range overflows"))?;
            for reference in first..end {
                if read_rep_u32(&root, field::DEF_USE_SYMBOL, reference)? != symbol as u32 {
                    bail!("symbol {symbol} reference range contains another symbol");
                }
            }
        }
        for reference in next_symbol_reference..reference_count {
            if read_rep_u32(&root, field::DEF_USE_SYMBOL, reference)? != NO_ROW {
                bail!("resolved def-use row is outside its symbol reference range");
            }
        }

        validate_id_blob(&root, field::CALL_IDS, call_count, "call_ids")?;
        for column in [
            field::CALL_NODE,
            field::CALL_CALLEE_REFERENCE,
            field::CALL_TARGET_SYMBOL,
            field::CALL_PROPERTY,
            field::CALL_KIND,
        ] {
            validate_count(&root, column, call_count, "call")?;
        }
        let mut seen_call_nodes = vec![false; node_count];
        for index in 0..call_count {
            let callee = read_rep_u32(&root, field::CALL_CALLEE_REFERENCE, index)?;
            let target = read_rep_u32(&root, field::CALL_TARGET_SYMBOL, index)?;
            let property = read_rep_u32(&root, field::CALL_PROPERTY, index)?;
            if read_rep_u32(&root, field::CALL_NODE, index)? as usize >= node_count
                || (callee != NO_ROW && callee as usize >= reference_count)
                || (target != NO_ROW && target as usize >= symbol_count)
                || (property != NO_ROW && property as usize >= strings.count())
            {
                bail!("call {index} contains an invalid row reference");
            }
            let kind = AnalysisCallKind::from_code(read_rep_u8(&root, field::CALL_KIND, index)?)?;
            let call_node = read_rep_u32(&root, field::CALL_NODE, index)? as usize;
            if std::mem::replace(&mut seen_call_nodes[call_node], true) {
                bail!("call {index} reuses another call node");
            }
            let call_kind_row = read_rep_u32(&root, field::NODE_KIND, call_node)? as usize;
            let call_node_kind = strings
                .blob(call_kind_row)
                .and_then(|value| std::str::from_utf8(value).ok())
                .ok_or_else(|| anyhow!("call {index} has an unreadable node kind"))?;
            let valid_node_kind = match kind {
                AnalysisCallKind::Direct => call_node_kind == "call_expression",
                AnalysisCallKind::Construct => call_node_kind == "new_expression",
                AnalysisCallKind::Member | AnalysisCallKind::Dynamic => {
                    matches!(call_node_kind, "call_expression" | "new_expression")
                }
            };
            if !valid_node_kind {
                bail!("call {index} has an invalid syntax node kind");
            }
            if callee != NO_ROW {
                let callee_node =
                    read_rep_u32(&root, field::REFERENCE_NODE, callee as usize)? as usize;
                let call_start = read_rep_u32(&root, field::NODE_START_BYTE, call_node)?;
                let call_end = read_rep_u32(&root, field::NODE_END_BYTE, call_node)?;
                let callee_start = read_rep_u32(&root, field::NODE_START_BYTE, callee_node)?;
                let callee_end = read_rep_u32(&root, field::NODE_END_BYTE, callee_node)?;
                if callee_start < call_start || callee_end > call_end {
                    bail!("call {index} callee is outside the call expression");
                }
            }
            match kind {
                AnalysisCallKind::Direct | AnalysisCallKind::Construct => {
                    if callee == NO_ROW || property != NO_ROW {
                        bail!("call {index} has inconsistent direct-call relationships");
                    }
                    let callee_symbol =
                        read_rep_u32(&root, field::DEF_USE_SYMBOL, callee as usize)?;
                    if callee_symbol != target {
                        bail!("call {index} target does not match its callee def-use");
                    }
                    let role = AnalysisReferenceRole::from_code(read_rep_u8(
                        &root,
                        field::REFERENCE_ROLE,
                        callee as usize,
                    )?)?;
                    let expected_role = if kind == AnalysisCallKind::Construct {
                        AnalysisReferenceRole::Construct
                    } else {
                        AnalysisReferenceRole::Call
                    };
                    if role != expected_role {
                        bail!("call {index} has an invalid callee role");
                    }
                }
                AnalysisCallKind::Member => {
                    if property == NO_ROW || target != NO_ROW {
                        bail!("call {index} has inconsistent member-call relationships");
                    }
                }
                AnalysisCallKind::Dynamic => {
                    if callee != NO_ROW || target != NO_ROW || property != NO_ROW {
                        bail!("call {index} has inconsistent dynamic-call relationships");
                    }
                }
            }
        }

        for column in [field::LOSS_CODE, field::LOSS_MESSAGE] {
            validate_count(&root, column, loss_count, "loss")?;
        }
        for index in 0..loss_count {
            LossCode::from_code(read_rep_u16(&root, field::LOSS_CODE, index)?)?;
            if read_rep_u32(&root, field::LOSS_MESSAGE, index)? as usize >= strings.count() {
                bail!("loss {index} has an invalid message string");
            }
        }

        let view = Self {
            root,
            node_count,
            scope_count,
            symbol_count,
            reference_count,
            def_use_count,
            call_count,
            loss_count,
            source_length,
            source_digest,
        };
        if view.profile() != Some(ANALYSIS_PROFILE) {
            bail!("unsupported analysis profile");
        }
        for index in 0..view.symbol_count {
            let symbol = view
                .symbol(index)
                .ok_or_else(|| anyhow!("symbol {index} cannot be read after verification"))?;
            let node = view
                .node(symbol.declaration_node as usize)
                .ok_or_else(|| anyhow!("symbol {index} references an unreadable node"))?;
            let expected_id = stable_id(b"astdiff/symbol/v1", &[&node.id.0, &[symbol.kind as u8]]);
            if symbol.id != expected_id {
                bail!("symbol {index} has an invalid stable ID");
            }
        }
        view.validate_relation_ids()?;
        Ok(view)
    }

    pub fn source_digest(&self) -> [u8; 32] {
        self.source_digest
    }

    pub fn source_length(&self) -> u64 {
        self.source_length
    }

    pub fn node_count(&self) -> usize {
        self.node_count
    }

    pub fn scope_count(&self) -> usize {
        self.scope_count
    }

    pub fn symbol_count(&self) -> usize {
        self.symbol_count
    }

    pub fn reference_count(&self) -> usize {
        self.reference_count
    }

    pub fn def_use_count(&self) -> usize {
        self.def_use_count
    }

    pub fn call_count(&self) -> usize {
        self.call_count
    }

    pub fn loss_count(&self) -> usize {
        self.loss_count
    }

    pub fn profile(&self) -> Option<&'a str> {
        self.metadata_string(field::PROFILE)
    }

    pub fn producer(&self) -> Option<&'a str> {
        self.metadata_string(field::PRODUCER)
    }

    pub fn frontend(&self) -> Option<&'a str> {
        self.metadata_string(field::FRONTEND)
    }

    /// O(1) indexed UTF-8 lookup through Isoform's persisted offset table.
    pub fn string(&self, index: usize) -> Option<&'a str> {
        let bytes = self.root.repetition_at(field::STRINGS)?.blob(index)?;
        std::str::from_utf8(bytes).ok()
    }

    pub fn node(&self, index: usize) -> Option<CachedNode<'a>> {
        if index >= self.node_count {
            return None;
        }
        let parent_row = read_rep_u32(&self.root, field::NODE_PARENT, index).ok()?;
        let child_ordinal = read_rep_u32(&self.root, field::NODE_CHILD_ORDINAL, index).ok()?;
        let kind = self.string(read_rep_u32(&self.root, field::NODE_KIND, index).ok()? as usize)?;
        let start_byte = u64::from(read_rep_u32(&self.root, field::NODE_START_BYTE, index).ok()?);
        let end_byte = u64::from(read_rep_u32(&self.root, field::NODE_END_BYTE, index).ok()?);
        let flags = read_rep_u8(&self.root, field::NODE_FLAGS, index).ok()?;
        Some(CachedNode {
            id: stable_id(
                b"astdiff/node/v1",
                &[
                    &parent_row.to_le_bytes(),
                    &child_ordinal.to_le_bytes(),
                    kind.as_bytes(),
                    &[flags],
                ],
            ),
            parent: optional_row(parent_row),
            child_ordinal,
            kind,
            start_byte,
            end_byte,
            flags,
        })
    }

    pub fn scope(&self, index: usize) -> Option<CachedScope> {
        if index >= self.scope_count {
            return None;
        }
        let parent_row = read_rep_u32(&self.root, field::SCOPE_PARENT, index).ok()?;
        let kind =
            AnalysisScopeKind::from_code(read_rep_u8(&self.root, field::SCOPE_KIND, index).ok()?)
                .ok()?;
        let depth = read_rep_u32(&self.root, field::SCOPE_DEPTH, index).ok()?;
        let start_byte = u64::from(read_rep_u32(&self.root, field::SCOPE_START_BYTE, index).ok()?);
        let end_byte = u64::from(read_rep_u32(&self.root, field::SCOPE_END_BYTE, index).ok()?);
        Some(CachedScope {
            id: stable_id(
                b"astdiff/scope/v1",
                &[
                    &parent_row.to_le_bytes(),
                    &[kind as u8],
                    &depth.to_le_bytes(),
                    &start_byte.to_le_bytes(),
                    &end_byte.to_le_bytes(),
                ],
            ),
            parent: optional_row(parent_row),
            kind,
            depth,
            start_byte,
            end_byte,
        })
    }

    pub fn symbol(&self, index: usize) -> Option<CachedSymbol<'a>> {
        if index >= self.symbol_count {
            return None;
        }
        Some(CachedSymbol {
            id: id_at(self.root.blob_at(field::SYMBOL_IDS)?, index)?,
            declaration_node: read_rep_u32(&self.root, field::SYMBOL_DECLARATION_NODE, index)
                .ok()?,
            scope: read_rep_u32(&self.root, field::SYMBOL_SCOPE, index).ok()?,
            name: self.string(read_rep_u32(&self.root, field::SYMBOL_NAME, index).ok()? as usize)?,
            kind: AnalysisSymbolKind::from_code(
                read_rep_u8(&self.root, field::SYMBOL_KIND, index).ok()?,
            )
            .ok()?,
            reference_first: read_rep_u32(&self.root, field::SYMBOL_REFERENCE_FIRST, index).ok()?,
            reference_count: read_rep_u32(&self.root, field::SYMBOL_REFERENCE_COUNT, index).ok()?,
        })
    }

    pub fn reference(&self, index: usize) -> Option<CachedReference<'a>> {
        if index >= self.reference_count {
            return None;
        }
        Some(CachedReference {
            id: id_at(self.root.blob_at(field::REFERENCE_IDS)?, index)?,
            node: read_rep_u32(&self.root, field::REFERENCE_NODE, index).ok()?,
            scope: read_rep_u32(&self.root, field::REFERENCE_SCOPE, index).ok()?,
            name: self
                .string(read_rep_u32(&self.root, field::REFERENCE_NAME, index).ok()? as usize)?,
            role: AnalysisReferenceRole::from_code(
                read_rep_u8(&self.root, field::REFERENCE_ROLE, index).ok()?,
            )
            .ok()?,
        })
    }

    pub fn def_use(&self, index: usize) -> Option<CachedDefUse> {
        if index >= self.def_use_count {
            return None;
        }
        let symbol = read_rep_u32(&self.root, field::DEF_USE_SYMBOL, index).ok()?;
        Some(CachedDefUse {
            id: id_at(self.root.blob_at(field::DEF_USE_IDS)?, index)?,
            reference: read_rep_u32(&self.root, field::DEF_USE_REFERENCE, index).ok()?,
            symbol: optional_row(symbol),
            resolution: AnalysisResolution::from_code(
                read_rep_u8(&self.root, field::DEF_USE_RESOLUTION, index).ok()?,
            )
            .ok()?,
        })
    }

    pub fn call(&self, index: usize) -> Option<CachedCall<'a>> {
        if index >= self.call_count {
            return None;
        }
        let callee = read_rep_u32(&self.root, field::CALL_CALLEE_REFERENCE, index).ok()?;
        let target = read_rep_u32(&self.root, field::CALL_TARGET_SYMBOL, index).ok()?;
        let property = read_rep_u32(&self.root, field::CALL_PROPERTY, index).ok()?;
        Some(CachedCall {
            id: id_at(self.root.blob_at(field::CALL_IDS)?, index)?,
            node: read_rep_u32(&self.root, field::CALL_NODE, index).ok()?,
            callee_reference: optional_row(callee),
            target_symbol: optional_row(target),
            property: optional_row(property).and_then(|row| self.string(row as usize)),
            kind: AnalysisCallKind::from_code(
                read_rep_u8(&self.root, field::CALL_KIND, index).ok()?,
            )
            .ok()?,
        })
    }

    pub fn loss(&self, index: usize) -> Option<CachedLoss<'a>> {
        if index >= self.loss_count {
            return None;
        }
        Some(CachedLoss {
            code: LossCode::from_code(read_rep_u16(&self.root, field::LOSS_CODE, index).ok()?)
                .ok()?,
            message: self
                .string(read_rep_u32(&self.root, field::LOSS_MESSAGE, index).ok()? as usize)?,
        })
    }

    fn metadata_string(&self, field_index: usize) -> Option<&'a str> {
        self.string(read_fixed_u32(&self.root, field_index).ok()? as usize)
    }

    fn validate_relation_ids(&self) -> Result<()> {
        for index in 0..self.reference_count {
            let reference = self
                .reference(index)
                .ok_or_else(|| anyhow!("reference {index} cannot be read after verification"))?;
            let node = self
                .node(reference.node as usize)
                .ok_or_else(|| anyhow!("reference {index} has an unreadable node"))?;
            let expected = stable_id(
                b"astdiff/reference/v1",
                &[&node.id.0, &[reference.role as u8]],
            );
            if reference.id != expected {
                bail!("reference {index} has an invalid stable ID");
            }
            let def_use = self
                .def_use(index)
                .ok_or_else(|| anyhow!("def-use {index} cannot be read after verification"))?;
            let target = def_use
                .symbol
                .and_then(|symbol| self.symbol(symbol as usize))
                .map(|symbol| symbol.id)
                .unwrap_or(StableId([0; 32]));
            let expected = stable_id(
                b"astdiff/def-use/v1",
                &[&reference.id.0, &target.0, &[def_use.resolution as u8]],
            );
            if def_use.id != expected {
                bail!("def-use {index} has an invalid stable ID");
            }
        }
        for index in 0..self.call_count {
            let call = self
                .call(index)
                .ok_or_else(|| anyhow!("call {index} cannot be read after verification"))?;
            let node = self
                .node(call.node as usize)
                .ok_or_else(|| anyhow!("call {index} has an unreadable node"))?;
            let callee = call
                .callee_reference
                .and_then(|reference| self.def_use(reference as usize))
                .map(|edge| edge.id)
                .unwrap_or(StableId([0; 32]));
            let target = call
                .target_symbol
                .and_then(|symbol| self.symbol(symbol as usize))
                .map(|symbol| symbol.id)
                .unwrap_or(StableId([0; 32]));
            let property = read_rep_u32(&self.root, field::CALL_PROPERTY, index)?;
            let expected = stable_id(
                b"astdiff/call/v1",
                &[
                    &node.id.0,
                    &[call.kind as u8],
                    &callee.0,
                    &target.0,
                    &property.to_le_bytes(),
                ],
            );
            if call.id != expected {
                bail!("call {index} has an invalid stable ID");
            }
        }
        Ok(())
    }
}

pub struct CachedNode<'a> {
    pub id: StableId,
    pub parent: Option<u32>,
    pub child_ordinal: u32,
    pub kind: &'a str,
    pub start_byte: u64,
    pub end_byte: u64,
    pub flags: u8,
}

pub struct CachedScope {
    pub id: StableId,
    pub parent: Option<u32>,
    pub kind: AnalysisScopeKind,
    pub depth: u32,
    pub start_byte: u64,
    pub end_byte: u64,
}

pub struct CachedSymbol<'a> {
    pub id: StableId,
    pub declaration_node: u32,
    pub scope: u32,
    pub name: &'a str,
    pub kind: AnalysisSymbolKind,
    pub reference_first: u32,
    pub reference_count: u32,
}

pub struct CachedReference<'a> {
    pub id: StableId,
    pub node: u32,
    pub scope: u32,
    pub name: &'a str,
    pub role: AnalysisReferenceRole,
}

pub struct CachedDefUse {
    pub id: StableId,
    pub reference: u32,
    pub symbol: Option<u32>,
    pub resolution: AnalysisResolution,
}

pub struct CachedCall<'a> {
    pub id: StableId,
    pub node: u32,
    pub callee_reference: Option<u32>,
    pub target_symbol: Option<u32>,
    pub property: Option<&'a str>,
    pub kind: AnalysisCallKind,
}

pub struct CachedLoss<'a> {
    pub code: LossCode,
    pub message: &'a str,
}

impl AnalysisSymbolKind {
    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Function),
            2 => Ok(Self::Var),
            3 => Ok(Self::Let),
            4 => Ok(Self::Const),
            5 => Ok(Self::Parameter),
            6 => Ok(Self::Class),
            7 => Ok(Self::Import),
            8 => Ok(Self::Catch),
            _ => bail!("unknown symbol kind code {code}"),
        }
    }
}

impl AnalysisReferenceRole {
    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::ReadWrite),
            4 => Ok(Self::Call),
            5 => Ok(Self::Construct),
            6 => Ok(Self::Export),
            _ => bail!("unknown reference role code {code}"),
        }
    }
}

impl AnalysisResolution {
    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Resolved),
            2 => Ok(Self::Unresolved),
            3 => Ok(Self::Ambiguous),
            _ => bail!("unknown resolution code {code}"),
        }
    }
}

impl AnalysisCallKind {
    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Direct),
            2 => Ok(Self::Member),
            3 => Ok(Self::Construct),
            4 => Ok(Self::Dynamic),
            _ => bail!("unknown call kind code {code}"),
        }
    }
}

impl AnalysisScopeKind {
    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Global),
            2 => Ok(Self::Function),
            3 => Ok(Self::Block),
            4 => Ok(Self::Class),
            5 => Ok(Self::Module),
            _ => bail!("unknown scope kind code {code}"),
        }
    }
}

impl LossCode {
    fn from_code(code: u16) -> Result<Self> {
        match code {
            1 => Ok(Self::SourceMapLineageUnavailable),
            2 => Ok(Self::FingerprintEvidenceUnavailable),
            3 => Ok(Self::DynamicCallTargetUnavailable),
            4 => Ok(Self::TdzAndFlowResolutionUnavailable),
            5 => Ok(Self::DynamicScopeUnavailable),
            _ => bail!("unknown loss code {code}"),
        }
    }
}

fn validate_header(header: &[u8; HEADER_SIZE], file_len: usize) -> Result<()> {
    if &header[0..8] != CACHE_MAGIC {
        bail!("invalid analysis cache magic");
    }
    if read_u16(&header[8..10]) != CACHE_VERSION {
        bail!("unsupported analysis cache container version");
    }
    if read_u16(&header[10..12]) != CACHE_FLAGS_POSITIONED {
        bail!("unsupported analysis cache flags");
    }
    if read_u32(&header[12..16]) as usize != HEADER_SIZE {
        bail!("invalid analysis cache header size");
    }
    if header[120..128].iter().any(|byte| *byte != 0) {
        bail!("analysis cache reserved header bytes are not zero");
    }
    let state = schema_state()?;
    if header[16..48] != state.layout_hash {
        bail!("analysis cache layout hash does not match the embedded schema");
    }
    let payload_len_u64 = read_u64(&header[112..120]);
    if payload_len_u64 > MAX_CACHE_BYTES {
        bail!("analysis cache exceeds the 4 GiB payload limit");
    }
    let payload_len = usize::try_from(payload_len_u64)?;
    if HEADER_SIZE.checked_add(payload_len) != Some(file_len) {
        bail!("analysis cache payload length is invalid");
    }
    Ok(())
}

fn write_atomic(path: &Path, header: &[u8; HEADER_SIZE], payload: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("analysis output path has no UTF-8 file name"))?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| {
                format!(
                    "failed to create temporary analysis file {}",
                    temporary.display()
                )
            })?;
        file.write_all(header)?;
        file.write_all(payload)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "failed to publish analysis file {} as {}",
                temporary.display(),
                path.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_metadata_string(
    root: &CanonicalView<'_, '_>,
    field_index: usize,
    string_count: usize,
    name: &str,
) -> Result<()> {
    if read_fixed_u32(root, field_index)? as usize >= string_count {
        bail!("{name} references an invalid string row");
    }
    Ok(())
}

fn validate_count(
    root: &CanonicalView<'_, '_>,
    field_index: usize,
    expected: usize,
    table: &str,
) -> Result<()> {
    let actual = repetition(root, field_index, table)?.count();
    if actual != expected {
        bail!("{table} column {field_index} has {actual} rows, expected {expected}");
    }
    Ok(())
}

fn validate_id_blob(
    root: &CanonicalView<'_, '_>,
    field_index: usize,
    count: usize,
    name: &str,
) -> Result<()> {
    let bytes = root
        .blob_at(field_index)
        .ok_or_else(|| anyhow!("missing {name} column"))?;
    if bytes.len() != count.saturating_mul(ID_SIZE) {
        bail!("{name} has the wrong byte length");
    }
    Ok(())
}

fn repetition<'l, 'a>(
    root: &'a CanonicalView<'l, 'a>,
    field_index: usize,
    name: &str,
) -> Result<isoform::positioned::RepetitionView<'l, 'a>> {
    root.repetition_at(field_index)
        .ok_or_else(|| anyhow!("missing {name} column"))
}

fn read_fixed_u8(root: &CanonicalView<'_, '_>, field_index: usize) -> Result<u8> {
    Ok(*root
        .fixed_at(field_index)
        .and_then(|bytes| bytes.first())
        .ok_or_else(|| anyhow!("missing fixed field {field_index}"))?)
}

fn read_fixed_u32(root: &CanonicalView<'_, '_>, field_index: usize) -> Result<u32> {
    let bytes = root
        .fixed_at(field_index)
        .ok_or_else(|| anyhow!("missing fixed field {field_index}"))?;
    Ok(read_u32(bytes))
}

fn read_fixed_u64(root: &CanonicalView<'_, '_>, field_index: usize) -> Result<u64> {
    let bytes = root
        .fixed_at(field_index)
        .ok_or_else(|| anyhow!("missing fixed field {field_index}"))?;
    Ok(read_u64(bytes))
}

fn read_rep_u8(root: &CanonicalView<'_, '_>, field_index: usize, index: usize) -> Result<u8> {
    Ok(*repetition(root, field_index, "u8")?
        .fixed(index)
        .and_then(|bytes| bytes.first())
        .ok_or_else(|| anyhow!("missing row {index} in column {field_index}"))?)
}

fn read_rep_u16(root: &CanonicalView<'_, '_>, field_index: usize, index: usize) -> Result<u16> {
    let rep = repetition(root, field_index, "u16")?;
    let bytes = rep
        .fixed(index)
        .ok_or_else(|| anyhow!("missing row {index} in column {field_index}"))?;
    Ok(read_u16(bytes))
}

fn read_rep_u32(root: &CanonicalView<'_, '_>, field_index: usize, index: usize) -> Result<u32> {
    let rep = repetition(root, field_index, "u32")?;
    let bytes = rep
        .fixed(index)
        .ok_or_else(|| anyhow!("missing row {index} in column {field_index}"))?;
    Ok(read_u32(bytes))
}

fn exact_blob<const N: usize>(
    root: &CanonicalView<'_, '_>,
    field_index: usize,
    name: &str,
) -> Result<[u8; N]> {
    let bytes = root
        .blob_at(field_index)
        .ok_or_else(|| anyhow!("missing {name}"))?;
    if bytes.len() != N {
        bail!("{name} has length {}, expected {N}", bytes.len());
    }
    Ok(array(bytes))
}

fn id_at(bytes: &[u8], index: usize) -> Option<StableId> {
    let start = index.checked_mul(ID_SIZE)?;
    let end = start.checked_add(ID_SIZE)?;
    Some(StableId(array(bytes.get(start..end)?)))
}

fn optional_row(value: u32) -> Option<u32> {
    (value != NO_ROW).then_some(value)
}

fn fixed_count(count: usize) -> Result<OwnedValue> {
    Ok(fixed_u32(u32::try_from(count)?))
}

fn fixed_u8(value: u8) -> OwnedValue {
    OwnedValue::Fixed(vec![value])
}

fn fixed_u16(value: u16) -> OwnedValue {
    OwnedValue::Fixed(value.to_le_bytes().to_vec())
}

fn fixed_u32(value: u32) -> OwnedValue {
    OwnedValue::Fixed(value.to_le_bytes().to_vec())
}

fn fixed_u64(value: u64) -> OwnedValue {
    OwnedValue::Fixed(value.to_le_bytes().to_vec())
}

fn repetition_u8(values: impl Iterator<Item = u8>) -> OwnedValue {
    OwnedValue::Repetition(values.map(fixed_u8).collect())
}

fn repetition_u16(values: impl Iterator<Item = u16>) -> OwnedValue {
    OwnedValue::Repetition(values.map(fixed_u16).collect())
}

fn repetition_u32(values: impl Iterator<Item = u32>) -> OwnedValue {
    OwnedValue::Repetition(values.map(fixed_u32).collect())
}

fn repetition_u32_from_u64(values: impl Iterator<Item = u64>) -> Result<OwnedValue> {
    Ok(OwnedValue::Repetition(
        values
            .map(|value| Ok(fixed_u32(u32::try_from(value)?)))
            .collect::<Result<Vec<_>>>()?,
    ))
}

fn flatten_ids(ids: impl Iterator<Item = StableId>) -> Vec<u8> {
    ids.flat_map(|id| id.0).collect()
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("caller supplied exact-width bytes")
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(array(bytes))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(array(bytes))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(array(bytes))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::parser::JsParser;

    use super::*;

    fn analysis(source: &str) -> Analysis {
        let mut parser = JsParser::new().unwrap();
        let tree = parser.parse(source).unwrap();
        Analysis::from_javascript(source, &tree).unwrap()
    }

    fn positioned_fixed_offset(bytes: &[u8], field_index: usize, row: usize) -> usize {
        let payload = &bytes[HEADER_SIZE..];
        let state = schema_state().unwrap();
        let verified = verify(
            &state.layouts,
            "Analysis",
            payload,
            cache_budgets(payload.len()),
        )
        .unwrap();
        let root = verified.as_canonical().unwrap();
        let value = root.repetition_at(field_index).unwrap().fixed(row).unwrap();
        value.as_ptr() as usize - payload.as_ptr() as usize
    }

    fn rewrite_payload_digest(bytes: &mut [u8]) {
        let digest: [u8; 32] = Sha256::digest(&bytes[HEADER_SIZE..]).into();
        bytes[80..112].copy_from_slice(&digest);
    }

    #[test]
    fn positioned_cache_round_trips_with_indexed_strings_and_o1_rows() {
        let source = "function greet(name) { return `hello ${name}`; }";
        let analysis = analysis(source);
        let directory = tempdir().unwrap();
        let path = directory.path().join("analysis.astir");
        analysis.write_positioned(&path).unwrap();

        let mapped = MappedAnalysis::open(&path).unwrap();
        let view = mapped.verify().unwrap();
        assert_eq!(view.source_digest(), analysis.source_digest);
        assert_eq!(view.node_count(), analysis.nodes.len());
        assert_eq!(view.scope_count(), analysis.scopes.len());
        assert_eq!(view.symbol_count(), 2);
        assert_eq!(view.reference_count(), 1);
        assert_eq!(view.def_use_count(), 1);
        assert_eq!(view.symbol(0).unwrap().name, "greet");
        assert_eq!(view.symbol(0).unwrap().id, analysis.symbols[0].id);
        assert_eq!(view.reference(0).unwrap().name, "name");
        assert_eq!(
            view.def_use(0).unwrap().resolution,
            AnalysisResolution::Resolved
        );
        assert_eq!(view.node(0).unwrap().kind, "program");
        assert_eq!(view.node(0).unwrap().id, analysis.nodes[0].id);
        assert_eq!(view.scope(0).unwrap().id, analysis.scopes[0].id);
        assert_eq!(
            view.loss(0).unwrap().code,
            LossCode::SourceMapLineageUnavailable
        );
    }

    #[test]
    fn envelope_corruption_is_rejected_before_isoform_access() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("analysis.astir");
        analysis("const answer = 42;")
            .write_positioned(&path)
            .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0x80;
        std::fs::write(&path, bytes).unwrap();
        assert!(MappedAnalysis::open(&path)
            .unwrap_err()
            .to_string()
            .contains("digest mismatch"));
    }

    #[test]
    fn cache_can_be_bound_to_exact_source_bytes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("analysis.astir");
        let source = b"const answer = 42;";
        analysis(std::str::from_utf8(source).unwrap())
            .write_positioned(&path)
            .unwrap();
        assert!(MappedAnalysis::open_for_source(&path, source).is_ok());
        assert!(
            MappedAnalysis::open_for_source(&path, b"const answer = 43;")
                .unwrap_err()
                .to_string()
                .contains("source digest mismatch")
        );
    }

    #[test]
    fn layout_hash_mismatch_is_rejected_before_mapping_fields() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("analysis.astir");
        analysis("const answer = 42;")
            .write_positioned(&path)
            .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[16] ^= 0x01;
        std::fs::write(&path, bytes).unwrap();
        assert!(MappedAnalysis::open(&path)
            .unwrap_err()
            .to_string()
            .contains("layout hash"));
    }

    #[test]
    fn semantic_verifier_rejects_non_utf8_string_after_valid_isoform_structure() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("analysis.astir");
        analysis("const answer = 42;")
            .write_positioned(&path)
            .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let string_offset = {
            let payload = &bytes[HEADER_SIZE..];
            let state = schema_state().unwrap();
            let verified = verify(
                &state.layouts,
                "Analysis",
                payload,
                cache_budgets(payload.len()),
            )
            .unwrap();
            let root = verified.as_canonical().unwrap();
            let value = root.repetition_at(field::STRINGS).unwrap().blob(0).unwrap();
            value.as_ptr() as usize - payload.as_ptr() as usize
        };
        bytes[HEADER_SIZE + string_offset] = 0xff;
        let digest: [u8; 32] = Sha256::digest(&bytes[HEADER_SIZE..]).into();
        bytes[80..112].copy_from_slice(&digest);
        std::fs::write(&path, bytes).unwrap();

        let mapped = MappedAnalysis::open(&path).unwrap();
        let error = mapped.verify().err().unwrap();
        assert!(error.to_string().contains("not valid UTF-8"));
    }

    #[test]
    fn semantic_verifier_rejects_a_structurally_valid_forged_symbol_id() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("analysis.astir");
        analysis("function answer() { return 42; }")
            .write_positioned(&path)
            .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let id_offset = {
            let payload = &bytes[HEADER_SIZE..];
            let state = schema_state().unwrap();
            let verified = verify(
                &state.layouts,
                "Analysis",
                payload,
                cache_budgets(payload.len()),
            )
            .unwrap();
            let root = verified.as_canonical().unwrap();
            let value = root.blob_at(field::SYMBOL_IDS).unwrap();
            value.as_ptr() as usize - payload.as_ptr() as usize
        };
        bytes[HEADER_SIZE + id_offset] ^= 0x01;
        let digest: [u8; 32] = Sha256::digest(&bytes[HEADER_SIZE..]).into();
        bytes[80..112].copy_from_slice(&digest);
        std::fs::write(&path, bytes).unwrap();

        let mapped = MappedAnalysis::open(&path).unwrap();
        let error = mapped.verify().err().unwrap();
        assert!(error.to_string().contains("invalid stable ID"));
    }

    #[test]
    fn semantic_verifier_rejects_overlapping_symbol_reference_ranges() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("analysis.astir");
        analysis("let first = 1, second = 2; first; second;")
            .write_positioned(&path)
            .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let offset = positioned_fixed_offset(&bytes, field::SYMBOL_REFERENCE_FIRST, 1);
        bytes[HEADER_SIZE + offset..HEADER_SIZE + offset + 4].copy_from_slice(&0u32.to_le_bytes());
        rewrite_payload_digest(&mut bytes);
        std::fs::write(&path, bytes).unwrap();

        let mapped = MappedAnalysis::open(&path).unwrap();
        let error = mapped.verify().err().unwrap();
        assert!(error.to_string().contains("invalid reference range"));
    }

    #[test]
    fn semantic_verifier_rejects_call_rows_on_non_call_nodes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("analysis.astir");
        analysis("function invoke() {} invoke();")
            .write_positioned(&path)
            .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let offset = positioned_fixed_offset(&bytes, field::CALL_NODE, 0);
        bytes[HEADER_SIZE + offset..HEADER_SIZE + offset + 4].copy_from_slice(&0u32.to_le_bytes());
        rewrite_payload_digest(&mut bytes);
        std::fs::write(&path, bytes).unwrap();

        let mapped = MappedAnalysis::open(&path).unwrap();
        let error = mapped.verify().err().unwrap();
        assert!(error.to_string().contains("invalid syntax node kind"));
    }

    #[test]
    fn positioned_bytes_are_deterministic() {
        let first = analysis("const answer = 42;").encode_positioned().unwrap();
        let second = analysis("const answer = 42;").encode_positioned().unwrap();
        assert_eq!(first, second);
    }
}
