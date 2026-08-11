//! Isoform positioned persistence for parsed Source Map v3 basic maps.
//!
//! The `.astsm` sidecar is intentionally separate from Analysis v1.  It keeps
//! a nullable source tuple (`sourceRoot`, `sources[source]`) and stores line
//! and segment columns in one canonical positioned payload.  Indexed maps are
//! accepted by the normal parser and lookup implementation, but cannot be
//! encoded by this v1 sidecar because section offsets do not form one global
//! line/segment slice; callers must flatten them before encoding.

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

use super::{GeneratedPosition, MapKind, OriginalPosition, Segment, SourceMap};

const SCHEMA_ARTIFACT: &[u8] = include_bytes!("../../schemas/sourcemap-v3.isf");
const CACHE_MAGIC: &[u8; 8] = b"ASTSM\0\0\0";
const CACHE_VERSION: u16 = 1;
const CACHE_FLAGS_POSITIONED: u16 = 1;
const HEADER_SIZE: usize = 160;
const MAX_CACHE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CACHE_ROWS: u64 = 100_000_000;
const NO_ROW: u32 = u32::MAX;

/// Version and profile identity for the Source Map sidecar.
pub const SOURCEMAP_VERSION: u32 = 1;
pub const SOURCEMAP_PROFILE: &str = "astdiff.sourcemap.v3.positioned";
pub const SOURCEMAP_PRODUCER: &str = "astdiff";
pub const SOURCEMAP_PRODUCER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Explicit resource bounds applied while encoding and verifying a sidecar.
#[derive(Debug, Clone, Copy)]
pub struct SourceMapCacheLimits {
    pub max_payload_bytes: u64,
    pub max_lines: usize,
    pub max_segments: usize,
    pub max_strings: usize,
    pub max_string_bytes: usize,
}

impl Default for SourceMapCacheLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: MAX_CACHE_BYTES,
            max_lines: 20_000_000,
            max_segments: 100_000_000,
            max_strings: 2_000_000,
            max_string_bytes: 256 * 1024 * 1024,
        }
    }
}

mod field {
    pub const FORMAT_VERSION: usize = 0;
    pub const PROFILE: usize = 1;
    pub const PRODUCER: usize = 2;
    pub const PRODUCER_VERSION: usize = 3;
    pub const MAP_VERSION: usize = 4;
    pub const SOURCE_COUNT: usize = 5;
    pub const NAME_COUNT: usize = 6;
    pub const LINE_COUNT: usize = 7;
    pub const SEGMENT_COUNT: usize = 8;
    pub const SOURCE_ROOT: usize = 9;
    pub const STRINGS: usize = 10;
    pub const SOURCE_STRING: usize = 11;
    pub const NAME_STRING: usize = 12;
    pub const LINE_FIRST: usize = 13;
    pub const LINE_COUNT_COLUMN: usize = 14;
    pub const SEGMENT_GENERATED_COLUMN: usize = 15;
    pub const SEGMENT_SOURCE: usize = 16;
    pub const SEGMENT_ORIGINAL_LINE: usize = 17;
    pub const SEGMENT_ORIGINAL_COLUMN: usize = 18;
    pub const SEGMENT_NAME: usize = 19;
}

const EXPECTED_FIELDS: [&str; 20] = [
    "format_version",
    "profile",
    "producer",
    "producer_version",
    "map_version",
    "source_count",
    "name_count",
    "line_count",
    "segment_count",
    "source_root",
    "strings",
    "source_string",
    "name_string",
    "line_first_segment",
    "line_segment_count",
    "segment_generated_column",
    "segment_source",
    "segment_original_line",
    "segment_original_column",
    "segment_name",
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
                .message("SourceMap")
                .ok_or_else(|| "embedded schema has no SourceMap message".to_string())?;
            let actual_fields = message
                .fields()
                .iter()
                .map(|field| field.name())
                .collect::<Vec<_>>();
            if actual_fields != EXPECTED_FIELDS {
                return Err(
                    "embedded SourceMap schema does not match generated field indexes".to_string(),
                );
            }
            let layout_hash =
                artifact::layout_hash(&schema, "SourceMap").map_err(|error| error.to_string())?;
            let layouts = LayoutSet::compile(&schema).map_err(|error| format!("{error:?}"))?;
            validate_layout_contract(&layouts)?;
            Ok(SchemaState {
                schema,
                layouts,
                layout_hash,
            })
        })
        .as_ref()
        .map_err(|error| anyhow!("invalid embedded source-map schema: {error}"))
}

fn validate_layout_contract(layouts: &LayoutSet) -> std::result::Result<(), String> {
    let region = layouts
        .region("SourceMap")
        .ok_or_else(|| "embedded SourceMap layout is missing".to_string())?;
    if region.fields.len() != EXPECTED_FIELDS.len()
        || region.fields.iter().any(|field| field.optional)
    {
        return Err("embedded SourceMap layout has unexpected fields or optionality".to_string());
    }
    let check_fixed = |index: usize, width: u8| match region.fields[index].kind {
        FieldKind::Fixed { width: actual } if actual == width => Ok(()),
        _ => Err(format!(
            "SourceMap field {} is not fixed width {width}",
            EXPECTED_FIELDS[index]
        )),
    };
    for index in 0..10 {
        check_fixed(index, 4)?;
    }
    let check_rep = |index: usize, width: u8| match &region.fields[index].kind {
        FieldKind::Repetition {
            element: ElementLayout::Fixed { width: actual },
            element_offset_width: None,
            ..
        } if *actual == width => Ok(()),
        _ => Err(format!(
            "SourceMap field {} is not fixed repetition width {width}",
            EXPECTED_FIELDS[index]
        )),
    };
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
        return Err("SourceMap strings lack their required indexed layout".to_string());
    }
    for index in field::SOURCE_STRING..=field::SEGMENT_NAME {
        check_rep(index, 4)?;
    }
    Ok(())
}

fn cache_budgets(payload_len: usize, limits: SourceMapCacheLimits) -> Budgets {
    Budgets::default()
        .with_max_message_size(payload_len)
        .with_max_count(
            u64::try_from(
                limits
                    .max_lines
                    .max(limits.max_segments)
                    .max(limits.max_strings),
            )
            .unwrap_or(MAX_CACHE_ROWS),
        )
}

impl SourceMap {
    /// Encode a parsed basic map as a deterministic Isoform positioned payload.
    pub fn encode_positioned(&self) -> Result<Vec<u8>> {
        self.encode_positioned_with_limits(SourceMapCacheLimits::default())
    }

    pub fn encode_positioned_with_limits(&self, limits: SourceMapCacheLimits) -> Result<Vec<u8>> {
        let MapKind::Basic(map) = &self.kind else {
            bail!("indexed source maps cannot be encoded as .astsm v1: sections do not fit one first line/segment slice; flatten the map first");
        };
        if map.lines.len() > limits.max_lines {
            bail!("source-map sidecar exceeds the line limit");
        }
        if map.segments.len() > limits.max_segments {
            bail!("source-map sidecar exceeds the segment limit");
        }
        let string_count = map
            .sources
            .iter()
            .filter(|source| source.is_some())
            .count()
            .checked_add(map.names.len())
            .and_then(|count| count.checked_add(usize::from(map.source_root.is_some())))
            .and_then(|count| count.checked_add(3))
            .ok_or_else(|| anyhow!("source-map sidecar string count overflow"))?;
        if string_count > limits.max_strings {
            bail!("source-map sidecar exceeds the string limit");
        }
        let string_bytes = map
            .sources
            .iter()
            .filter_map(|source| source.as_deref())
            .map(str::len)
            .sum::<usize>()
            .checked_add(map.names.iter().map(String::len).sum::<usize>())
            .and_then(|size| {
                map.source_root
                    .as_deref()
                    .map_or(Some(size), |root| size.checked_add(root.len()))
            })
            .and_then(|size| size.checked_add(SOURCEMAP_PROFILE.len()))
            .and_then(|size| size.checked_add(SOURCEMAP_PRODUCER.len()))
            .and_then(|size| size.checked_add(SOURCEMAP_PRODUCER_VERSION.len()))
            .ok_or_else(|| anyhow!("source-map sidecar string byte count overflow"))?;
        if string_bytes > limits.max_string_bytes {
            bail!("source-map sidecar exceeds the string byte limit");
        }
        let state = schema_state()?;
        let mut builder = MessageBuilder::new(&state.schema, "SourceMap")?;

        // Keep source rows and name rows in stable source/name order.  A null
        // source has no string row, while duplicate strings retain duplicate
        // rows so source/name indexes remain exactly Source Map v3 indexes.
        let mut strings = Vec::with_capacity(string_count);
        let mut source_string = Vec::with_capacity(map.sources.len());
        for source in &map.sources {
            source_string.push(match source {
                Some(value) => {
                    let row = u32::try_from(strings.len())?;
                    strings.push(value.as_bytes().to_vec());
                    row
                }
                None => NO_ROW,
            });
        }
        let mut name_string = Vec::with_capacity(map.names.len());
        for name in &map.names {
            let row = u32::try_from(strings.len())?;
            strings.push(name.as_bytes().to_vec());
            name_string.push(row);
        }
        let source_root = if let Some(root) = &map.source_root {
            let row = u32::try_from(strings.len())?;
            strings.push(root.as_bytes().to_vec());
            row
        } else {
            NO_ROW
        };
        let profile = metadata_string_index(&mut strings, SOURCEMAP_PROFILE)?;
        let producer = metadata_string_index(&mut strings, SOURCEMAP_PRODUCER)?;
        let producer_version = metadata_string_index(&mut strings, SOURCEMAP_PRODUCER_VERSION)?;
        // Metadata strings are appended after source/name strings and are not
        // source/name rows.  The explicit source/name row tables bind indexes.
        let mut line_first = Vec::with_capacity(map.lines.len());
        let mut line_counts = Vec::with_capacity(map.lines.len());
        for line in &map.lines {
            line_first.push(u32::try_from(line.first)?);
            line_counts.push(u32::try_from(line.count)?);
        }
        let mut segment_generated = Vec::with_capacity(map.segments.len());
        let mut segment_source = Vec::with_capacity(map.segments.len());
        let mut segment_line = Vec::with_capacity(map.segments.len());
        let mut segment_column = Vec::with_capacity(map.segments.len());
        let mut segment_name = Vec::with_capacity(map.segments.len());
        for Segment {
            generated_column,
            original,
        } in &map.segments
        {
            segment_generated.push(*generated_column);
            if let Some(original) = original {
                segment_source.push(original.source);
                segment_line.push(original.line);
                segment_column.push(original.column);
                segment_name.push(original.name.unwrap_or(NO_ROW));
            } else {
                segment_source.push(NO_ROW);
                segment_line.push(NO_ROW);
                segment_column.push(NO_ROW);
                segment_name.push(NO_ROW);
            }
        }
        builder
            .set_at(field::FORMAT_VERSION, fixed_u32(SOURCEMAP_VERSION))?
            .set_at(field::PROFILE, fixed_u32(profile))?
            .set_at(field::PRODUCER, fixed_u32(producer))?
            .set_at(field::PRODUCER_VERSION, fixed_u32(producer_version))?
            .set_at(field::MAP_VERSION, fixed_u32(3))?
            .set_at(
                field::SOURCE_COUNT,
                fixed_u32(u32::try_from(map.sources.len())?),
            )?
            .set_at(
                field::NAME_COUNT,
                fixed_u32(u32::try_from(map.names.len())?),
            )?
            .set_at(
                field::LINE_COUNT,
                fixed_u32(u32::try_from(map.lines.len())?),
            )?
            .set_at(
                field::SEGMENT_COUNT,
                fixed_u32(u32::try_from(map.segments.len())?),
            )?
            .set_at(field::SOURCE_ROOT, fixed_u32(source_root))?
            .set_at(
                field::STRINGS,
                OwnedValue::Repetition(strings.into_iter().map(OwnedValue::Blob).collect()),
            )?
            .set_at(field::SOURCE_STRING, repetition_u32(source_string))?
            .set_at(field::NAME_STRING, repetition_u32(name_string))?
            .set_at(field::LINE_FIRST, repetition_u32(line_first))?
            .set_at(field::LINE_COUNT_COLUMN, repetition_u32(line_counts))?
            .set_at(
                field::SEGMENT_GENERATED_COLUMN,
                repetition_u32(segment_generated),
            )?
            .set_at(field::SEGMENT_SOURCE, repetition_u32(segment_source))?
            .set_at(field::SEGMENT_ORIGINAL_LINE, repetition_u32(segment_line))?
            .set_at(
                field::SEGMENT_ORIGINAL_COLUMN,
                repetition_u32(segment_column),
            )?
            .set_at(field::SEGMENT_NAME, repetition_u32(segment_name))?;

        let message = builder.build()?;
        let payload = encode_owned_positioned(
            &state.schema,
            &state.layouts,
            &message,
            cache_budgets(
                usize::try_from(limits.max_payload_bytes.min(usize::MAX as u64))?,
                limits,
            ),
        )
        .map_err(|error| anyhow!("failed to encode source-map sidecar: {error:?}"))?;
        if u64::try_from(payload.len())? > limits.max_payload_bytes {
            bail!("source-map sidecar payload exceeds the byte limit");
        }
        Ok(payload)
    }

    /// Write a `.astsm` file containing this map and bind it to generated bytes.
    pub fn write_positioned(&self, path: &Path, generated_source: &[u8]) -> Result<()> {
        self.write_positioned_with_limits(path, generated_source, SourceMapCacheLimits::default())
    }

    pub fn write_positioned_with_limits(
        &self,
        path: &Path,
        generated_source: &[u8],
        limits: SourceMapCacheLimits,
    ) -> Result<()> {
        let payload = self.encode_positioned_with_limits(limits)?;
        let state = schema_state()?;
        let payload_len = u64::try_from(payload.len())?;
        let raw_digest = self.digest;
        let payload_digest: [u8; 32] = Sha256::digest(&payload).into();
        let generated_digest: [u8; 32] = Sha256::digest(generated_source).into();
        let mut header = [0u8; HEADER_SIZE];
        header[0..8].copy_from_slice(CACHE_MAGIC);
        header[8..10].copy_from_slice(&CACHE_VERSION.to_le_bytes());
        header[10..12].copy_from_slice(&CACHE_FLAGS_POSITIONED.to_le_bytes());
        header[12..16].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        header[16..48].copy_from_slice(&state.layout_hash);
        header[48..80].copy_from_slice(&raw_digest);
        header[80..112].copy_from_slice(&payload_digest);
        header[112..144].copy_from_slice(&generated_digest);
        header[144..152].copy_from_slice(&payload_len.to_le_bytes());
        write_atomic(path, &header, &payload)
    }

    pub fn write_astsm(&self, path: &Path, generated_source: &[u8]) -> Result<()> {
        self.write_positioned(path, generated_source)
    }
}

fn metadata_string_index(strings: &mut Vec<Vec<u8>>, value: &str) -> Result<u32> {
    let row = u32::try_from(strings.len())?;
    strings.push(value.as_bytes().to_vec());
    Ok(row)
}

/// An opened, digest-checked `.astsm` mapping sidecar.
#[derive(Debug)]
pub struct MappedSourceMap {
    mmap: Mmap,
    payload: Range<usize>,
    raw_map_digest: [u8; 32],
    generated_source_digest: [u8; 32],
}

impl MappedSourceMap {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_limits(path, SourceMapCacheLimits::default())
    }

    pub fn open_with_limits(path: &Path, limits: SourceMapCacheLimits) -> Result<Self> {
        let mut file = File::open(path)
            .with_context(|| format!("failed to open source-map sidecar {}", path.display()))?;
        let length = usize::try_from(file.metadata()?.len())?;
        if length < HEADER_SIZE {
            bail!("source-map sidecar is shorter than its fixed header");
        }
        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header)?;
        validate_header(&header, length, limits)?;
        // SAFETY: the map remains owned by this value and all accesses are
        // bounds checked. Callers must not truncate or rewrite the path while
        // this value is alive.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let payload = HEADER_SIZE..length;
        let expected_digest = array::<32>(&header[80..112]);
        let actual_digest: [u8; 32] = Sha256::digest(&mmap[payload.clone()]).into();
        if expected_digest != actual_digest {
            bail!("source-map sidecar normalized payload digest mismatch");
        }
        Ok(Self {
            mmap,
            payload,
            raw_map_digest: array::<32>(&header[48..80]),
            generated_source_digest: array::<32>(&header[112..144]),
        })
    }

    pub fn open_for_source(path: &Path, generated_source: &[u8]) -> Result<Self> {
        let mapped = Self::open(path)?;
        let actual: [u8; 32] = Sha256::digest(generated_source).into();
        if actual != mapped.generated_source_digest {
            bail!("source-map sidecar generated source digest mismatch");
        }
        Ok(mapped)
    }

    pub fn raw_map_digest(&self) -> [u8; 32] {
        self.raw_map_digest
    }

    pub fn generated_source_digest(&self) -> [u8; 32] {
        self.generated_source_digest
    }

    pub fn verify(&self) -> Result<SourceMapCacheView<'_>> {
        self.verify_with_limits(SourceMapCacheLimits::default())
    }

    pub fn verify_with_limits(
        &self,
        limits: SourceMapCacheLimits,
    ) -> Result<SourceMapCacheView<'_>> {
        let state = schema_state()?;
        let payload = &self.mmap[self.payload.clone()];
        let verified = verify(
            &state.layouts,
            "SourceMap",
            payload,
            cache_budgets(payload.len(), limits),
        )
        .map_err(|error| anyhow!("invalid positioned source-map sidecar: {error:?}"))?;
        let Verified::Canonical(root) = verified else {
            bail!("bare SourceMap schema unexpectedly produced a bounded view");
        };
        SourceMapCacheView::new(
            root,
            self.raw_map_digest,
            self.generated_source_digest,
            limits,
        )
    }
}

/// A semantically verified borrowed source-map sidecar.
pub struct SourceMapCacheView<'a> {
    root: CanonicalView<'static, 'a>,
    source_count: usize,
    name_count: usize,
    line_count: usize,
    segment_count: usize,
    source_root: Option<u32>,
    raw_map_digest: [u8; 32],
    generated_source_digest: [u8; 32],
}

impl<'a> SourceMapCacheView<'a> {
    fn new(
        root: CanonicalView<'static, 'a>,
        raw_map_digest: [u8; 32],
        generated_source_digest: [u8; 32],
        limits: SourceMapCacheLimits,
    ) -> Result<Self> {
        if read_fixed_u32(&root, field::FORMAT_VERSION)? != SOURCEMAP_VERSION
            || read_fixed_u32(&root, field::MAP_VERSION)? != 3
        {
            bail!("unsupported source-map sidecar version");
        }
        let strings = repetition(&root, field::STRINGS, "strings")?;
        if !strings.has_materialized_index() {
            bail!("source-map strings lack their materialized offset index");
        }
        if strings.count() > limits.max_strings {
            bail!("source-map sidecar string limit exceeded");
        }
        let mut string_bytes = 0usize;
        for index in 0..strings.count() {
            let value = strings
                .blob(index)
                .ok_or_else(|| anyhow!("missing string row {index}"))?;
            string_bytes = string_bytes
                .checked_add(value.len())
                .ok_or_else(|| anyhow!("source-map string byte count overflow"))?;
            std::str::from_utf8(value)
                .with_context(|| format!("source-map string row {index} is not valid UTF-8"))?;
        }
        if string_bytes > limits.max_string_bytes {
            bail!("source-map sidecar string byte limit exceeded");
        }
        validate_metadata_string(
            &root,
            field::PROFILE,
            &strings,
            SOURCEMAP_PROFILE,
            "profile",
        )?;
        validate_metadata_string(
            &root,
            field::PRODUCER,
            &strings,
            SOURCEMAP_PRODUCER,
            "producer",
        )?;
        validate_metadata_string(
            &root,
            field::PRODUCER_VERSION,
            &strings,
            SOURCEMAP_PRODUCER_VERSION,
            "producer_version",
        )?;

        let source_count = usize::try_from(read_fixed_u32(&root, field::SOURCE_COUNT)?)?;
        let name_count = usize::try_from(read_fixed_u32(&root, field::NAME_COUNT)?)?;
        let line_count = usize::try_from(read_fixed_u32(&root, field::LINE_COUNT)?)?;
        let segment_count = usize::try_from(read_fixed_u32(&root, field::SEGMENT_COUNT)?)?;
        if line_count > limits.max_lines || segment_count > limits.max_segments {
            bail!("source-map sidecar row limit exceeded");
        }
        if line_count == 0 {
            bail!("source-map sidecar must contain at least one generated line");
        }
        validate_count(&root, field::SOURCE_STRING, source_count, "source_string")?;
        validate_count(&root, field::NAME_STRING, name_count, "name_string")?;
        validate_count(&root, field::LINE_FIRST, line_count, "line_first_segment")?;
        validate_count(
            &root,
            field::LINE_COUNT_COLUMN,
            line_count,
            "line_segment_count",
        )?;
        for field_index in field::SEGMENT_GENERATED_COLUMN..=field::SEGMENT_NAME {
            validate_count(&root, field_index, segment_count, "segment")?;
        }
        for index in 0..source_count {
            let row = read_rep_u32(&root, field::SOURCE_STRING, index)?;
            if row != NO_ROW && row as usize >= strings.count() {
                bail!("source row {index} references an invalid string");
            }
        }
        for index in 0..name_count {
            let row = read_rep_u32(&root, field::NAME_STRING, index)?;
            if row as usize >= strings.count() {
                bail!("name row {index} references an invalid string");
            }
        }
        let source_root = read_fixed_u32(&root, field::SOURCE_ROOT)?;
        if source_root != NO_ROW && source_root as usize >= strings.count() {
            bail!("sourceRoot references an invalid string");
        }
        let mut next_segment = 0usize;
        for line in 0..line_count {
            let first = usize::try_from(read_rep_u32(&root, field::LINE_FIRST, line)?)?;
            let count = usize::try_from(read_rep_u32(&root, field::LINE_COUNT_COLUMN, line)?)?;
            if first != next_segment
                || first
                    .checked_add(count)
                    .is_none_or(|end| end > segment_count)
            {
                bail!("line {line} has an invalid segment slice");
            }
            let end = first + count;
            let mut prior = None;
            for segment in first..end {
                let generated = read_rep_u32(&root, field::SEGMENT_GENERATED_COLUMN, segment)?;
                if prior.is_some_and(|value| generated < value) {
                    bail!("line {line} has decreasing generated columns");
                }
                prior = Some(generated);
                let source = read_rep_u32(&root, field::SEGMENT_SOURCE, segment)?;
                let original_line = read_rep_u32(&root, field::SEGMENT_ORIGINAL_LINE, segment)?;
                let original_column = read_rep_u32(&root, field::SEGMENT_ORIGINAL_COLUMN, segment)?;
                let name = read_rep_u32(&root, field::SEGMENT_NAME, segment)?;
                if source == NO_ROW {
                    if original_line != NO_ROW || original_column != NO_ROW || name != NO_ROW {
                        bail!("unmapped segment {segment} has original fields");
                    }
                } else {
                    if source as usize >= source_count {
                        bail!("segment {segment} references an invalid source row");
                    }
                    if original_line == NO_ROW || original_column == NO_ROW {
                        bail!("mapped segment {segment} has missing original coordinates");
                    }
                    if name != NO_ROW && name as usize >= name_count {
                        bail!("segment {segment} references an invalid name row");
                    }
                }
            }
            next_segment = first + count;
        }
        if next_segment != segment_count {
            bail!("line slices do not cover every segment");
        }
        Ok(Self {
            root,
            source_count,
            name_count,
            line_count,
            segment_count,
            source_root: (source_root != NO_ROW).then_some(source_root),
            raw_map_digest,
            generated_source_digest,
        })
    }

    pub fn raw_map_digest(&self) -> [u8; 32] {
        self.raw_map_digest
    }

    pub fn generated_source_digest(&self) -> [u8; 32] {
        self.generated_source_digest
    }

    pub fn source_count(&self) -> usize {
        self.source_count
    }

    pub fn name_count(&self) -> usize {
        self.name_count
    }

    pub fn line_count(&self) -> usize {
        self.line_count
    }

    pub fn segment_count(&self) -> usize {
        self.segment_count
    }

    pub fn string(&self, index: usize) -> Option<&'a str> {
        let bytes = self.root.repetition_at(field::STRINGS)?.blob(index)?;
        std::str::from_utf8(bytes).ok()
    }

    pub fn source(&self, index: usize) -> Option<&'a str> {
        if index >= self.source_count {
            return None;
        }
        let row = read_rep_u32(&self.root, field::SOURCE_STRING, index).ok()?;
        (row != NO_ROW).then(|| self.string(row as usize)).flatten()
    }

    pub fn name(&self, index: usize) -> Option<&'a str> {
        if index >= self.name_count {
            return None;
        }
        self.string(read_rep_u32(&self.root, field::NAME_STRING, index).ok()? as usize)
    }

    pub fn source_root(&self) -> Option<&'a str> {
        self.source_root.and_then(|row| self.string(row as usize))
    }

    /// Return the fixed line slice in O(1) after verification.
    pub fn line_slice(&self, line: u32) -> Option<Range<usize>> {
        let line = usize::try_from(line).ok()?;
        if line >= self.line_count {
            return None;
        }
        let first =
            usize::try_from(read_rep_u32(&self.root, field::LINE_FIRST, line).ok()?).ok()?;
        let count =
            usize::try_from(read_rep_u32(&self.root, field::LINE_COUNT_COLUMN, line).ok()?).ok()?;
        Some(first..first + count)
    }

    pub fn segment(&self, index: usize) -> Option<CachedSourceMapSegment<'a>> {
        if index >= self.segment_count {
            return None;
        }
        let source_index = read_rep_u32(&self.root, field::SEGMENT_SOURCE, index).ok()?;
        let name = read_rep_u32(&self.root, field::SEGMENT_NAME, index).ok()?;
        Some(CachedSourceMapSegment {
            generated_column: read_rep_u32(&self.root, field::SEGMENT_GENERATED_COLUMN, index)
                .ok()?,
            source_index: (source_index != NO_ROW).then_some(source_index),
            source: (source_index != NO_ROW)
                .then(|| self.source(source_index as usize))
                .flatten(),
            original_line: (source_index != NO_ROW)
                .then(|| read_rep_u32(&self.root, field::SEGMENT_ORIGINAL_LINE, index).ok())
                .flatten(),
            original_column: (source_index != NO_ROW)
                .then(|| read_rep_u32(&self.root, field::SEGMENT_ORIGINAL_COLUMN, index).ok())
                .flatten(),
            name_index: (name != NO_ROW).then_some(name),
            name: (name != NO_ROW).then(|| self.name(name as usize)).flatten(),
        })
    }

    /// Return every original position at the greatest generated position not
    /// exceeding the query. Locating the group is O(log n) within a line;
    /// consuming duplicate-position results is O(result size).
    pub fn lookup_all(&self, generated: GeneratedPosition) -> Vec<OriginalPosition> {
        let Some(mut line) = usize::try_from(generated.line)
            .ok()
            .map(|line| line.min(self.line_count.saturating_sub(1)))
        else {
            return Vec::new();
        };
        loop {
            let Some(range) = self.line_slice(line as u32) else {
                return Vec::new();
            };
            let mut low = range.start;
            let mut high = range.end;
            while low < high {
                let middle = low + (high - low) / 2;
                let before_query = self.segment(middle).is_some_and(|segment| {
                    line < generated.line as usize || segment.generated_column <= generated.column
                });
                if before_query {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            if low > range.start {
                let column = self
                    .segment(low - 1)
                    .expect("verified segment row exists")
                    .generated_column;
                let mut start = low - 1;
                while start > range.start
                    && self
                        .segment(start - 1)
                        .is_some_and(|segment| segment.generated_column == column)
                {
                    start -= 1;
                }
                return (start..low)
                    .filter_map(|index| self.segment(index))
                    .filter_map(|segment| {
                        let source_index = segment.source_index?;
                        Some(OriginalPosition {
                            source: segment.source.map(str::to_owned),
                            source_root: self.source_root().map(str::to_owned),
                            source_index,
                            line: segment.original_line?,
                            column: segment.original_column?,
                            name: segment.name.map(str::to_owned),
                            name_index: segment.name_index,
                        })
                    })
                    .collect();
            }
            let Some(previous) = line.checked_sub(1) else {
                return Vec::new();
            };
            line = previous;
        }
    }

    /// Return a mapping only when the selected generated position is unique.
    /// Ambiguous duplicate-position groups deliberately return `None`.
    pub fn lookup(&self, generated: GeneratedPosition) -> Option<OriginalPosition> {
        let mut positions = self.lookup_all(generated);
        (positions.len() == 1).then(|| positions.pop()).flatten()
    }
}

pub struct CachedSourceMapSegment<'a> {
    pub generated_column: u32,
    pub source: Option<&'a str>,
    pub source_index: Option<u32>,
    pub original_line: Option<u32>,
    pub original_column: Option<u32>,
    pub name: Option<&'a str>,
    pub name_index: Option<u32>,
}

fn validate_header(
    header: &[u8; HEADER_SIZE],
    file_len: usize,
    limits: SourceMapCacheLimits,
) -> Result<()> {
    if &header[0..8] != CACHE_MAGIC {
        bail!("invalid source-map sidecar magic");
    }
    if read_u16(&header[8..10]) != CACHE_VERSION {
        bail!("unsupported source-map sidecar container version");
    }
    if read_u16(&header[10..12]) != CACHE_FLAGS_POSITIONED {
        bail!("unsupported source-map sidecar flags");
    }
    if read_u32(&header[12..16]) as usize != HEADER_SIZE {
        bail!("invalid source-map sidecar header size");
    }
    if header[152..160].iter().any(|byte| *byte != 0) {
        bail!("source-map sidecar reserved header bytes are not zero");
    }
    let state = schema_state()?;
    if header[16..48] != state.layout_hash {
        bail!("source-map sidecar layout hash does not match the embedded schema");
    }
    let payload_len_u64 = read_u64(&header[144..152]);
    if payload_len_u64 > limits.max_payload_bytes || payload_len_u64 > MAX_CACHE_BYTES {
        bail!("source-map sidecar exceeds the payload byte limit");
    }
    let payload_len = usize::try_from(payload_len_u64)?;
    if HEADER_SIZE.checked_add(payload_len) != Some(file_len) {
        bail!("source-map sidecar payload length is invalid");
    }
    Ok(())
}

fn write_atomic(path: &Path, header: &[u8; HEADER_SIZE], payload: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("source-map output path has no UTF-8 file name"))?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| {
                format!(
                    "failed to create temporary source-map file {}",
                    temporary.display()
                )
            })?;
        file.write_all(header)?;
        file.write_all(payload)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "failed to publish source-map file {} as {}",
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
    strings: &isoform::positioned::RepetitionView<'_, '_>,
    expected: &str,
    name: &str,
) -> Result<()> {
    let row = read_fixed_u32(root, field_index)? as usize;
    let actual = strings
        .blob(row)
        .and_then(|bytes| std::str::from_utf8(bytes).ok());
    if actual != Some(expected) {
        bail!("unsupported source-map {name}");
    }
    Ok(())
}

fn validate_count(
    root: &CanonicalView<'_, '_>,
    field_index: usize,
    expected: usize,
    name: &str,
) -> Result<()> {
    let actual = repetition(root, field_index, name)?.count();
    if actual != expected {
        bail!("source-map {name} column has {actual} rows, expected {expected}");
    }
    Ok(())
}

fn repetition<'l, 'a>(
    root: &'a CanonicalView<'l, 'a>,
    field_index: usize,
    name: &str,
) -> Result<isoform::positioned::RepetitionView<'l, 'a>> {
    root.repetition_at(field_index)
        .ok_or_else(|| anyhow!("missing source-map {name} column"))
}

fn read_fixed_u32(root: &CanonicalView<'_, '_>, field_index: usize) -> Result<u32> {
    let bytes = root
        .fixed_at(field_index)
        .ok_or_else(|| anyhow!("missing source-map fixed field {field_index}"))?;
    Ok(read_u32(bytes))
}

fn read_rep_u32(root: &CanonicalView<'_, '_>, field_index: usize, index: usize) -> Result<u32> {
    let bytes = repetition(root, field_index, "fixed")?
        .fixed(index)
        .ok_or_else(|| anyhow!("missing row {index} in source-map field {field_index}"))?;
    Ok(read_u32(bytes))
}

fn fixed_u32(value: u32) -> OwnedValue {
    OwnedValue::Fixed(value.to_le_bytes().to_vec())
}

fn repetition_u32(values: impl IntoIterator<Item = u32>) -> OwnedValue {
    OwnedValue::Repetition(values.into_iter().map(fixed_u32).collect())
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

    use super::*;
    use crate::sourcemap::SourceMapLimits;

    fn map(value: &str) -> SourceMap {
        SourceMap::parse(value.as_bytes(), SourceMapLimits::default()).unwrap()
    }

    #[test]
    fn positioned_sidecar_round_trips_line_slice_and_binary_lookup() {
        let source_map = map(
            r#"{"version":3,"sourceRoot":"../src/","sources":[null,"input.js"],"names":["answer"],"mappings":"AAAA,CCACA;AACA"}"#,
        );
        let directory = tempdir().unwrap();
        let path = directory.path().join("bundle.astsm");
        source_map
            .write_positioned(&path, b"generated\ncode")
            .unwrap();
        let mapped = MappedSourceMap::open_for_source(&path, b"generated\ncode").unwrap();
        assert_eq!(mapped.raw_map_digest(), source_map.digest());
        let view = mapped.verify().unwrap();
        assert_eq!(view.source_count(), 2);
        assert_eq!(view.source(0), None);
        assert_eq!(view.source(1), Some("input.js"));
        assert_eq!(view.source_root(), Some("../src/"));
        assert_eq!(view.line_slice(0), Some(0..2));
        assert_eq!(view.line_slice(1), Some(2..3));
        let position = view
            .lookup(GeneratedPosition { line: 0, column: 1 })
            .unwrap();
        assert_eq!(position.source.as_deref(), Some("input.js"));
        assert_eq!(position.source_root.as_deref(), Some("../src/"));
        assert_eq!(position.name.as_deref(), Some("answer"));
    }

    #[test]
    fn positioned_sidecar_bytes_are_deterministic_and_indexed_maps_are_rejected() {
        let source_map =
            map(r#"{"version":3,"sources":["input.js"],"names":[],"mappings":"AAAA"}"#);
        assert_eq!(
            source_map.encode_positioned().unwrap(),
            source_map.encode_positioned().unwrap()
        );
        let indexed = map(
            r#"{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a.js"],"names":[],"mappings":"AAAA"}}]}"#,
        );
        let error = indexed.encode_positioned().unwrap_err();
        assert!(error
            .to_string()
            .contains("indexed source maps cannot be encoded"));
    }

    #[test]
    fn generated_source_digest_is_a_binding_not_just_metadata() {
        let source_map =
            map(r#"{"version":3,"sources":["input.js"],"names":[],"mappings":"AAAA"}"#);
        let directory = tempdir().unwrap();
        let path = directory.path().join("bundle.astsm");
        source_map.write_astsm(&path, b"generated").unwrap();
        assert!(MappedSourceMap::open_for_source(&path, b"different")
            .unwrap_err()
            .to_string()
            .contains("generated source digest mismatch"));
    }

    #[test]
    fn payload_corruption_and_cross_line_ambiguity_are_preserved() {
        let source_map =
            map(r#"{"version":3,"sources":["a","b"],"names":[],"mappings":"AAAA,ACAA;;"}"#);
        let directory = tempdir().unwrap();
        let path = directory.path().join("bundle.astsm");
        source_map.write_positioned(&path, b"generated").unwrap();

        let mapped = MappedSourceMap::open_for_source(&path, b"generated").unwrap();
        let view = mapped.verify().unwrap();
        let positions = view.lookup_all(GeneratedPosition {
            line: 2,
            column: 100,
        });
        assert_eq!(positions.len(), 2);
        assert_eq!(positions[0].source.as_deref(), Some("a"));
        assert_eq!(positions[1].source.as_deref(), Some("b"));
        drop(view);
        drop(mapped);

        let mut bytes = fs::read(&path).unwrap();
        bytes[HEADER_SIZE] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(MappedSourceMap::open(&path)
            .unwrap_err()
            .to_string()
            .contains("payload digest mismatch"));
    }
}
