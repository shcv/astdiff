//! Bounded Source Map v3 parsing, lookup, and composition.

use std::cmp::Ordering;

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub mod cache;

#[derive(Debug, Clone, Copy)]
pub struct SourceMapLimits {
    pub max_bytes: usize,
    pub max_sources: usize,
    pub max_names: usize,
    pub max_lines: usize,
    pub max_segments: usize,
    pub max_sections: usize,
    pub max_depth: usize,
    pub allow_sources_content: bool,
}

impl Default for SourceMapLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024,
            max_sources: 1_000_000,
            max_names: 1_000_000,
            max_lines: 20_000_000,
            max_segments: 100_000_000,
            max_sections: 100_000,
            max_depth: 8,
            allow_sources_content: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratedPosition {
    pub line: u32,
    /// UTF-16 code-unit column, as defined by Source Map v3.
    pub column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalPosition {
    /// The nullable raw `sources[source_index]` entry.  It is deliberately
    /// kept separate from `source_root`; concatenating the two loses the
    /// distinction between a null source and an empty source string.
    pub source: Option<String>,
    /// The nullable map-level `sourceRoot` value, if present.
    pub source_root: Option<String>,
    pub source_index: u32,
    pub line: u32,
    pub column: u32,
    pub name: Option<String>,
    pub name_index: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SourceMap {
    digest: [u8; 32],
    kind: MapKind,
    segment_count: usize,
}

#[derive(Debug, Clone)]
enum MapKind {
    Basic(BasicMap),
    Indexed(Vec<Section>),
}

#[derive(Debug, Clone)]
struct BasicMap {
    sources: Vec<Option<String>>,
    source_root: Option<String>,
    names: Vec<String>,
    lines: Vec<LineRange>,
    segments: Vec<Segment>,
}

#[derive(Debug, Clone, Copy)]
struct LineRange {
    first: usize,
    count: usize,
}

#[derive(Debug, Clone, Copy)]
struct Segment {
    generated_column: u32,
    original: Option<OriginalFields>,
}

#[derive(Debug, Clone, Copy)]
struct OriginalFields {
    source: u32,
    line: u32,
    column: u32,
    name: Option<u32>,
}

#[derive(Debug, Clone)]
struct Section {
    offset: GeneratedPosition,
    map: SourceMap,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMap {
    version: u32,
    #[serde(default)]
    source_root: Option<String>,
    sources: Option<Vec<Option<String>>>,
    #[serde(default)]
    sources_content: Option<Vec<Option<String>>>,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    mappings: Option<String>,
    #[serde(default)]
    sections: Option<Vec<RawSection>>,
    #[serde(default)]
    ignore_list: Option<Vec<u32>>,
    #[serde(default, rename = "x_google_ignoreList")]
    x_google_ignore_list: Option<Vec<u32>>,
}

#[derive(Debug, Deserialize)]
struct RawSection {
    offset: RawOffset,
    map: Box<RawMap>,
}

#[derive(Debug, Deserialize)]
struct RawOffset {
    line: u32,
    column: u32,
}

#[derive(Default)]
struct ParseBudget {
    sources: usize,
    names: usize,
    lines: usize,
    segments: usize,
    sections: usize,
}

impl SourceMap {
    pub fn parse(bytes: &[u8], limits: SourceMapLimits) -> Result<Self> {
        if bytes.len() > limits.max_bytes {
            bail!("source map exceeds the byte limit");
        }
        let raw: RawMap = serde_json::from_slice(bytes)?;
        let mut budget = ParseBudget::default();
        let mut map = parse_raw(raw, &limits, &mut budget, 0)?;
        map.digest = Sha256::digest(bytes).into();
        Ok(map)
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn segment_count(&self) -> usize {
        self.segment_count
    }

    pub fn lookup(&self, generated: GeneratedPosition) -> Option<OriginalPosition> {
        let mut positions = self.lookup_all(generated);
        (positions.len() == 1).then(|| positions.pop()).flatten()
    }

    /// Return every original position at the greatest generated position not
    /// exceeding `generated`, as required by ECMA-426. Duplicate generated
    /// positions are preserved instead of being guessed into one mapping.
    pub fn lookup_all(&self, generated: GeneratedPosition) -> Vec<OriginalPosition> {
        match self.lookup_group(generated) {
            LookupGroup::None => Vec::new(),
            LookupGroup::Found { positions, .. } => positions,
        }
    }

    pub fn compose_lookup(
        outer: &SourceMap,
        inner: &SourceMap,
        generated: GeneratedPosition,
    ) -> Option<OriginalPosition> {
        let mut positions = Self::compose_lookup_all(outer, inner, generated);
        (positions.len() == 1).then(|| positions.pop()).flatten()
    }

    /// Compose all mappings at the selected outer and inner generated
    /// positions. The caller chooses the map pair; no source URL is fetched or
    /// inferred from the outer mapping.
    pub fn compose_lookup_all(
        outer: &SourceMap,
        inner: &SourceMap,
        generated: GeneratedPosition,
    ) -> Vec<OriginalPosition> {
        let mut output = Vec::new();
        for intermediate in outer.lookup_all(generated) {
            for mut original in inner.lookup_all(GeneratedPosition {
                line: intermediate.line,
                column: intermediate.column,
            }) {
                if original.name.is_none() {
                    original.name = intermediate.name.clone();
                    original.name_index = intermediate.name_index;
                }
                output.push(original);
            }
        }
        output
    }

    fn lookup_group(&self, generated: GeneratedPosition) -> LookupGroup {
        match &self.kind {
            MapKind::Basic(map) => map.lookup_group(generated),
            MapKind::Indexed(sections) => {
                let end = sections.partition_point(|section| {
                    position_cmp(section.offset, generated) != Ordering::Greater
                });
                let mut best_position = None;
                let mut best_positions = Vec::new();
                for section in sections[..end].iter().rev() {
                    let Some(line) = generated.line.checked_sub(section.offset.line) else {
                        continue;
                    };
                    let Some(column) = (if line == 0 {
                        generated.column.checked_sub(section.offset.column)
                    } else {
                        Some(generated.column)
                    }) else {
                        continue;
                    };
                    let LookupGroup::Found {
                        generated: local,
                        positions,
                    } = section.map.lookup_group(GeneratedPosition { line, column })
                    else {
                        continue;
                    };
                    let Ok(global) = add_section_offset(section.offset, local) else {
                        continue;
                    };
                    match best_position.map(|best| position_cmp(global, best)) {
                        None | Some(Ordering::Greater) => {
                            best_position = Some(global);
                            best_positions = positions;
                        }
                        Some(Ordering::Equal) => best_positions.extend(positions),
                        Some(Ordering::Less) => break,
                    }
                }
                best_position.map_or(LookupGroup::None, |generated| LookupGroup::Found {
                    generated,
                    positions: best_positions,
                })
            }
        }
    }

    fn last_generated_position(&self) -> Result<Option<GeneratedPosition>> {
        match &self.kind {
            MapKind::Basic(map) => Ok(map.last_generated_position()),
            MapKind::Indexed(sections) => {
                for section in sections.iter().rev() {
                    if let Some(local) = section.map.last_generated_position()? {
                        return Ok(Some(add_section_offset(section.offset, local)?));
                    }
                }
                Ok(None)
            }
        }
    }
}

enum LookupGroup {
    None,
    Found {
        generated: GeneratedPosition,
        positions: Vec<OriginalPosition>,
    },
}

/// Convert sorted or unsorted UTF-8 byte offsets to Source Map v3 coordinates
/// in one pass over the generated source.
pub fn positions_for_byte_offsets(source: &str, offsets: &[u64]) -> Result<Vec<GeneratedPosition>> {
    let mut requested = offsets
        .iter()
        .enumerate()
        .map(|(index, offset)| {
            usize::try_from(*offset)
                .map(|offset| (offset, index))
                .map_err(|_| anyhow!("source byte offset is out of range"))
        })
        .collect::<Result<Vec<_>>>()?;
    requested.sort_unstable();
    if requested
        .last()
        .is_some_and(|(offset, _)| *offset > source.len())
    {
        bail!("source byte offset exceeds source length");
    }
    let mut output = vec![GeneratedPosition { line: 0, column: 0 }; offsets.len()];
    let (mut next, mut line, mut column, mut after_cr) = (0usize, 0u32, 0u32, false);
    for (byte_offset, character) in source.char_indices() {
        while requested
            .get(next)
            .is_some_and(|(offset, _)| *offset == byte_offset)
        {
            output[requested[next].1] = GeneratedPosition { line, column };
            next += 1;
        }
        if requested
            .get(next)
            .is_some_and(|(offset, _)| *offset < byte_offset)
        {
            bail!("source byte offset is not a UTF-8 boundary");
        }
        match character {
            '\r' => {
                line = line
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("generated line overflow"))?;
                column = 0;
                after_cr = true;
            }
            '\n' if after_cr => after_cr = false,
            '\n' | '\u{2028}' | '\u{2029}' => {
                line = line
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("generated line overflow"))?;
                column = 0;
                after_cr = false;
            }
            _ => {
                column = column
                    .checked_add(character.len_utf16() as u32)
                    .ok_or_else(|| anyhow!("generated column overflow"))?;
                after_cr = false;
            }
        }
    }
    while requested
        .get(next)
        .is_some_and(|(offset, _)| *offset == source.len())
    {
        output[requested[next].1] = GeneratedPosition { line, column };
        next += 1;
    }
    if next != requested.len() {
        bail!("source byte offset is not a UTF-8 boundary");
    }
    Ok(output)
}

impl BasicMap {
    fn lookup_group(&self, generated: GeneratedPosition) -> LookupGroup {
        let Some(mut line) = usize::try_from(generated.line)
            .ok()
            .map(|line| line.min(self.lines.len().saturating_sub(1)))
        else {
            return LookupGroup::None;
        };
        loop {
            let range = self.lines[line];
            let segments = &self.segments[range.first..range.first + range.count];
            let end = if line == generated.line as usize {
                segments.partition_point(|segment| segment.generated_column <= generated.column)
            } else {
                segments.len()
            };
            if end > 0 {
                let column = segments[end - 1].generated_column;
                let start =
                    segments[..end].partition_point(|segment| segment.generated_column < column);
                let positions = segments[start..end]
                    .iter()
                    .filter_map(|segment| segment.original)
                    .map(|original| OriginalPosition {
                        source: self.sources[original.source as usize].clone(),
                        source_root: self.source_root.clone(),
                        source_index: original.source,
                        line: original.line,
                        column: original.column,
                        name: original.name.map(|name| self.names[name as usize].clone()),
                        name_index: original.name,
                    })
                    .collect();
                return LookupGroup::Found {
                    generated: GeneratedPosition {
                        line: line as u32,
                        column,
                    },
                    positions,
                };
            }
            let Some(previous) = line.checked_sub(1) else {
                return LookupGroup::None;
            };
            line = previous;
        }
    }

    fn last_generated_position(&self) -> Option<GeneratedPosition> {
        self.lines
            .iter()
            .enumerate()
            .rev()
            .find_map(|(line, range)| {
                (range.count > 0).then(|| GeneratedPosition {
                    line: line as u32,
                    column: self.segments[range.first + range.count - 1].generated_column,
                })
            })
    }
}

fn parse_raw(
    raw: RawMap,
    limits: &SourceMapLimits,
    budget: &mut ParseBudget,
    depth: usize,
) -> Result<SourceMap> {
    if depth > limits.max_depth || raw.version != 3 {
        bail!("unsupported source map version or section depth");
    }
    match (raw.mappings, raw.sections) {
        (Some(mappings), None) => {
            let sources = raw
                .sources
                .ok_or_else(|| anyhow!("basic source map is missing its sources array"))?;
            if raw.sources_content.is_some() && !limits.allow_sources_content {
                bail!("sourcesContent requires explicit permission");
            }
            if let Some(content) = &raw.sources_content {
                if content.len() > sources.len() {
                    bail!("sourcesContent is longer than sources");
                }
            }
            let ignore_list = raw
                .ignore_list
                .as_deref()
                .or(raw.x_google_ignore_list.as_deref())
                .unwrap_or_default();
            if ignore_list
                .iter()
                .any(|index| *index as usize >= sources.len())
            {
                bail!("source map ignore-list index is out of range");
            }
            budget.sources = checked_total(budget.sources, sources.len(), limits.max_sources)?;
            budget.names = checked_total(budget.names, raw.names.len(), limits.max_names)?;
            let source_root = raw.source_root;
            let (lines, segments) =
                decode_mappings(&mappings, sources.len(), raw.names.len(), limits, budget)?;
            Ok(SourceMap {
                digest: [0; 32],
                segment_count: segments.len(),
                kind: MapKind::Basic(BasicMap {
                    sources,
                    source_root,
                    names: raw.names,
                    lines,
                    segments,
                }),
            })
        }
        (None, Some(raw_sections)) => {
            budget.sections =
                checked_total(budget.sections, raw_sections.len(), limits.max_sections)?;
            let mut sections = Vec::with_capacity(raw_sections.len());
            let mut prior_offset = None;
            let mut prior_last_mapping = None;
            let mut segment_count = 0usize;
            for raw_section in raw_sections {
                let offset = GeneratedPosition {
                    line: raw_section.offset.line,
                    column: raw_section.offset.column,
                };
                if prior_offset
                    .is_some_and(|value| position_cmp(value, offset) == Ordering::Greater)
                {
                    bail!("source map sections are not ordered");
                }
                if prior_last_mapping
                    .is_some_and(|value| position_cmp(value, offset) == Ordering::Greater)
                {
                    bail!("source map sections overlap");
                }
                prior_offset = Some(offset);
                let map = parse_raw(*raw_section.map, limits, budget, depth + 1)?;
                if let Some(local_last) = map.last_generated_position()? {
                    prior_last_mapping = Some(add_section_offset(offset, local_last)?);
                }
                segment_count = segment_count
                    .checked_add(map.segment_count)
                    .ok_or_else(|| anyhow!("source map segment count overflow"))?;
                sections.push(Section { offset, map });
            }
            Ok(SourceMap {
                digest: [0; 32],
                kind: MapKind::Indexed(sections),
                segment_count,
            })
        }
        _ => bail!("source map must contain exactly one of mappings or sections"),
    }
}

fn decode_mappings(
    mappings: &str,
    source_count: usize,
    name_count: usize,
    limits: &SourceMapLimits,
    budget: &mut ParseBudget,
) -> Result<(Vec<LineRange>, Vec<Segment>)> {
    let mut lines = Vec::new();
    let mut segments = Vec::new();
    let mut source = 0i64;
    let mut original_line = 0i64;
    let mut original_column = 0i64;
    let mut name = 0i64;
    for encoded_line in mappings.split(';') {
        budget.lines = checked_total(budget.lines, 1, limits.max_lines)?;
        let first = segments.len();
        let mut generated_column = 0i64;
        let mut decreasing = false;
        let mut prior_column = None;
        if !encoded_line.is_empty() {
            for encoded_segment in encoded_line.split(',') {
                if encoded_segment.is_empty() {
                    bail!("source map contains an empty segment");
                }
                budget.segments = checked_total(budget.segments, 1, limits.max_segments)?;
                let fields = decode_segment(encoded_segment)?;
                if !matches!(fields.len(), 1 | 4 | 5) {
                    bail!("source map segment must contain 1, 4, or 5 fields");
                }
                generated_column = checked_delta(generated_column, fields[0])?;
                let generated = u32::try_from(generated_column)
                    .map_err(|_| anyhow!("generated source map column is out of range"))?;
                decreasing |= prior_column.is_some_and(|prior| generated < prior);
                prior_column = Some(generated);
                let original = if fields.len() == 1 {
                    None
                } else {
                    source = checked_delta(source, fields[1])?;
                    original_line = checked_delta(original_line, fields[2])?;
                    original_column = checked_delta(original_column, fields[3])?;
                    let source_index = u32::try_from(source)
                        .map_err(|_| anyhow!("source index is out of range"))?;
                    if source_index as usize >= source_count {
                        bail!("source map source index is out of range");
                    }
                    let name_index = if fields.len() == 5 {
                        name = checked_delta(name, fields[4])?;
                        let index = u32::try_from(name)
                            .map_err(|_| anyhow!("name index is out of range"))?;
                        if index as usize >= name_count {
                            bail!("source map name index is out of range");
                        }
                        Some(index)
                    } else {
                        None
                    };
                    Some(OriginalFields {
                        source: source_index,
                        line: u32::try_from(original_line)
                            .map_err(|_| anyhow!("original line is out of range"))?,
                        column: u32::try_from(original_column)
                            .map_err(|_| anyhow!("original column is out of range"))?,
                        name: name_index,
                    })
                };
                segments.push(Segment {
                    generated_column: generated,
                    original,
                });
            }
        }
        if decreasing {
            segments[first..].sort_by_key(|segment| segment.generated_column);
        }
        lines.push(LineRange {
            first,
            count: segments.len() - first,
        });
    }
    Ok((lines, segments))
}

fn decode_segment(value: &str) -> Result<Vec<i64>> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(5);
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let mut payload = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *bytes
                .get(cursor)
                .ok_or_else(|| anyhow!("truncated source map VLQ"))?;
            cursor += 1;
            let digit = base64_value(byte).ok_or_else(|| anyhow!("invalid source map base64"))?;
            let chunk = u64::from(digit & 31);
            payload = payload
                .checked_add(
                    chunk
                        .checked_shl(shift)
                        .ok_or_else(|| anyhow!("source map VLQ overflow"))?,
                )
                .ok_or_else(|| anyhow!("source map VLQ overflow"))?;
            if digit & 32 == 0 {
                break;
            }
            shift = shift
                .checked_add(5)
                .ok_or_else(|| anyhow!("source map VLQ overflow"))?;
            if shift > 35 {
                bail!("source map VLQ exceeds 32-bit range");
            }
        }
        let negative = payload & 1 != 0;
        let magnitude = payload >> 1;
        if magnitude > (i32::MAX as u64 + 1) || (!negative && magnitude > i32::MAX as u64) {
            bail!("source map VLQ exceeds 32-bit range");
        }
        let signed = if negative && magnitude == 0 {
            i64::from(i32::MIN)
        } else {
            if magnitude >= (1u64 << 31) {
                bail!("source map VLQ exceeds 32-bit range");
            }
            let magnitude = i64::try_from(magnitude).expect("31-bit magnitude fits i64");
            if negative {
                -magnitude
            } else {
                magnitude
            }
        };
        output.push(signed);
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn checked_delta(base: i64, delta: i64) -> Result<i64> {
    let value = base
        .checked_add(delta)
        .ok_or_else(|| anyhow!("source map delta overflow"))?;
    if !(0..=i64::from(u32::MAX)).contains(&value) {
        bail!("source map cumulative value is out of range");
    }
    Ok(value)
}

fn checked_total(current: usize, added: usize, limit: usize) -> Result<usize> {
    let total = current
        .checked_add(added)
        .ok_or_else(|| anyhow!("source map resource count overflow"))?;
    if total > limit {
        bail!("source map resource limit exceeded");
    }
    Ok(total)
}

fn position_cmp(left: GeneratedPosition, right: GeneratedPosition) -> Ordering {
    (left.line, left.column).cmp(&(right.line, right.column))
}

fn add_section_offset(
    offset: GeneratedPosition,
    local: GeneratedPosition,
) -> Result<GeneratedPosition> {
    let line = offset
        .line
        .checked_add(local.line)
        .ok_or_else(|| anyhow!("indexed source-map line overflow"))?;
    let column = if local.line == 0 {
        offset
            .column
            .checked_add(local.column)
            .ok_or_else(|| anyhow!("indexed source-map column overflow"))?
    } else {
        local.column
    };
    Ok(GeneratedPosition { line, column })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> SourceMap {
        SourceMap::parse(value.as_bytes(), SourceMapLimits::default()).unwrap()
    }

    #[test]
    fn basic_map_decodes_lines_names_and_unmapped_segments() {
        let map = parse(
            r#"{"version":3,"sources":["input.js"],"names":["answer"],"mappings":"AAAAA,C;AACA"}"#,
        );
        let first = map
            .lookup(GeneratedPosition { line: 0, column: 0 })
            .unwrap();
        assert_eq!(first.source.as_deref(), Some("input.js"));
        assert_eq!(first.name.as_deref(), Some("answer"));
        assert!(map
            .lookup(GeneratedPosition { line: 0, column: 1 })
            .is_none());
        assert_eq!(
            map.lookup(GeneratedPosition { line: 1, column: 0 })
                .unwrap()
                .line,
            1
        );
    }

    #[test]
    fn indexed_sections_apply_line_and_first_line_column_offsets() {
        let map = parse(
            r#"{"version":3,"sections":[{"offset":{"line":0,"column":4},"map":{"version":3,"sources":["a.js"],"names":[],"mappings":"AAAA"}},{"offset":{"line":2,"column":0},"map":{"version":3,"sources":["b.js"],"names":[],"mappings":"AAAA"}}]}"#,
        );
        assert!(map
            .lookup(GeneratedPosition { line: 0, column: 3 })
            .is_none());
        assert_eq!(
            map.lookup(GeneratedPosition { line: 0, column: 4 })
                .unwrap()
                .source,
            Some("a.js".to_string())
        );
        assert_eq!(
            map.lookup(GeneratedPosition { line: 2, column: 0 })
                .unwrap()
                .source,
            Some("b.js".to_string())
        );
    }

    #[test]
    fn composition_uses_intermediate_coordinates() {
        let outer = parse(r#"{"version":3,"sources":["mid.js"],"names":[],"mappings":"AACA"}"#);
        let inner =
            parse(r#"{"version":3,"sources":["original.js"],"names":[],"mappings":";AAEA"}"#);
        let result =
            SourceMap::compose_lookup(&outer, &inner, GeneratedPosition { line: 0, column: 0 })
                .unwrap();
        assert_eq!(result.source.as_deref(), Some("original.js"));
        assert_eq!(result.line, 2);
    }

    #[test]
    fn malformed_vlq_indexes_ordering_and_limits_are_rejected() {
        for value in [
            r#"{"version":3,"sources":[],"names":[],"mappings":"g"}"#,
            r#"{"version":3,"sources":[],"names":[],"mappings":"AAAA"}"#,
            r#"{"version":3,"names":[],"mappings":"A"}"#,
            r#"{"version":3,"sources":["a"],"names":[],"mappings":"AAAB"}"#,
            r#"{"version":3,"sections":[{"offset":{"line":1,"column":0},"map":{"version":3,"sources":["a"],"names":[],"mappings":"AAAA"}},{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["b"],"names":[],"mappings":"AAAA"}}]}"#,
            r#"{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a"],"names":[],"mappings":"AAAA,oGAAA"}},{"offset":{"line":0,"column":50},"map":{"version":3,"sources":["b"],"names":[],"mappings":"AAAA"}}]}"#,
        ] {
            assert!(SourceMap::parse(value.as_bytes(), SourceMapLimits::default()).is_err());
        }
        let limits = SourceMapLimits {
            max_segments: 1,
            ..SourceMapLimits::default()
        };
        assert!(SourceMap::parse(
            br#"{"version":3,"sources":["a"],"names":[],"mappings":"AAAA,CAAA"}"#,
            limits,
        )
        .is_err());
    }

    #[test]
    fn sources_content_is_opt_in_and_not_retained() {
        let bytes = br#"{"version":3,"sources":["a"],"sourcesContent":["synthetic"],"names":[],"mappings":"AAAA"}"#;
        assert!(SourceMap::parse(bytes, SourceMapLimits::default()).is_err());
        let map = SourceMap::parse(
            bytes,
            SourceMapLimits {
                allow_sources_content: true,
                ..SourceMapLimits::default()
            },
        )
        .unwrap();
        assert_eq!(map.segment_count(), 1);

        let shorter = br#"{"version":3,"sources":[null,"b"],"sourcesContent":[null],"names":[],"mappings":"AAAA"}"#;
        let map = SourceMap::parse(
            shorter,
            SourceMapLimits {
                allow_sources_content: true,
                ..SourceMapLimits::default()
            },
        )
        .unwrap();
        let position = map
            .lookup(GeneratedPosition { line: 0, column: 0 })
            .unwrap();
        assert_eq!(position.source, None);
    }

    #[test]
    fn lookup_preserves_duplicate_positions_and_falls_back_across_lines() {
        let duplicate =
            parse(r#"{"version":3,"sources":["a","b"],"names":[],"mappings":"AAAA,ACAA"}"#);
        let all = duplicate.lookup_all(GeneratedPosition { line: 0, column: 0 });
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].source.as_deref(), Some("a"));
        assert_eq!(all[1].source.as_deref(), Some("b"));
        assert!(duplicate
            .lookup(GeneratedPosition { line: 0, column: 0 })
            .is_none());

        let prior_line = parse(r#"{"version":3,"sources":["a"],"names":[],"mappings":"AAAA;;"}"#);
        assert_eq!(
            prior_line
                .lookup(GeneratedPosition {
                    line: 2,
                    column: 100
                })
                .unwrap()
                .source
                .as_deref(),
            Some("a")
        );

        let decreasing =
            parse(r#"{"version":3,"sources":["a"],"names":[],"mappings":"IAAA,FAAA"}"#);
        assert_eq!(
            decreasing
                .lookup(GeneratedPosition { line: 0, column: 3 })
                .unwrap()
                .source
                .as_deref(),
            Some("a")
        );
    }

    #[test]
    fn indexed_empty_sections_may_share_an_offset() {
        let map = parse(
            r#"{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":[],"names":[],"mappings":""}},{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a"],"names":[],"mappings":"AAAA"}}]}"#,
        );
        assert_eq!(
            map.lookup(GeneratedPosition { line: 0, column: 0 })
                .unwrap()
                .source
                .as_deref(),
            Some("a")
        );

        let duplicate = parse(
            r#"{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a"],"names":[],"mappings":"AAAA"}},{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["b"],"names":[],"mappings":"AAAA"}}]}"#,
        );
        let positions = duplicate.lookup_all(GeneratedPosition { line: 0, column: 0 });
        assert_eq!(positions.len(), 2);
        assert_eq!(positions[0].source.as_deref(), Some("b"));
        assert_eq!(positions[1].source.as_deref(), Some("a"));
    }

    #[test]
    fn byte_offsets_convert_to_utf16_coordinates_in_one_pass() {
        let source = "a😀b\r\nπc\u{2028}z";
        let offsets = [0, 1, 5, 6, 8, 10, 11, source.len() as u64];
        let positions = positions_for_byte_offsets(source, &offsets).unwrap();
        assert_eq!(positions[0], GeneratedPosition { line: 0, column: 0 });
        assert_eq!(positions[1], GeneratedPosition { line: 0, column: 1 });
        assert_eq!(positions[2], GeneratedPosition { line: 0, column: 3 });
        assert_eq!(positions[4], GeneratedPosition { line: 1, column: 0 });
        assert_eq!(positions[5], GeneratedPosition { line: 1, column: 1 });
        assert_eq!(positions[6], GeneratedPosition { line: 1, column: 2 });
        assert_eq!(positions[7], GeneratedPosition { line: 2, column: 1 });
    }
}
