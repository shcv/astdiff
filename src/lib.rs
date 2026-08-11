pub mod analysis;
pub mod canonicalizer;
pub mod cli;
pub mod diff;
pub mod dump;
pub mod lineage;
pub mod mapping;
pub mod naming;
pub mod parser;
pub mod pretty;
pub mod render;
pub mod scope;
pub mod sourcemap;

use anyhow::Result;
use std::fs;
use std::io::Read;

use canonicalizer::Canonicalizer;
pub use cli::{AnalysisQuery, Args, Mode, NameCommand, QueryType, SourceMapCommand};
use mapping::MappingGenerator;
use parser::JsParser;
use pretty::PrettyPrinter;
use scope::ScopeAnalyzer;

pub fn run(args: Args) -> Result<()> {
    match args.mode() {
        Mode::Map(command) => run_source_map(command),
        Mode::Lineage {
            source_file,
            target_file,
            source_map_source,
            source_map_target,
            allow_sources_content,
            output,
            min_score_bps,
            min_margin_bps,
            max_candidates,
        } => run_lineage(LineageRunOptions {
            source_file: &source_file,
            target_file: &target_file,
            output: &output,
            source_map_source: source_map_source.as_deref(),
            source_map_target: source_map_target.as_deref(),
            allow_sources_content,
            min_score_bps,
            min_margin_bps,
            max_candidates,
        }),
        Mode::Names(command) => run_names(command),
        Mode::Analyze { input_file, output } => run_analyze(&input_file, &output),
        Mode::Analysis {
            analysis_file,
            query,
        } => run_analysis_query(&analysis_file, query),
        Mode::Diff {
            file1,
            file2,
            format,
            export_mappings,
            summary,
            verbose,
            fingerprints,
            compact,
            lite,
            dump,
        } => run_diff(
            file1,
            file2,
            DiffOptions {
                format,
                export_mappings,
                summary,
                verbose,
                fingerprints,
                compact,
                lite,
                dump,
            },
        ),
        Mode::Canonicalize {
            input_file,
            preserve_comments,
            pretty,
        } => run_canonicalize(&input_file, preserve_comments, pretty, args.verbose),
        Mode::GenerateMapping {
            input_file,
            preserve_comments,
            pretty,
        } => run_generate_mapping(&input_file, preserve_comments, pretty, args.verbose),
        Mode::ApplyMapping {
            input_file,
            map_file,
            preserve_comments,
            pretty,
        } => run_apply_mapping(
            &input_file,
            &map_file,
            preserve_comments,
            pretty,
            args.verbose,
        ),
        Mode::Inspect {
            input_file,
            compare_file,
            identifier,
        } => run_inspect(
            &input_file,
            compare_file.as_ref(),
            &identifier,
            args.verbose,
        ),
        Mode::Query {
            dump_file,
            query_type,
        } => run_query(&dump_file, query_type),
        Mode::Load { dump_file, format } => run_load(&dump_file, &format),
    }
}

fn run_source_map(command: SourceMapCommand) -> Result<()> {
    use sourcemap::{GeneratedPosition, SourceMap, SourceMapLimits};

    let parse = |path: &std::path::Path, allow_sources_content: bool| -> Result<SourceMap> {
        let limits = SourceMapLimits {
            allow_sources_content,
            ..SourceMapLimits::default()
        };
        let bytes = read_bounded_file(path, limits.max_bytes as u64, "source map")?;
        SourceMap::parse(&bytes, limits)
    };
    match command {
        SourceMapCommand::Validate {
            map_file,
            allow_sources_content,
        } => {
            let map = parse(&map_file, allow_sources_content)?;
            println!(
                "{}",
                serde_json::json!({
                    "valid": true,
                    "version": 3,
                    "coordinate_basis": "zero_based_utf16",
                    "map_digest": analysis::StableId(map.digest()).to_hex(),
                    "segments": map.segment_count(),
                })
            );
        }
        SourceMapCommand::Lookup {
            map_file,
            line,
            column,
            allow_sources_content,
            include_source_names,
        } => {
            let map = parse(&map_file, allow_sources_content)?;
            println!(
                "{}",
                source_map_positions_json(
                    map.lookup_all(GeneratedPosition { line, column }),
                    include_source_names,
                )
            );
        }
        SourceMapCommand::ComposeLookup {
            outer_map,
            inner_map,
            line,
            column,
            allow_sources_content,
            include_source_names,
        } => {
            let outer = parse(&outer_map, allow_sources_content)?;
            let inner = parse(&inner_map, allow_sources_content)?;
            println!(
                "{}",
                source_map_positions_json(
                    SourceMap::compose_lookup_all(
                        &outer,
                        &inner,
                        GeneratedPosition { line, column },
                    ),
                    include_source_names,
                )
            );
        }
        SourceMapCommand::Cache {
            map_file,
            generated_file,
            output,
            allow_sources_content,
        } => {
            let map = parse(&map_file, allow_sources_content)?;
            let generated =
                read_bounded_file(&generated_file, 512 * 1024 * 1024, "generated source")?;
            map.write_positioned(&output, &generated)?;
            println!(
                "{}",
                serde_json::json!({
                    "cached": true,
                    "segments": map.segment_count(),
                    "map_digest": analysis::StableId(map.digest()).to_hex(),
                })
            );
        }
        SourceMapCommand::CacheValidate {
            cache_file,
            generated_file,
        } => {
            let generated =
                read_bounded_file(&generated_file, 512 * 1024 * 1024, "generated source")?;
            let mapped =
                sourcemap::cache::MappedSourceMap::open_for_source(&cache_file, &generated)?;
            let view = mapped.verify()?;
            println!(
                "{}",
                serde_json::json!({
                    "valid": true,
                    "sources": view.source_count(),
                    "names": view.name_count(),
                    "lines": view.line_count(),
                    "segments": view.segment_count(),
                    "map_digest": analysis::StableId(view.raw_map_digest()).to_hex(),
                })
            );
        }
        SourceMapCommand::CacheLookup {
            cache_file,
            generated_file,
            line,
            column,
            include_source_names,
        } => {
            let generated =
                read_bounded_file(&generated_file, 512 * 1024 * 1024, "generated source")?;
            let mapped =
                sourcemap::cache::MappedSourceMap::open_for_source(&cache_file, &generated)?;
            let view = mapped.verify()?;
            println!(
                "{}",
                source_map_positions_json(
                    view.lookup_all(GeneratedPosition { line, column }),
                    include_source_names,
                )
            );
        }
    }
    Ok(())
}

fn read_bounded_file(path: &std::path::Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("{label} exceeds the byte limit");
    }
    Ok(bytes)
}

fn source_map_positions_json(
    positions: Vec<sourcemap::OriginalPosition>,
    include_source_names: bool,
) -> serde_json::Value {
    let mut values = positions
        .into_iter()
        .map(|position| {
            let mut value = serde_json::json!({
                "source_index": position.source_index,
                "original_line": position.line,
                "original_column": position.column,
                "name_index": position.name_index,
            });
            if include_source_names {
                value["source"] = position
                    .source
                    .map_or(serde_json::Value::Null, serde_json::Value::String);
                value["source_root"] = position
                    .source_root
                    .map_or(serde_json::Value::Null, serde_json::Value::String);
                value["name"] = position
                    .name
                    .map_or(serde_json::Value::Null, serde_json::Value::String);
            }
            value
        })
        .collect::<Vec<_>>();
    match values.len() {
        0 => serde_json::json!({
            "mapping": "unmapped",
            "coordinate_basis": "zero_based_utf16",
        }),
        1 => {
            let mut value = values.pop().expect("one position exists");
            value["mapping"] = serde_json::Value::String("mapped".to_string());
            value["coordinate_basis"] = serde_json::Value::String("zero_based_utf16".to_string());
            value
        }
        _ => serde_json::json!({
            "mapping": "ambiguous",
            "coordinate_basis": "zero_based_utf16",
            "count": values.len(),
            "positions": values,
        }),
    }
}

fn analyze_source(path: &std::path::Path) -> Result<analysis::Analysis> {
    let source = fs::read_to_string(path)?;
    let mut parser = JsParser::new()?;
    let tree = parser.parse(&source)?;
    analysis::Analysis::from_javascript(&source, &tree)
}

fn read_source_map_for_lineage(
    path: &std::path::Path,
    allow_sources_content: bool,
) -> Result<sourcemap::SourceMap> {
    let limits = sourcemap::SourceMapLimits {
        allow_sources_content,
        ..sourcemap::SourceMapLimits::default()
    };
    let bytes = read_bounded_file(path, limits.max_bytes as u64, "source map")?;
    sourcemap::SourceMap::parse(&bytes, limits)
}

struct LineageRunOptions<'a> {
    source_file: &'a std::path::Path,
    target_file: &'a std::path::Path,
    output: &'a std::path::Path,
    source_map_source: Option<&'a std::path::Path>,
    source_map_target: Option<&'a std::path::Path>,
    allow_sources_content: bool,
    min_score_bps: u32,
    min_margin_bps: u32,
    max_candidates: usize,
}

fn run_lineage(options: LineageRunOptions<'_>) -> Result<()> {
    if options.source_map_source.is_some() != options.source_map_target.is_some() {
        anyhow::bail!("--source-map-source and --source-map-target must be supplied together");
    }
    let source = analyze_source(options.source_file)?;
    let target = analyze_source(options.target_file)?;
    let config = lineage::MatcherConfig {
        min_score_bps: options.min_score_bps,
        min_margin_bps: options.min_margin_bps,
        max_candidates: options.max_candidates,
        ..lineage::MatcherConfig::default()
    };
    let report = match (options.source_map_source, options.source_map_target) {
        (Some(source_map_path), Some(target_map_path)) => {
            let source_text = fs::read_to_string(options.source_file)?;
            let target_text = fs::read_to_string(options.target_file)?;
            let source_map =
                read_source_map_for_lineage(source_map_path, options.allow_sources_content)?;
            let target_map =
                read_source_map_for_lineage(target_map_path, options.allow_sources_content)?;
            lineage::match_analyses_with_source_maps(
                &source,
                &target,
                config,
                &source_text,
                &target_text,
                &source_map,
                &target_map,
            )?
        }
        (None, None) => lineage::match_analyses(&source, &target, config)?,
        _ => unreachable!("source-map flags were checked as a pair"),
    };
    report.write(options.output)?;
    println!(
        "{}",
        serde_json::json!({
            "accepted": report.stats.accepted,
            "abstained": report.stats.abstained,
            "deleted": report.stats.deleted,
            "added": report.stats.added,
            "ambiguous_targets": report.stats.ambiguous_targets,
            "candidate_pairs": report.stats.candidate_pairs,
            "expensive_comparisons": report.stats.expensive_comparisons,
            "truncated_sources": report.stats.truncated_sources,
        })
    );
    Ok(())
}

fn run_names(command: NameCommand) -> Result<()> {
    use naming::{NameProvenance, NameState, SemanticNameDocument};

    let provenance = |origin: String| NameProvenance {
        origin,
        actor: None,
        evidence_digest: None,
    };
    match command {
        NameCommand::Export {
            input_file,
            output,
            include_generated_names,
        } => {
            let analysis = analyze_source(&input_file)?;
            let document = SemanticNameDocument::from_analysis(&analysis, include_generated_names)?;
            document.write(&output)?;
            println!(
                "{}",
                serde_json::json!({"symbols": document.symbols.len(), "revision": 0})
            );
        }
        NameCommand::Validate {
            document,
            source_file,
        } => {
            let document = SemanticNameDocument::read(&document)?;
            if let Some(source_file) = source_file {
                document.validate_against(&analyze_source(&source_file)?)?;
            }
            let approved = document
                .symbols
                .iter()
                .filter(|entry| entry.state == NameState::Approved)
                .count();
            println!(
                "{}",
                serde_json::json!({"valid": true, "symbols": document.symbols.len(), "approved": approved, "revision": document.revision})
            );
        }
        NameCommand::Set {
            document,
            symbol_id,
            semantic_name,
            expected_revision,
            origin,
        } => {
            let mut value = SemanticNameDocument::read(&document)?;
            require_revision(value.revision, expected_revision)?;
            value.suggest(&symbol_id, semantic_name, provenance(origin))?;
            value.write(&document)?;
            println!(
                "{}",
                serde_json::json!({"updated": true, "revision": value.revision})
            );
        }
        NameCommand::Approve {
            document,
            symbol_id,
            expected_revision,
            origin,
        } => {
            let mut value = SemanticNameDocument::read(&document)?;
            require_revision(value.revision, expected_revision)?;
            value.transition(&symbol_id, NameState::Approved, provenance(origin))?;
            value.write(&document)?;
            println!(
                "{}",
                serde_json::json!({"updated": true, "revision": value.revision})
            );
        }
        NameCommand::Reject {
            document,
            symbol_id,
            expected_revision,
            origin,
        } => {
            let mut value = SemanticNameDocument::read(&document)?;
            require_revision(value.revision, expected_revision)?;
            value.transition(&symbol_id, NameState::Rejected, provenance(origin))?;
            value.write(&document)?;
            println!(
                "{}",
                serde_json::json!({"updated": true, "revision": value.revision})
            );
        }
        NameCommand::Clear {
            document,
            symbol_id,
            expected_revision,
            origin,
        } => {
            let mut value = SemanticNameDocument::read(&document)?;
            require_revision(value.revision, expected_revision)?;
            value.transition(&symbol_id, NameState::Cleared, provenance(origin))?;
            value.write(&document)?;
            println!(
                "{}",
                serde_json::json!({"updated": true, "revision": value.revision})
            );
        }
        NameCommand::Propagate {
            source_names,
            lineage,
            source_file,
            target_file,
            source_map_source,
            source_map_target,
            allow_sources_content,
            output,
            render_output,
            render_format,
        } => {
            let names = SemanticNameDocument::read(&source_names)?;
            let lineage = lineage::LineageReport::read(&lineage)?;
            let source = analyze_source(&source_file)?;
            let target = analyze_source(&target_file)?;
            if source_map_source.is_some() != source_map_target.is_some() {
                anyhow::bail!(
                    "--source-map-source and --source-map-target must be supplied together"
                );
            }
            let output_document = match (source_map_source, source_map_target) {
                (Some(source_map_path), Some(target_map_path)) => {
                    let source_text = fs::read_to_string(&source_file)?;
                    let target_text = fs::read_to_string(&target_file)?;
                    let source_map =
                        read_source_map_for_lineage(&source_map_path, allow_sources_content)?;
                    let target_map =
                        read_source_map_for_lineage(&target_map_path, allow_sources_content)?;
                    naming::propagate_approved_names_with_source_maps(
                        &names,
                        &lineage,
                        &source,
                        &target,
                        naming::SourceMapPropagationInputs {
                            source_text: &source_text,
                            target_text: &target_text,
                            source_map: &source_map,
                            target_map: &target_map,
                        },
                    )?
                }
                (None, None) => {
                    naming::propagate_approved_names(&names, &lineage, &source, &target)?
                }
                _ => unreachable!("source-map flags were checked as a pair"),
            };
            let rendered = if let Some(path) = render_output.as_ref() {
                reject_input_overwrite(&target_file, path)?;
                let target_text = fs::read_to_string(&target_file)?;
                let format = parse_render_format(&render_format)?;
                Some((
                    path,
                    render::render_semantic_names(&output_document, &target, &target_text, format)?,
                ))
            } else {
                None
            };
            output_document.write(&output)?;
            if let Some((path, bytes)) = rendered {
                render::write_output(path, &bytes)?;
            }
            let propagated = output_document
                .symbols
                .iter()
                .filter(|entry| entry.state == NameState::Approved)
                .count();
            println!(
                "{}",
                serde_json::json!({
                    "propagated": propagated,
                    "revision": output_document.revision,
                    "rendered": render_output.is_some(),
                })
            );
        }
        NameCommand::Render {
            document,
            target_file,
            output,
            format,
        } => {
            let document = SemanticNameDocument::read(&document)?;
            let target_text = fs::read_to_string(&target_file)?;
            let target = analyze_source(&target_file)?;
            reject_input_overwrite(&target_file, &output)?;
            let rendered = render::render_semantic_names(
                &document,
                &target,
                &target_text,
                parse_render_format(&format)?,
            )?;
            render::write_output(&output, &rendered)?;
            println!(
                "{}",
                serde_json::json!({"rendered": true, "bytes": rendered.len()})
            );
        }
    }
    Ok(())
}

fn parse_render_format(value: &str) -> Result<render::RenderFormat> {
    match value {
        "pretty" => Ok(render::RenderFormat::Pretty),
        "preserve" => Ok(render::RenderFormat::Preserve),
        _ => anyhow::bail!("unsupported render format {value:?}"),
    }
}

fn reject_input_overwrite(input: &std::path::Path, output: &std::path::Path) -> Result<()> {
    let input = fs::canonicalize(input)?;
    let output = match fs::canonicalize(output) {
        Ok(path) => path,
        Err(_) => {
            let parent = output.parent().unwrap_or_else(|| std::path::Path::new("."));
            fs::canonicalize(parent)?.join(
                output
                    .file_name()
                    .ok_or_else(|| anyhow::anyhow!("rendered output has no file name"))?,
            )
        }
    };
    if input == output {
        anyhow::bail!("rendered output must be a separate path from the target input");
    }
    Ok(())
}

fn require_revision(actual: u64, expected: u64) -> Result<()> {
    if actual != expected {
        anyhow::bail!("semantic-name revision changed: expected {expected}, found {actual}");
    }
    Ok(())
}

fn run_analyze(input_file: &std::path::Path, output: &std::path::Path) -> Result<()> {
    let source = fs::read_to_string(input_file)?;
    let mut parser = JsParser::new()?;
    let tree = parser.parse(&source)?;
    let analysis = analysis::Analysis::from_javascript(&source, &tree)?;
    analysis.write_positioned(output)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "output": output,
            "format_version": analysis.version,
            "profile": analysis.profile,
            "nodes": analysis.nodes.len(),
            "scopes": analysis.scopes.len(),
            "symbols": analysis.symbols.len(),
            "references": analysis.references.len(),
            "def_uses": analysis.def_uses.len(),
            "calls": analysis.calls.len(),
            "losses": analysis.losses.len(),
        }))?
    );
    Ok(())
}

fn run_analysis_query(path: &std::path::Path, query: AnalysisQuery) -> Result<()> {
    let mapped = analysis::MappedAnalysis::open(path)?;
    let view = mapped.verify()?;
    let value = match query {
        AnalysisQuery::Summary => serde_json::json!({
            "profile": view.profile(),
            "producer": view.producer(),
            "frontend": view.frontend(),
            "source_digest": analysis::StableId(view.source_digest()).to_hex(),
            "source_length": view.source_length(),
            "nodes": view.node_count(),
            "scopes": view.scope_count(),
            "symbols": view.symbol_count(),
            "references": view.reference_count(),
            "def_uses": view.def_use_count(),
            "calls": view.call_count(),
            "losses": view.loss_count(),
        }),
        AnalysisQuery::Node { index } => {
            let node = view
                .node(index)
                .ok_or_else(|| anyhow::anyhow!("node index {index} is out of range"))?;
            serde_json::json!({
                "index": index,
                "id": node.id.to_hex(),
                "parent": node.parent,
                "kind": node.kind,
                "start_byte": node.start_byte,
                "end_byte": node.end_byte,
                "flags": node.flags,
            })
        }
        AnalysisQuery::Scope { index } => {
            let scope = view
                .scope(index)
                .ok_or_else(|| anyhow::anyhow!("scope index {index} is out of range"))?;
            serde_json::json!({
                "index": index,
                "id": scope.id.to_hex(),
                "parent": scope.parent,
                "kind": format!("{:?}", scope.kind).to_lowercase(),
                "depth": scope.depth,
                "start_byte": scope.start_byte,
                "end_byte": scope.end_byte,
            })
        }
        AnalysisQuery::Symbol { index } => {
            let symbol = view
                .symbol(index)
                .ok_or_else(|| anyhow::anyhow!("symbol index {index} is out of range"))?;
            serde_json::json!({
                "index": index,
                "id": symbol.id.to_hex(),
                "declaration_node": symbol.declaration_node,
                "scope": symbol.scope,
                "name": symbol.name,
                "kind": format!("{:?}", symbol.kind).to_lowercase(),
                "reference_first": symbol.reference_first,
                "reference_count": symbol.reference_count,
            })
        }
        AnalysisQuery::Reference { index } => {
            let reference = view
                .reference(index)
                .ok_or_else(|| anyhow::anyhow!("reference index {index} is out of range"))?;
            serde_json::json!({
                "index": index,
                "id": reference.id.to_hex(),
                "node": reference.node,
                "scope": reference.scope,
                "name": reference.name,
                "role": format!("{:?}", reference.role).to_lowercase(),
            })
        }
        AnalysisQuery::DefUse { index } => {
            let edge = view
                .def_use(index)
                .ok_or_else(|| anyhow::anyhow!("def-use index {index} is out of range"))?;
            serde_json::json!({
                "index": index,
                "id": edge.id.to_hex(),
                "reference": edge.reference,
                "symbol": edge.symbol,
                "resolution": format!("{:?}", edge.resolution).to_lowercase(),
            })
        }
        AnalysisQuery::Call { index } => {
            let call = view
                .call(index)
                .ok_or_else(|| anyhow::anyhow!("call index {index} is out of range"))?;
            serde_json::json!({
                "index": index,
                "id": call.id.to_hex(),
                "node": call.node,
                "callee_reference": call.callee_reference,
                "target_symbol": call.target_symbol,
                "property": call.property,
                "kind": format!("{:?}", call.kind).to_lowercase(),
            })
        }
        AnalysisQuery::String { index } => serde_json::json!({
            "index": index,
            "value": view
                .string(index)
                .ok_or_else(|| anyhow::anyhow!("string index {index} is out of range"))?,
        }),
        AnalysisQuery::Loss { index } => {
            let loss = view
                .loss(index)
                .ok_or_else(|| anyhow::anyhow!("loss index {index} is out of range"))?;
            serde_json::json!({
                "index": index,
                "code": loss.code as u16,
                "message": loss.message,
            })
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn run_canonicalize(
    input_file: &std::path::PathBuf,
    _preserve_comments: bool,
    pretty: bool,
    verbose: bool,
) -> Result<()> {
    let source = fs::read_to_string(input_file)?;
    let mut parser = JsParser::new()?;
    let tree = parser.parse(&source)?;

    let mut analyzer = ScopeAnalyzer::new();
    analyzer.analyze(tree.root_node(), &source)?;

    if verbose {
        print_scope_analysis(&analyzer);
    }

    let mut canonicalizer = Canonicalizer::new(analyzer);
    canonicalizer.canonicalize(&tree, &source)?;

    let canonical = canonicalizer.apply_canonicalization(&tree, &source)?;
    if pretty {
        let pretty_printer = PrettyPrinter::new();
        let mut parser = JsParser::new()?;
        let canonical_tree = parser.parse(&canonical)?;
        let formatted = pretty_printer.format(&canonical_tree, &canonical);
        print!("{}", formatted);
    } else {
        print!("{}", canonical);
    }

    Ok(())
}

fn run_generate_mapping(
    input_file: &std::path::PathBuf,
    _preserve_comments: bool,
    _pretty: bool,
    verbose: bool,
) -> Result<()> {
    let source = fs::read_to_string(input_file)?;
    let mut parser = JsParser::new()?;
    let tree = parser.parse(&source)?;

    let mut analyzer = ScopeAnalyzer::new();
    analyzer.analyze(tree.root_node(), &source)?;

    if verbose {
        print_scope_analysis(&analyzer);
    }

    let mut canonicalizer = Canonicalizer::new(analyzer);
    canonicalizer.canonicalize(&tree, &source)?;

    let generator = MappingGenerator::new(canonicalizer, source.clone());
    let mapping_file = generator.generate_mapping_file(&tree)?;
    print!("{}", mapping_file);

    Ok(())
}

fn run_apply_mapping(
    input_file: &std::path::PathBuf,
    map_file: &std::path::PathBuf,
    _preserve_comments: bool,
    pretty: bool,
    verbose: bool,
) -> Result<()> {
    let source = fs::read_to_string(input_file)?;
    let mut parser = JsParser::new()?;
    let tree = parser.parse(&source)?;

    let mut analyzer = ScopeAnalyzer::new();
    analyzer.analyze(tree.root_node(), &source)?;

    if verbose {
        print_scope_analysis(&analyzer);
    }

    let mut canonicalizer = Canonicalizer::new(analyzer);
    canonicalizer.canonicalize(&tree, &source)?;

    let mapping_content = fs::read_to_string(map_file)?;
    let mappings = MappingGenerator::parse_mapping_file(&mapping_content)?;
    let generator = MappingGenerator::new(canonicalizer, source.clone());
    let output = generator.apply_mappings(&tree, mappings)?;

    if pretty {
        let pretty_printer = PrettyPrinter::new();
        let mut parser = JsParser::new()?;
        let output_tree = parser.parse(&output)?;
        let formatted = pretty_printer.format(&output_tree, &output);
        print!("{}", formatted);
    } else {
        print!("{}", output);
    }

    Ok(())
}

struct DiffOptions {
    format: String,
    export_mappings: Option<std::path::PathBuf>,
    summary: bool,
    verbose: bool,
    fingerprints: bool,
    compact: bool,
    lite: bool,
    dump: Option<std::path::PathBuf>,
}

fn run_diff(
    file1: std::path::PathBuf,
    file2: std::path::PathBuf,
    options: DiffOptions,
) -> Result<()> {
    let DiffOptions {
        format,
        export_mappings,
        summary,
        verbose,
        fingerprints,
        compact,
        lite,
        dump,
    } = options;

    use crate::diff::profiling::Timer;
    use crate::diff::StructuralDiff;

    use std::thread;

    // Load and parse both files in parallel
    let file1_path = file1.clone();
    let handle1 = thread::spawn(move || -> Result<(String, tree_sitter::Tree)> {
        let _timer = Timer::new("read_and_parse_file1");
        let source = fs::read_to_string(&file1_path)?;
        let mut parser = JsParser::new()?;
        let tree = parser.parse(&source)?;
        Ok((source, tree))
    });

    let file2_path = file2.clone();
    let handle2 = thread::spawn(move || -> Result<(String, tree_sitter::Tree)> {
        let _timer = Timer::new("read_and_parse_file2");
        let source = fs::read_to_string(&file2_path)?;
        let mut parser = JsParser::new()?;
        let tree = parser.parse(&source)?;
        Ok((source, tree))
    });

    let (source1, tree1) = handle1.join().expect("Thread 1 panicked")?;
    let (source2, tree2) = handle2.join().expect("Thread 2 panicked")?;

    eprintln!(
        "Source files: {} bytes, {} bytes",
        source1.len(),
        source2.len()
    );

    let mut diff = StructuralDiff::new();

    // Configure diff based on CLI flags
    diff.set_use_fingerprints(fingerprints);
    if verbose {
        std::env::set_var("ASTDIFF_DEBUG", "1");
    }

    let result = {
        let _timer = Timer::new("diff_compare_total");
        diff.compare(
            &source1,
            &source2,
            &tree1,
            &tree2,
            dump.as_deref(),
            &file1,
            &file2,
        )?
    };

    {
        let _timer = Timer::new("generate_output");
        match format.as_str() {
            "unified" => {
                if compact || lite {
                    diff.print_compact_locations(&result, &file1, &file2)
                } else if summary {
                    diff.print_summary(&result, &file1, &file2, &source1, &source2)
                } else {
                    diff.print_default(&result, &file1, &file2, &source1, &source2)?
                }
            }
            "json" => diff.print_json(&result)?,
            _ => anyhow::bail!("Unknown format: {}", format),
        }
    }

    // Export rename mappings if requested
    if let Some(export_path) = export_mappings {
        let rename_mappings = diff.generate_rename_mapping(&result);
        let yaml = serde_yaml::to_string(&rename_mappings)?;
        fs::write(&export_path, yaml)?;
        eprintln!(
            "Exported {} rename mappings to {}",
            rename_mappings.len(),
            export_path.display()
        );
    }

    // Report profiling data at the very end
    crate::diff::profiling::report_profile();

    Ok(())
}

fn print_scope_analysis(analyzer: &ScopeAnalyzer) {
    eprintln!("=== Scope Analysis ===");
    for (id, scope) in analyzer.get_scopes() {
        eprintln!(
            "Scope: {} (type: {:?}, depth: {})",
            id, scope.scope_type, scope.depth
        );
        for var in &scope.variables {
            eprintln!("  Variable: {} (kind: {:?})", var.name, var.kind);
        }
    }
    eprintln!();
}

fn run_inspect(
    input_file: &std::path::PathBuf,
    compare_file: Option<&std::path::PathBuf>,
    identifier: &str,
    _verbose: bool,
) -> Result<()> {
    use crate::diff::StructuralDiff;

    let diff = StructuralDiff::new();

    // Load and extract declarations for file1
    let source1 = fs::read_to_string(input_file)?;
    let mut parser = JsParser::new()?;
    let tree1 = parser.parse(&source1)?;
    let declarations1 = diff.extract_declarations_for_inspection(tree1.root_node(), &source1);

    // Find all declarations matching the identifier in file1
    let matches1: Vec<_> = declarations1
        .iter()
        .enumerate()
        .filter(|(_, d)| d.name == identifier)
        .collect();

    if matches1.is_empty() {
        println!(
            "No declarations found with identifier '{}' in {}",
            identifier,
            input_file.display()
        );
        return Ok(());
    }

    // If comparing with another file, run the matching algorithm
    let match_results = if let Some(file2) = compare_file {
        let source2 = fs::read_to_string(file2)?;
        let mut parser = JsParser::new()?;
        let tree2 = parser.parse(&source2)?;
        let declarations2 = diff.extract_declarations_for_inspection(tree2.root_node(), &source2);

        // Run the matching algorithm
        let (matches, _, _) =
            diff.match_declarations(&declarations1, &declarations2, &source1, &source2);

        // Find what each declaration in file1 matched to
        let mut match_map = std::collections::HashMap::new();
        for (i1, i2, _) in matches {
            match_map.insert(i1, i2);
        }

        Some((declarations2, match_map, source2))
    } else {
        None
    };

    println!(
        "Found {} declaration(s) with identifier '{}' in {}:\n",
        matches1.len(),
        identifier,
        input_file.display()
    );

    for (i, (idx1, decl1)) in matches1.iter().enumerate() {
        println!("=== Declaration #{} ===", i + 1);
        println!("File: {}", input_file.display());
        println!("Name: {}", decl1.name);
        println!("Kind: {:?}", decl1.kind);
        println!("Line: {}", decl1.line);
        println!("Size (structural hashes): {}", decl1.size);
        println!("Signature: {}", decl1.signature);

        // Print matching information if available
        if let Some((ref declarations2, ref match_map, ref source2)) = match_results {
            println!("\nMatching Information:");
            if let Some(&idx2) = match_map.get(idx1) {
                let decl2 = &declarations2[idx2];
                println!(
                    "  MATCHED to: {} (line {}) in {}",
                    decl2.name,
                    decl2.line,
                    compare_file.unwrap().display()
                );
                if decl1.name != decl2.name {
                    println!("  NOTE: Different names! {} -> {}", decl1.name, decl2.name);
                }
                println!("  Match similarity: calculating...");

                // Calculate similarity
                let similarity =
                    diff.calculate_declaration_similarity(decl1, decl2, &source1, source2);
                println!("  Structural similarity: {:.1}%", similarity * 100.0);
            } else {
                println!("  NOT MATCHED - This declaration was removed or significantly changed");
            }
        }

        // Print structural hashes (first 10)
        println!("\nStructural hashes (showing first 10):");
        for (j, hash) in decl1.structural_hashes.iter().take(10).enumerate() {
            println!("  {}: {}", j + 1, hash);
        }
        if decl1.structural_hashes.len() > 10 {
            println!("  ... and {} more", decl1.structural_hashes.len() - 10);
        }

        // Print fingerprint if available
        if let Some(ref fp) = decl1.fingerprint {
            println!("\nFingerprint:");
            println!(
                "  Strings ({}): {:?}",
                fp.strings.len(),
                fp.strings
                    .iter()
                    .take(5)
                    .map(|s| &s.value)
                    .collect::<Vec<_>>()
            );
            println!(
                "  Constants ({}): {:?}",
                fp.constants.len(),
                fp.constants.iter().take(5).collect::<Vec<_>>()
            );
            println!(
                "  API calls ({}): {:?}",
                fp.api_calls.len(),
                fp.api_calls.iter().take(5).collect::<Vec<_>>()
            );
        }

        // Print AST snippet
        println!("\nAST Node:");
        println!("  Kind: {}", decl1.node_kind);
        println!("  Start line: {}", decl1.line);
        println!("  End line: {}", decl1.end_line);

        // Print source snippet
        let start_byte = decl1.start_byte;
        let end_byte = decl1.end_byte.min(source1.len());
        let snippet = &source1[start_byte..end_byte];
        let preview = if snippet.len() > 200 {
            format!("{}...", &snippet[..200])
        } else {
            snippet.to_string()
        };
        println!("\nSource preview:");
        println!("{}", preview);

        if i < matches1.len() - 1 {
            println!("\n");
        }
    }

    // Also look for the identifier in file2 if provided
    if let Some((ref declarations2, ref match_map, _)) = match_results {
        let matches2: Vec<_> = declarations2
            .iter()
            .enumerate()
            .filter(|(_, d)| d.name == identifier)
            .filter(|(idx2, _)| {
                // Only show if it wasn't already shown as a match
                !matches1
                    .iter()
                    .any(|(idx1, _)| match_map.get(idx1).is_some_and(|&i| i == *idx2))
            })
            .collect();

        if !matches2.is_empty() {
            println!(
                "\n\nAdditional declarations with identifier '{}' in {}:",
                identifier,
                compare_file.unwrap().display()
            );
            for (_idx2, decl2) in matches2 {
                println!(
                    "\n- {} (line {}) - NOT MATCHED (new declaration)",
                    decl2.name, decl2.line
                );
            }
        }
    }

    Ok(())
}

fn run_query(dump_file: &std::path::Path, query_type: QueryType) -> Result<()> {
    use crate::dump::AstDiffDump;

    // Load the dump
    let dump = AstDiffDump::load(dump_file)?;

    match query_type {
        QueryType::Find { name } => {
            let found = dump
                .file1_data
                .declarations
                .iter()
                .find(|decl| decl.decl.name == name)
                .map(|decl| (decl, &dump.file1_data.path))
                .or_else(|| {
                    dump.file2_data
                        .declarations
                        .iter()
                        .find(|decl| decl.decl.name == name)
                        .map(|decl| (decl, &dump.file2_data.path))
                });
            if let Some((decl, path)) = found {
                println!("Found declaration '{}' in {}:", name, path.display());
                println!("  Kind: {:?}", decl.decl.kind);
                println!("  Line: {}", decl.decl.line);
                println!("  Signature: {}", decl.decl.signature);

                if let Some(match_decision) = &decl.match_decision {
                    println!("  Match decision: {:?}", match_decision.reason);
                    if let Some(matched_to) = match_decision.matched_to {
                        println!("  Matched to index: {}", matched_to);
                    }
                }
            } else {
                println!("Declaration '{}' not found in dump", name);
            }
        }
        QueryType::UnmatchedFrom1 => {
            let unmatched = dump.unmatched_from_file1();
            println!(
                "Unmatched declarations from {} ({} total):",
                dump.file1_data.path.display(),
                unmatched.len()
            );
            for decl in unmatched {
                println!(
                    "  - {} (line {}): {}",
                    decl.decl.name, decl.decl.line, decl.decl.kind
                );
            }
        }
        QueryType::UnmatchedFrom2 => {
            let unmatched = dump.unmatched_from_file2();
            println!(
                "Unmatched declarations from {} ({} total):",
                dump.file2_data.path.display(),
                unmatched.len()
            );
            for decl in unmatched {
                println!(
                    "  - {} (line {}): {}",
                    decl.decl.name, decl.decl.line, decl.decl.kind
                );
            }
        }
        QueryType::Match { name } => {
            // Find the declaration in file1
            let file1_idx = dump
                .file1_data
                .declarations
                .iter()
                .position(|d| d.decl.name == name);

            if let Some(idx) = file1_idx {
                if let Some(match_pair) = dump.get_match_for(idx) {
                    let decl2 = &dump.file2_data.declarations[match_pair.idx2];
                    println!(
                        "Declaration '{}' from {} matches:",
                        name,
                        dump.file1_data.path.display()
                    );
                    println!(
                        "  -> {} (line {}) in {}",
                        decl2.decl.name,
                        decl2.decl.line,
                        dump.file2_data.path.display()
                    );
                    println!("  Similarity: {:.1}%", match_pair.similarity * 100.0);
                    println!("  Evidence count: {}", match_pair.evidence_count);
                } else {
                    println!(
                        "Declaration '{}' from {} has no match",
                        name,
                        dump.file1_data.path.display()
                    );
                }
            } else {
                println!(
                    "Declaration '{}' not found in {}",
                    name,
                    dump.file1_data.path.display()
                );
            }
        }
        QueryType::Validate { file1, file2 } => match dump.validate(&file1, &file2)? {
            true => println!("✓ Dump is valid for the provided source files"),
            false => {
                println!("✗ Dump is NOT valid - source files have changed");
                println!("  Expected files:");
                println!("    - {}", dump.file1_data.path.display());
                println!("    - {}", dump.file2_data.path.display());
            }
        },
    }

    Ok(())
}

fn run_load(dump_file: &std::path::Path, format: &str) -> Result<()> {
    use crate::dump::AstDiffDump;

    // Load the dump
    let dump = AstDiffDump::load(dump_file)?;

    match format {
        "summary" => {
            println!("=== AstDiff Dump Summary ===");
            println!("Version: {}", dump.header.version);
            println!(
                "Created: {}",
                chrono::DateTime::<chrono::Utc>::from_timestamp(dump.metadata.timestamp as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Unknown".to_string())
            );
            println!("Tool version: {}", dump.metadata.tool_version);
            println!("\nConfiguration:");
            println!(
                "  Use fingerprints: {}",
                dump.metadata.config.use_fingerprints
            );
            println!(
                "  Parallel matching: {}",
                dump.metadata.config.parallel_matching
            );
            println!("  Threshold: {}", dump.metadata.config.threshold);
            println!("\nFiles:");
            println!(
                "  File 1: {} ({} declarations)",
                dump.file1_data.path.display(),
                dump.file1_data.declarations.len()
            );
            println!(
                "  File 2: {} ({} declarations)",
                dump.file2_data.path.display(),
                dump.file2_data.declarations.len()
            );
            println!("\nMatching results:");
            println!("  Total matches: {}", dump.matching.matches.len());
            println!("  Similarity: {:.1}%", dump.diff_result.similarity * 100.0);
            println!("  Changes: {}", dump.diff_result.changes.len());

            let additions = dump
                .diff_result
                .changes
                .iter()
                .filter(|c| matches!(c.change_type, crate::diff::ChangeType::Addition))
                .count();
            let deletions = dump
                .diff_result
                .changes
                .iter()
                .filter(|c| matches!(c.change_type, crate::diff::ChangeType::Deletion))
                .count();
            let modifications = dump
                .diff_result
                .changes
                .iter()
                .filter(|c| matches!(c.change_type, crate::diff::ChangeType::Modification))
                .count();

            println!("    - Additions: {}", additions);
            println!("    - Deletions: {}", deletions);
            println!("    - Modifications: {}", modifications);
        }
        "full" => {
            // Print detailed information
            println!("{:#?}", dump);
        }
        "json" => {
            // Serialize to JSON
            let json = serde_json::to_string_pretty(&dump)?;
            println!("{}", json);
        }
        _ => {
            anyhow::bail!(
                "Unknown format: {}. Use 'summary', 'full', or 'json'",
                format
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod bounded_read_tests {
    use tempfile::tempdir;

    use super::read_bounded_file;

    #[test]
    fn bounded_reader_rejects_before_returning_oversized_data() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("bounded.bin");
        std::fs::write(&path, b"12345").unwrap();
        let error = read_bounded_file(&path, 4, "fixture").unwrap_err();
        assert!(error.to_string().contains("fixture exceeds the byte limit"));
    }
}
