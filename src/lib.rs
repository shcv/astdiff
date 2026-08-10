pub mod canonicalizer;
pub mod cli;
pub mod diff;
pub mod dump;
pub mod mapping;
pub mod parser;
pub mod pretty;
pub mod scope;

use anyhow::Result;
use std::fs;

use canonicalizer::Canonicalizer;
pub use cli::{Args, Mode, QueryType};
use mapping::MappingGenerator;
use parser::JsParser;
use pretty::PrettyPrinter;
use scope::ScopeAnalyzer;

pub fn run(args: Args) -> Result<()> {
    match args.mode() {
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
