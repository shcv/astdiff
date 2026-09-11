use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about = "AST-based JavaScript Diff and Code Analysis Tool", long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Option<Command>,

    // Default diff mode arguments (when no subcommand is used)
    /// First JavaScript file to compare
    pub file1: Option<PathBuf>,

    /// Second JavaScript file to compare
    pub file2: Option<PathBuf>,

    /// Output format: unified (default) or json
    #[clap(long, default_value = "unified", value_parser = ["unified", "json"])]
    pub format: String,

    /// Export rename mappings to a file
    #[clap(long)]
    pub export_mappings: Option<PathBuf>,

    /// Show only summary of changes (no detailed diffs)
    #[clap(long)]
    pub summary: bool,

    /// Show detailed analysis to stderr
    #[clap(long)]
    pub verbose: bool,

    /// Enable fingerprint-based matching (disabled by default due to accuracy issues)
    #[clap(long)]
    pub fingerprints: bool,

    /// Compact output showing only function names and line ranges
    #[clap(long)]
    pub compact: bool,

    /// Alias for --compact
    #[clap(long)]
    pub lite: bool,

    /// Save declarations, matches, and results for later inspection
    #[clap(long, value_name = "FILE")]
    pub dump: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Validate and query Source Map v3 files
    Map {
        #[clap(subcommand)]
        command: SourceMapCommand,
    },

    /// Match symbols across two JavaScript artifacts using structural context
    Lineage {
        source_file: PathBuf,
        target_file: PathBuf,
        /// Exact raw source map for `source_file`; must be paired with the
        /// target map.  Maps are never discovered by filename.
        #[clap(long, value_name = "FILE", requires = "source_map_target")]
        source_map_source: Option<PathBuf>,
        /// Exact raw source map for `target_file`; must be paired with the
        /// source map.
        #[clap(long, value_name = "FILE", requires = "source_map_source")]
        source_map_target: Option<PathBuf>,
        /// Permit embedded sourcesContent while parsing; content is never
        /// retained or emitted by lineage.
        #[clap(long)]
        allow_sources_content: bool,
        #[clap(short, long, value_name = "FILE")]
        output: PathBuf,
        #[clap(long, default_value_t = 7200)]
        min_score_bps: u32,
        #[clap(long, default_value_t = 700)]
        min_margin_bps: u32,
        #[clap(long, default_value_t = 96)]
        max_candidates: usize,
    },

    /// Export, validate, edit, and propagate semantic-name review documents
    Names {
        #[clap(subcommand)]
        command: NameCommand,
    },

    /// Canonicalize JavaScript code (normalize variable names)
    Canon {
        /// Input JavaScript file
        input_file: PathBuf,

        /// Generate mapping template (no file) or apply mappings (with file)
        #[clap(long, value_name = "FILE")]
        map: Option<Option<PathBuf>>,

        /// Keep comments in output
        #[clap(long)]
        preserve_comments: bool,

        /// Pretty print the output with proper indentation
        #[clap(long)]
        pretty: bool,
    },

    /// Inspect a specific declaration in a file
    Inspect {
        /// Input JavaScript file
        input_file: PathBuf,

        /// Optional second file to compare against
        #[clap(long)]
        compare_file: Option<PathBuf>,

        /// Name of the declaration to inspect (e.g., function name, variable name)
        identifier: String,
    },

    /// Query information from a comprehensive dump file
    Query {
        /// Path to the dump file (.astdump)
        dump_file: PathBuf,

        #[clap(subcommand)]
        query_type: QueryType,
    },

    /// Load and display a comprehensive dump file
    Load {
        /// Path to the dump file (.astdump)
        dump_file: PathBuf,

        /// Output format: summary (default), full, or json
        #[clap(long, default_value = "summary")]
        format: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum QueryType {
    /// Find a declaration by name
    Find {
        /// Name of the declaration to find
        name: String,
    },

    /// Show all unmatched declarations from file1
    UnmatchedFrom1,

    /// Show all unmatched declarations from file2
    UnmatchedFrom2,

    /// Get match information for a declaration
    Match {
        /// Name of the declaration to find match for
        name: String,
    },

    /// Validate the dump against source files
    Validate {
        /// Path to the first source file
        file1: PathBuf,

        /// Path to the second source file  
        file2: PathBuf,
    },
}

impl Args {
    pub fn mode(&self) -> Mode {
        match &self.command {
            Some(Command::Canon {
                input_file,
                map,
                preserve_comments,
                pretty,
            }) => match map {
                None => Mode::Canonicalize {
                    input_file: input_file.clone(),
                    preserve_comments: *preserve_comments,
                    pretty: *pretty,
                },
                Some(None) => Mode::GenerateMapping {
                    input_file: input_file.clone(),
                    preserve_comments: *preserve_comments,
                    pretty: *pretty,
                },
                Some(Some(path)) => Mode::ApplyMapping {
                    input_file: input_file.clone(),
                    map_file: path.clone(),
                    preserve_comments: *preserve_comments,
                    pretty: *pretty,
                },
            },
            Some(Command::Map { command }) => Mode::Map(command.clone()),
            Some(Command::Lineage {
                source_file,
                target_file,
                source_map_source,
                source_map_target,
                allow_sources_content,
                output,
                min_score_bps,
                min_margin_bps,
                max_candidates,
            }) => Mode::Lineage {
                source_file: source_file.clone(),
                target_file: target_file.clone(),
                source_map_source: source_map_source.clone(),
                source_map_target: source_map_target.clone(),
                allow_sources_content: *allow_sources_content,
                output: output.clone(),
                min_score_bps: *min_score_bps,
                min_margin_bps: *min_margin_bps,
                max_candidates: *max_candidates,
            },
            Some(Command::Names { command }) => Mode::Names(command.clone()),
            Some(Command::Inspect {
                input_file,
                compare_file,
                identifier,
            }) => Mode::Inspect {
                input_file: input_file.clone(),
                compare_file: compare_file.clone(),
                identifier: identifier.clone(),
            },
            Some(Command::Query {
                dump_file,
                query_type,
            }) => Mode::Query {
                dump_file: dump_file.clone(),
                query_type: query_type.clone(),
            },
            Some(Command::Load { dump_file, format }) => Mode::Load {
                dump_file: dump_file.clone(),
                format: format.clone(),
            },
            None => {
                // Default is diff mode
                match (&self.file1, &self.file2) {
                    (Some(file1), Some(file2)) => Mode::Diff {
                        file1: file1.clone(),
                        file2: file2.clone(),
                        format: self.format.clone(),
                        export_mappings: self.export_mappings.clone(),
                        summary: self.summary,
                        verbose: self.verbose,
                        fingerprints: self.fingerprints,
                        compact: self.compact,
                        lite: self.lite,
                        dump: self.dump.clone(),
                    },
                    _ => {
                        eprintln!("Error: Two files required for diff");
                        eprintln!("\nUsage:");
                        eprintln!("  astdiff FILE1 FILE2                    # Compare two JavaScript files");
                        eprintln!("  astdiff FILE1 FILE2 --summary          # Show only summary of changes");
                        eprintln!("  astdiff FILE1 FILE2 --compact          # Show compact location summary");
                        eprintln!(
                            "  astdiff canon INPUT_FILE               # Canonicalize JavaScript"
                        );
                        eprintln!(
                            "  astdiff canon INPUT_FILE --map         # Generate mapping template"
                        );
                        eprintln!("  astdiff canon INPUT_FILE --map MAP.yaml # Apply mappings");
                        eprintln!("\nFor more information, run: astdiff --help");
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum Mode {
    Map(SourceMapCommand),
    Lineage {
        source_file: PathBuf,
        target_file: PathBuf,
        source_map_source: Option<PathBuf>,
        source_map_target: Option<PathBuf>,
        allow_sources_content: bool,
        output: PathBuf,
        min_score_bps: u32,
        min_margin_bps: u32,
        max_candidates: usize,
    },
    Names(NameCommand),
    /// Canonicalize JavaScript (normalize variable names)
    Canonicalize {
        input_file: PathBuf,
        preserve_comments: bool,
        pretty: bool,
    },
    /// Generate mapping template for editing
    GenerateMapping {
        input_file: PathBuf,
        preserve_comments: bool,
        pretty: bool,
    },
    /// Apply edited mappings to create semantic version
    ApplyMapping {
        input_file: PathBuf,
        map_file: PathBuf,
        preserve_comments: bool,
        pretty: bool,
    },
    /// Diff two JavaScript files structurally
    Diff {
        file1: PathBuf,
        file2: PathBuf,
        format: String,
        export_mappings: Option<PathBuf>,
        summary: bool,
        verbose: bool,
        fingerprints: bool,
        compact: bool,
        lite: bool,
        dump: Option<PathBuf>,
    },
    /// Inspect a specific declaration
    Inspect {
        input_file: PathBuf,
        compare_file: Option<PathBuf>,
        identifier: String,
    },
    /// Query information from a dump file
    Query {
        dump_file: PathBuf,
        query_type: QueryType,
    },
    /// Load and display a dump file
    Load {
        dump_file: PathBuf,
        format: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum SourceMapCommand {
    /// Validate a bounded Source Map v3 document
    Validate {
        map_file: PathBuf,
        #[clap(long)]
        allow_sources_content: bool,
    },
    /// Look up one zero-based generated UTF-16 position
    Lookup {
        map_file: PathBuf,
        #[clap(long)]
        line: u32,
        #[clap(long)]
        column: u32,
        #[clap(long)]
        allow_sources_content: bool,
        /// Include source/name strings instead of only their indexes
        #[clap(long)]
        include_source_names: bool,
    },
    /// Compose two maps for one zero-based generated UTF-16 position
    ComposeLookup {
        outer_map: PathBuf,
        inner_map: PathBuf,
        #[clap(long)]
        line: u32,
        #[clap(long)]
        column: u32,
        #[clap(long)]
        allow_sources_content: bool,
        /// Include source/name strings instead of only their indexes
        #[clap(long)]
        include_source_names: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum NameCommand {
    /// Export a bounded review document from JavaScript
    Export {
        input_file: PathBuf,
        #[clap(short, long, value_name = "FILE")]
        output: PathBuf,
        /// Include generated spellings; omitted by default for safe review packets
        #[clap(long)]
        include_generated_names: bool,
    },
    /// Validate a semantic-name review document
    Validate {
        document: PathBuf,
        /// Bind the document to exact source-derived analysis identity
        #[clap(long)]
        source_file: Option<PathBuf>,
    },
    /// Assign a semantic-name suggestion
    Set {
        document: PathBuf,
        symbol_id: String,
        semantic_name: String,
        #[clap(long)]
        expected_revision: u64,
        #[clap(long, default_value = "human")]
        origin: String,
    },
    /// Approve an existing suggestion
    Approve {
        document: PathBuf,
        symbol_id: String,
        #[clap(long)]
        expected_revision: u64,
        #[clap(long, default_value = "human")]
        origin: String,
    },
    /// Reject a suggestion while retaining a tombstone state
    Reject {
        document: PathBuf,
        symbol_id: String,
        #[clap(long)]
        expected_revision: u64,
        #[clap(long, default_value = "human")]
        origin: String,
    },
    /// Clear a semantic name while retaining a tombstone state
    Clear {
        document: PathBuf,
        symbol_id: String,
        #[clap(long)]
        expected_revision: u64,
        #[clap(long, default_value = "human")]
        origin: String,
    },
    /// Propagate approved source names through accepted lineage matches
    Propagate {
        source_names: PathBuf,
        lineage: PathBuf,
        source_file: PathBuf,
        target_file: PathBuf,
        /// Exact raw source map for `source_file`; must be paired with the
        /// target map when propagating a map-bound lineage report.
        #[clap(long, value_name = "FILE", requires = "source_map_target")]
        source_map_source: Option<PathBuf>,
        /// Exact raw source map for `target_file`; must be paired with the
        /// source map.
        #[clap(long, value_name = "FILE", requires = "source_map_source")]
        source_map_target: Option<PathBuf>,
        /// Permit embedded sourcesContent while parsing; content is not kept.
        #[clap(long)]
        allow_sources_content: bool,
        #[clap(short, long, value_name = "FILE")]
        output: PathBuf,
        /// Also write a reconstructed target JavaScript artifact
        #[clap(long, value_name = "FILE")]
        render_output: Option<PathBuf>,
        /// Formatting for a reconstructed artifact
        #[clap(long, default_value = "pretty", value_parser = ["pretty", "preserve"])]
        render_format: String,
    },
    /// Recreate a JavaScript artifact from approved target semantic names
    Render {
        /// Semantic-name document bound to the target artifact
        document: PathBuf,
        /// Target JavaScript input; it is read but never modified
        target_file: PathBuf,
        #[clap(short, long, value_name = "FILE")]
        output: PathBuf,
        /// Formatting for the reconstructed artifact
        #[clap(long, default_value = "pretty", value_parser = ["pretty", "preserve"])]
        format: String,
    },
}
