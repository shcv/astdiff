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
    Load { dump_file: PathBuf, format: String },
}
