# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```sh
cargo build                    # Debug build
cargo build --release          # Release build
cargo test                     # Run all tests
cargo test <test_name>         # Run single test
cargo fmt                      # Format code
cargo fmt -- --check           # Check formatting
cargo clippy -- -D warnings    # Lint with warnings as errors
```

## Architecture

astdiff is an AST-based structural diff tool for JavaScript that matches renamed functions/variables in minified code.

### Core Pipeline (src/lib.rs)

1. **Parsing** (`src/parser/`) - tree-sitter JavaScript parser
2. **Scope Analysis** (`src/scope/`) - variable scope tracking
3. **Canonicalization** (`src/canonicalizer/`) - normalize variable names for comparison
4. **Diff Engine** (`src/diff/`) - structural comparison and matching
5. **Analysis IR** (`src/analysis/`) - verified positioned AST/scope/symbol graph
6. **Lineage** (`src/lineage.rs`) - bounded structural-context symbol matching
7. **Semantic Names** (`src/naming.rs`) - strict audited review and propagation

### Diff Matching System (src/diff/)

- `mod.rs` - Main `StructuralDiff` struct, declaration extraction, similarity calculation
- `parallel_matching_v2.rs` - Primary parallel matching algorithm using MinHash signatures
- `fingerprint.rs` - Semantic fingerprints (strings, constants, API calls) for better matching
- `matching_report.rs` - Match-evidence data structures used by scoring
- `profiling.rs` - Performance timing (enabled via `ASTDIFF_PROFILE=1`)

### Key Data Structures

- `Declaration` - Extracted function/variable/class with structural hashes, MinHash signature, and optional fingerprint
- `DeclarationData` - Thread-safe version for parallel processing
- `DiffResult` - Final diff output with similarity score and changes

### Dump System (src/dump.rs)

Serializable analysis results for faster re-runs. Uses bincode + zstd compression.

### CLI (src/cli/)

clap-based CLI with subcommands: diff (default), canon, analyze, analysis,
lineage, names (including explicit target rendering), inspect, query, and load.

## Environment Variables

- `ASTDIFF_DEBUG` - Enable debug output for fingerprint extraction
- `ASTDIFF_PROFILE` - Show performance profiling
