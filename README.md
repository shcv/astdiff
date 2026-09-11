# astdiff

A high-performance AST-based structural diff tool for JavaScript that intelligently matches renamed functions and variables in minified or obfuscated code.

## Overview

`astdiff` analyzes JavaScript files at the Abstract Syntax Tree (AST) level to identify structural changes between versions, even when functions and variables have been renamed. Unlike traditional text-based diffs, it understands code structure and can match semantically equivalent code blocks.

### Key Features

- **Intelligent Matching**: Uses MinHash signatures and structural fingerprinting to match renamed functions
- **Minified Code Support**: Designed to work with heavily minified/obfuscated JavaScript
- **Fast Performance**: Parallel processing and optimized algorithms handle large files efficiently
- **Multiple Output Formats**: Detailed unified, summary, compact, and JSON outputs
- **Rename Exports**: Save detected old-to-new declaration names as YAML
- **Validated Dumps**: Save and inspect versioned analysis results with integrity checks
- **Analysis IR**: Deterministic, language-neutral AST/scope/symbol data shared by lineage and naming
- **Version Lineage**: Match symbols through identifier-erased structural context with bounded candidate indexes, two-sided margins, and explicit abstention
- **Semantic Name Review**: Export strict bounded JSON, record audited suggestions and approvals, and propagate only approved labels
- **Source Map v3 Queries**: Strict bounded VLQ validation, indexed lookup, and two-map position composition with redacted output defaults

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
./target/release/astdiff --help
```

## Usage

### Basic Diff

Compare two JavaScript files:

```bash
astdiff file1.js file2.js
```

### Output Formats

Choose the amount and representation of output:

```bash
# Detailed unified view (default)
astdiff old.js new.js

# Summary without declaration bodies
astdiff old.js new.js --summary

# Compact location summary
astdiff old.js new.js --compact

# JSON output for programmatic use
astdiff old.js new.js --format json
```

### Advanced Options

```bash
# Export detected declaration renames (old name -> new name)
astdiff old.js new.js --export-mappings renames.yaml

# Save analysis for later load/query inspection
astdiff old.js new.js --dump analysis.astdump
```

### Working with Dumps

Save and inspect analysis results. Dumps are not accepted as inputs to a new
comparison; they are archival/query artifacts.

```bash
# Create a comprehensive dump
astdiff v1.js v2.js --dump comparison.astdump

# Query the dump
astdiff query comparison.astdump find functionName
astdiff query comparison.astdump match functionName
astdiff query comparison.astdump unmatched-from1
astdiff query comparison.astdump validate v1.js v2.js

# Load and display the dump
astdiff load comparison.astdump
```

### Language-neutral analysis

The in-memory `Analysis::from_javascript` adapter records the syntax tree,
lexical scopes and bindings, resolved identifier references, call shapes,
artifact-local IDs, provenance, and explicit unsupported features. Comparison
uses resolved bindings to recognize local renames while retaining changes to
unresolved globals, property names, imported keys, and string contents.

Temporal-dead-zone and flow-sensitive resolution, dynamic call targets, and
matcher fingerprints remain listed as analysis losses. See
[the Analysis IR v1 contract](docs/analysis-ir.org).

Isoform-backed analysis and source-map caches are experimental and maintained
on the separate `isoform-cache` branch. Master builds without Isoform or a
sibling checkout; its analysis, lineage, naming, and raw source-map queries
operate in memory.

### Version lineage and semantic names

Create a redacted lineage report and a semantic-name review document:

```bash
astdiff lineage old.js new.js --output old-to-new.lineage.json
# Optional source-map evidence; both flags are required together.
astdiff lineage old.js new.js --output old-to-new.lineage.json \
  --source-map-source old.js.map --source-map-target new.js.map
astdiff names export old.js --output old.names.json
```

The export omits generated spellings by default. After selecting a symbol ID
from the document, an agent or human can suggest a label; a separate explicit
approval is required before propagation:

```bash
astdiff names set old.names.json SYMBOL_ID semantic_label \
  --expected-revision 0 --origin agent
astdiff names approve old.names.json SYMBOL_ID \
  --expected-revision 1 --origin human
astdiff names validate old.names.json --source-file old.js
astdiff names propagate old.names.json old-to-new.lineage.json \
  old.js new.js --output new.names.json

# Recreate a readable target artifact; the minified input is never modified
astdiff names render new.names.json new.js --output new-readable.js

# Propagation can publish the review document and reconstructed JavaScript together
astdiff names propagate old.names.json old-to-new.lineage.json \
  old.js new.js --output new.names.json --render-output new-readable.js
```

Each edit appends a deterministic audit event and uses an expected revision so
stale edits fail. Only approved labels cross accepted one-to-one matches;
ambiguous or low-margin symbols remain unknown. See
[the lineage and naming contract](docs/lineage.org).

Rendering is an explicit output operation. It applies approved names to target
declarations and resolved references, preserves the target input bytes, and
parse-checks the recreated artifact. `--format preserve` changes only approved
identifier spans; the default `pretty` format uses deterministic indentation
and whitespace.

The staged path from generated fixtures through reproducible public histories
to optional externally provisioned lineage corpora is documented in
[the corpus plan](docs/corpus-plan.org).

Run `tools/benchmark-lineage.sh OLD.js NEW.js RUNS` to record matcher
latency, candidate reduction, expensive comparisons, decisions, truncations,
and deterministic report digests.

### Other Commands

```bash
# Validate and query Source Map v3 coordinates
astdiff map validate bundle.js.map
astdiff map lookup bundle.js.map --line 12 --column 8
astdiff map compose-lookup generated-to-mid.map mid-to-source.map --line 12 --column 8

# Canonicalize JavaScript (normalize variable names)
astdiff canon input.js

# Generate an editable canonical-name mapping
astdiff canon input.js --map

# Apply an edited canonical-name mapping
astdiff canon input.js --map mapping.txt

# Inspect a specific declaration
astdiff inspect file.js functionName
astdiff inspect file.js functionName --compare-file other.js

```

Source-map output uses zero-based UTF-16 columns and emits only source/name
indexes by default. See [the Source Map v3 contract](docs/source-map.org).

## How It Works

1. **Parsing**: Uses tree-sitter to parse JavaScript into ASTs
2. **Declaration Extraction**: Identifies all functions, variables, classes, imports, and exports
3. **Structural Hashing**: Creates hash signatures for each declaration's AST structure
4. **MinHash Signatures**: Generates compact signatures for efficient similarity estimation
5. **Optional Fingerprinting**: With `--fingerprints`, extracts strings, constants, and API calls as matching evidence
6. **Parallel Matching**: Uses parallel algorithms to find best legacy diff matches between declarations
7. **Change Detection**: Identifies additions, deletions, modifications, and renames

## Performance

Optimized for large minified files:
- Parallel extraction and matching algorithms
- Efficient u64-based structural hashing
- MinHash filtering reduces comparison complexity from O(n²) to manageable levels

## Output Interpretation

The tool reports several types of changes:

- **Added/Removed Functions**: New or deleted declarations
- **Modified Functions**: Structurally changed but matched declarations
- **Renamed Functions**: Legacy declaration matches with different names (hidden by default); use `lineage` for evidence-bearing propagation
- **Structural Similarity**: Overall percentage of matched declarations

Example output:
```
Structural similarity: 98.5%
Matched declarations: 7483/7490 vs 7501
Changes: 18 additions, 7 deletions, 10 modifications (+ 7206 renames)
```

## Environment Variables

- `ASTDIFF_DEBUG`: Enable debug output for fingerprint extraction
- `ASTDIFF_PROFILE`: Show performance profiling information

## Building from Source

Requirements:

- Current stable Rust
- A C compiler (for tree-sitter)

```bash
git clone https://github.com/shcv/astdiff
cd astdiff
cargo build --release
```

## License

MIT License - see LICENSE file for details
