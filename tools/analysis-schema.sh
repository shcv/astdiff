#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
schema_json=${ANALYSIS_SCHEMA_JSON:-"$repo_dir/schemas/analysis-v1.json"}
schema_artifact=${ANALYSIS_SCHEMA_ARTIFACT:-"$repo_dir/schemas/analysis-v1.isf"}
isoform_dir=${ISOFORM_DIR:-"$repo_dir/../isoform"}
isoform_manifest=${ISOFORM_MANIFEST:-"$isoform_dir/rust/Cargo.toml"}
isoc_bin=${ISOFORM_ISOC:-}

usage() {
    cat >&2 <<EOF
usage: tools/analysis-schema.sh [generate|check|all]

Environment overrides:
  ANALYSIS_SCHEMA_JSON       human-authored JSON (default: schemas/analysis-v1.json)
  ANALYSIS_SCHEMA_ARTIFACT   generated artifact (default: schemas/analysis-v1.isf)
  ISOFORM_DIR                Isoform checkout (default: ../isoform)
  ISOFORM_MANIFEST           Isoform Cargo manifest
  ISOFORM_ISOC               prebuilt isoc binary; otherwise cargo run is used
EOF
}

run_isoc() {
    if [[ -n "$isoc_bin" ]]; then
        "$isoc_bin" "$@"
    else
        cargo run --quiet --manifest-path "$isoform_manifest" --bin isoc -- "$@"
    fi
}

generate() {
    mkdir -p "$(dirname "$schema_artifact")"
    run_isoc from-json "$schema_json" -o "$schema_artifact"
}

check() {
    [[ -f "$schema_json" ]] || { echo "missing schema JSON: $schema_json" >&2; return 2; }
    [[ -f "$schema_artifact" ]] || { echo "missing generated artifact: $schema_artifact (run generate)" >&2; return 2; }

    temporary_artifact=$(mktemp)
    trap 'rm -f "$temporary_artifact"' RETURN
    run_isoc from-json "$schema_json" -o "$temporary_artifact"
    cmp -s "$temporary_artifact" "$schema_artifact" || {
        echo "generated artifact is out of date: $schema_artifact" >&2
        return 1
    }
    run_isoc validate "$schema_artifact"
    run_isoc hash "$schema_artifact" --type Analysis
    run_isoc layout "$schema_artifact" --type Analysis
}

command=${1:-all}
case "$command" in
    generate)
        generate
        ;;
    check)
        check
        ;;
    all)
        generate
        check
        ;;
    -h|--help)
        usage
        ;;
    *)
        usage
        exit 2
        ;;
esac
