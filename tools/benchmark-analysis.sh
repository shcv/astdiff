#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_file=${1:-"$repo_dir/fixtures/regressions/bundle-old.js"}
runs=${2:-3}

if ! [[ $runs =~ ^[1-9][0-9]*$ ]]; then
    echo "RUNS must be a positive integer" >&2
    exit 2
fi
if [[ ! -f $source_file ]]; then
    echo "usage: tools/benchmark-analysis.sh [INPUT.js [RUNS]]" >&2
    exit 2
fi

cargo build --release --manifest-path "$repo_dir/Cargo.toml" --bin astdiff
benchmark_dir=$(mktemp -d "$repo_dir/target/astdiff-analysis.XXXXXX")
trap 'find "$benchmark_dir" -depth -delete' EXIT

printf 'run\tanalyze_seconds\tverify_seconds\tartifact_bytes\tartifact_sha256\n'
for ((run = 1; run <= runs; run++)); do
    artifact="$benchmark_dir/analysis-$run.astir"
    start_ns=$(date +%s%N)
    "$repo_dir/target/release/astdiff" analyze "$source_file" --output "$artifact" \
        >/dev/null
    end_ns=$(date +%s%N)
    analyze_ns=$((end_ns - start_ns))

    start_ns=$(date +%s%N)
    "$repo_dir/target/release/astdiff" analysis "$artifact" summary >/dev/null
    end_ns=$(date +%s%N)
    verify_ns=$((end_ns - start_ns))

    artifact_bytes=$(stat -c %s "$artifact")
    artifact_sha256=$(sha256sum "$artifact" | cut -d' ' -f1)
    awk -v run="$run" -v analyze="$analyze_ns" -v verify="$verify_ns" \
        -v bytes="$artifact_bytes" -v digest="$artifact_sha256" \
        'BEGIN { printf "%d\t%.3f\t%.3f\t%d\t%s\n", run, analyze / 1000000000, verify / 1000000000, bytes, digest }'
done
