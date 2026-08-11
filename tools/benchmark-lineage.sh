#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_file=${1:-"$repo_dir/fixtures/regressions/bundle-old.js"}
target_file=${2:-"$repo_dir/fixtures/regressions/bundle-new.js"}
runs=${3:-3}

if ! [[ $runs =~ ^[1-9][0-9]*$ ]] || [[ ! -f $source_file ]] || [[ ! -f $target_file ]]; then
    echo "usage: tools/benchmark-lineage.sh [OLD.js NEW.js [RUNS]]" >&2
    exit 2
fi

cargo build --release --manifest-path "$repo_dir/Cargo.toml" --bin astdiff
benchmark_dir=$(mktemp -d "$repo_dir/target/astdiff-lineage.XXXXXX")
trap 'find "$benchmark_dir" -depth -delete' EXIT

printf 'run\tseconds\tsource_symbols\ttarget_symbols\tcandidates\texpensive\taccepted\tabstained\tadded\tambiguous_targets\ttruncated\tsha256\n'
for ((run = 1; run <= runs; run++)); do
    report="$benchmark_dir/lineage-$run.json"
    summary="$benchmark_dir/summary-$run.json"
    start_ns=$(date +%s%N)
    "$repo_dir/target/release/astdiff" lineage "$source_file" "$target_file" \
        --output "$report" >"$summary"
    end_ns=$(date +%s%N)
    elapsed_ns=$((end_ns - start_ns))
    report_sha256=$(sha256sum "$report" | cut -d' ' -f1)
    python - "$run" "$elapsed_ns" "$report" "$report_sha256" <<'PY'
import json
import sys

run, elapsed_ns, path, digest = sys.argv[1:]
with open(path, "r", encoding="utf-8") as stream:
    stats = json.load(stream)["stats"]
print(
    f"{run}\t{int(elapsed_ns) / 1_000_000_000:.3f}\t"
    f"{stats['source_symbols']}\t{stats['target_symbols']}\t"
    f"{stats['candidate_pairs']}\t{stats['expensive_comparisons']}\t"
    f"{stats['accepted']}\t{stats['abstained']}\t{stats['added']}\t"
    f"{stats['ambiguous_targets']}\t"
    f"{stats['truncated_sources']}\t{digest}"
)
PY
done
