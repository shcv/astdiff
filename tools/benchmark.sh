#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
old_file=${1:-"$repo_dir/fixtures/regressions/bundle-old.js"}
new_file=${2:-"$repo_dir/fixtures/regressions/bundle-new.js"}
runs=${3:-3}
threads=${RAYON_NUM_THREADS:-4}

if ! [[ $runs =~ ^[1-9][0-9]*$ ]]; then
    echo "RUNS must be a positive integer" >&2
    exit 2
fi
if [[ ! -f $old_file || ! -f $new_file ]]; then
    echo "usage: tools/benchmark.sh [OLD.js NEW.js [RUNS]]" >&2
    exit 2
fi
cargo build --release --manifest-path "$repo_dir/Cargo.toml" --bin astdiff
benchmark_dir=$(mktemp -d)
trap 'find "$benchmark_dir" -depth -delete' EXIT

printf 'run\tseconds\tmax_rss_kib\toutput_sha256\n'
for ((run = 1; run <= runs; run++)); do
    output_file="$benchmark_dir/output-$run.json"
    metrics_file="$benchmark_dir/metrics-$run.txt"
    if [[ -x /usr/bin/time ]]; then
        RAYON_NUM_THREADS=$threads /usr/bin/time -f '%e\t%M' -o "$metrics_file" \
            "$repo_dir/target/release/astdiff" "$old_file" "$new_file" --format json \
            >"$output_file" 2>/dev/null
        read -r seconds max_rss_kib <"$metrics_file"
    else
        start_ns=$(date +%s%N)
        RAYON_NUM_THREADS=$threads \
            "$repo_dir/target/release/astdiff" "$old_file" "$new_file" --format json \
            >"$output_file" 2>/dev/null
        end_ns=$(date +%s%N)
        elapsed_ns=$((end_ns - start_ns))
        seconds=$(awk -v ns="$elapsed_ns" 'BEGIN { printf "%.3f", ns / 1000000000 }')
        max_rss_kib=NA
    fi
    output_sha256=$(sha256sum "$output_file" | cut -d' ' -f1)
    printf '%s\t%s\t%s\t%s\n' "$run" "$seconds" "$max_rss_kib" "$output_sha256"
done
