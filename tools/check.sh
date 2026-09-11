#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

# Keep test scratch data with the build artifacts. Shared /tmp directories can
# be quota-constrained even when the workspace has ample room, and every file
# created here is reproducible and removable with `cargo clean`.
mkdir -p "$repo_dir/target/tmp"
export TMPDIR="$repo_dir/target/tmp"

cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
shellcheck tools/*.sh
git diff --check
