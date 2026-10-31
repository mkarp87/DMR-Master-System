#!/usr/bin/env bash
set -euo pipefail
cargo fmt --all
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --workspace --release
if command -v docker >/dev/null 2>&1; then
  docker build -t dmr-master-system:test .
fi
