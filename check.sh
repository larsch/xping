#!/bin/sh -exu
cargo check
cargo check -F anyhow
cargo fmt --check
cargo test
cargo test -F anyhow
cargo clippy --release
cargo clippy --release -F anyhow
