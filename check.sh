#!/bin/sh -exu
cargo check
cargo fmt --check
cargo test
cargo clippy
