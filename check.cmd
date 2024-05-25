@echo off
cargo check || exit /b 1
cargo fmt --check || exit /b 1
cargo test || exit /b 1
cargo clippy || exit /b 1
cargo run -- --update-readme 0 || exit /b 1
