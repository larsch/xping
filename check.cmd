@echo off
cargo check || exit /b 1
cargo check -F anyhow || exit /b 1
cargo fmt --check || exit /b 1
cargo test || exit /b 1
cargo test -F anyhow || exit /b 1
cargo clippy --release || exit /b 1
cargo clippy --release -F anyhow || exit /b 1
wsl --shell-type login sh -c "cd /mnt/d/Prj/ping; ./check.sh" || exit /b 1
cargo run -- --update-readme 0 || exit /b 1
