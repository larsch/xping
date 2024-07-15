use clap::CommandFactory;
use clap_complete::{
    generate_to,
    shells::{Bash, Fish, Zsh},
};

#[cfg(unix)]
include!("src/args.rs");

#[cfg(unix)]
fn generate_completions() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let mut cmd = Args::command();
    generate_to(Bash, &mut cmd, "xping", &out_dir).unwrap();
    generate_to(Fish, &mut cmd, "xping", &out_dir).unwrap();
    generate_to(Zsh, &mut cmd, "xping", &out_dir).unwrap();
}

fn main() {
    #[cfg(unix)]
    generate_completions();
}
