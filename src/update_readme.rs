use clap::CommandFactory;

use super::args;

pub fn update_readme() {
    let mut args = args::Args::command();
    let help = args.render_help();

    let readme_infile = std::fs::read_to_string("README.md").unwrap();

    let mut output_lines: Vec<String> = Vec::new();
    let mut in_cli_section = false;
    for line in readme_infile.lines() {
        if line == "<!-- BEGIN CLI -->" {
            output_lines.push(line.to_string());
            output_lines.push("```".to_string());
            output_lines.push(help.to_string());
            output_lines.push("```".to_string());
            in_cli_section = true;
        } else if line == "<!-- END CLI -->" {
            output_lines.push(line.to_string());
            in_cli_section = false;
        } else if !in_cli_section {
            output_lines.push(line.to_string());
        }
    }
    std::fs::write("README.md.part", output_lines.join("\n") + "\n").unwrap();
    std::fs::rename("README.md.part", "README.md").unwrap();
}
