//! Command-line frontend for the safe Rust `KindleTool` implementation.
#![forbid(unsafe_code)]

mod args;
mod commands;

use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = args::parse_from(normalized_args());
    match commands::run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kindletool: {error}");
            ExitCode::FAILURE
        }
    }
}

fn normalized_args() -> Vec<String> {
    let mut args: Vec<String> = std::env::args().collect();
    if let Some(command) = args.get_mut(1) {
        if let Some(value) = command.strip_prefix("--") {
            if matches!(
                value,
                "md" | "dm" | "convert" | "extract" | "create" | "info" | "version" | "help"
            ) {
                *command = value.to_owned();
            }
        }
    }
    args
}
