//! Command-line frontend for the safe Rust `KindleTool` implementation.
#![forbid(unsafe_code)]

mod args;
mod commands;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = args::Cli::parse();
    match commands::run(cli.command) {
        Ok(commands::CommandStatus::Success) => ExitCode::SUCCESS,
        Ok(commands::CommandStatus::Rejected) => ExitCode::from(1),
        Err(error) => {
            eprintln!("kindletool: {error}");
            ExitCode::from(3)
        }
    }
}
