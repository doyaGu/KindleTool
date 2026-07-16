use clap::{ArgAction, Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use kindletool::{Board, BundleMagic, Certificate, DeviceCatalog, Platform};
use std::fmt::Write as _;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "kindletool",
    version,
    about = "Create, inspect, convert, and extract Kindle update packages",
    disable_version_flag = true,
    disable_help_subcommand = true,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

pub(crate) fn parse_from(arguments: Vec<String>) -> Cli {
    let matches = command().get_matches_from(arguments);
    Cli::from_arg_matches(&matches).expect("clap matches its derived CLI model")
}

pub(crate) fn command() -> clap::Command {
    let mut command = Cli::command();
    let create = command
        .find_subcommand_mut("create")
        .expect("derived CLI contains create");
    *create = create.clone().after_long_help(create_catalog_help());
    command
}

fn create_catalog_help() -> String {
    let mut output = String::from(
        "Device aliases (generated from DeviceCatalog; aliases gated by the environment are marked):\n",
    );
    for (name, description) in DeviceCatalog::aliases() {
        let _ = writeln!(output, "  {name:<18} {description}");
    }

    output.push_str("\nPlatforms:\n");
    for (platform, cli_name, display_name) in Platform::known() {
        let _ = writeln!(
            output,
            "  {cli_name:<18} {display_name} ({})",
            platform.raw()
        );
    }

    output.push_str("\nBoards:\n");
    for (board, cli_name, display_name) in Board::known() {
        let _ = writeln!(output, "  {cli_name:<18} {display_name} ({})", board.raw());
    }

    output.push_str("\nBundle magic values:\n");
    for (magic, description) in BundleMagic::known() {
        let _ = writeln!(output, "  {magic:<18} {description}");
    }

    output.push_str("\nCertificates:\n");
    for certificate in Certificate::known() {
        let _ = writeln!(
            output,
            "  {:<18} {} ({}-byte signature)",
            certificate.raw(),
            certificate.label(),
            certificate.signature_len()
        );
    }
    output
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Apply Kindle's byte substitution ("mangle") transform.
    Md(TransformArgs),
    /// Reverse Kindle's byte substitution ("demangle") transform.
    Dm(TransformArgs),
    /// Convert packages to archives, signatures, or unwrapped packages.
    Convert(ConvertArgs),
    /// Extract a package archive into a directory.
    Extract(ExtractArgs),
    /// Create a Kindle update package.
    Create(Box<CreateArgs>),
    /// Print passwords and model information for a Kindle serial number.
    Info(InfoArgs),
    /// Print version and build information.
    Version,
    /// Print general help or help for one command.
    Help(HelpArgs),
}

#[derive(Debug, Args)]
pub(crate) struct TransformArgs {
    /// Input file; stdin when omitted or `-`.
    pub(crate) input: Option<PathBuf>,
    /// Output file; stdout when omitted or `-`.
    pub(crate) output: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ConvertArgs {
    #[arg(short = 'c', long = "stdout")]
    pub(crate) stdout: bool,
    #[arg(short = 'i', long = "info")]
    pub(crate) inspect: bool,
    #[arg(short = 'k', long = "keep")]
    pub(crate) keep: bool,
    #[arg(short = 's', long = "sig")]
    pub(crate) signature: bool,
    #[arg(short = 'u', long = "unsigned")]
    pub(crate) fake_sign: bool,
    #[arg(short = 'w', long = "unwrap")]
    pub(crate) unwrap: bool,
    #[arg(required = true)]
    pub(crate) inputs: Vec<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct ExtractArgs {
    #[arg(short = 'u', long = "unsigned")]
    pub(crate) fake_sign: bool,
    pub(crate) input: PathBuf,
    pub(crate) output: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CreateType {
    Ota,
    Ota2,
    Recovery,
    Recovery2,
    Sig,
}

#[derive(Debug, Args)]
#[command(disable_help_flag = true)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct CreateArgs {
    #[arg(value_enum)]
    pub(crate) package_type: CreateType,
    #[arg(short = 'd', long = "device", action = ArgAction::Append)]
    pub(crate) devices: Vec<String>,
    #[arg(short = 'k', long = "key")]
    pub(crate) key: Option<PathBuf>,
    #[arg(short = 'b', long = "bundle")]
    pub(crate) bundle: Option<String>,
    #[arg(short = 's', long = "srcrev")]
    pub(crate) source_revision: Option<String>,
    #[arg(short = 't', long = "tgtrev")]
    pub(crate) target_revision: Option<String>,
    #[arg(short = '1', long = "magic1", default_value = "0")]
    pub(crate) magic_1: String,
    #[arg(short = '2', long = "magic2", default_value = "0")]
    pub(crate) magic_2: String,
    #[arg(short = 'm', long = "minor", default_value = "0")]
    pub(crate) minor: String,
    #[arg(short = 'p', long = "platform", default_value = "unspecified")]
    pub(crate) platform: String,
    #[arg(short = 'B', long = "board", default_value = "unspecified")]
    pub(crate) board: String,
    #[arg(short = 'h', long = "hdrrev", default_value_t = 0)]
    pub(crate) header_revision: u32,
    #[arg(short = 'c', long = "cert", default_value_t = 0)]
    pub(crate) certificate: u16,
    #[arg(short = 'o', long = "opt", default_value_t = 0)]
    pub(crate) optional: u8,
    #[arg(short = 'r', long = "crit", default_value_t = 0)]
    pub(crate) critical: u8,
    #[arg(short = 'x', long = "meta", action = ArgAction::Append)]
    pub(crate) metadata: Vec<String>,
    #[arg(short = 'a', long = "archive")]
    pub(crate) keep_archive: bool,
    #[arg(short = 'u', long = "unsigned")]
    pub(crate) unsigned: bool,
    #[arg(short = 'U', long = "userdata")]
    pub(crate) userdata: bool,
    #[arg(short = 'O', long = "ota")]
    pub(crate) official_ota: bool,
    #[arg(short = 'C', long = "legacy")]
    pub(crate) legacy_paths: bool,
    #[arg(short = 'X', long = "packaging")]
    pub(crate) packaging_metadata: bool,
    #[arg(long = "help", action = ArgAction::Help)]
    pub(crate) help: Option<bool>,
    #[arg(required = true, num_args = 1..)]
    pub(crate) paths: Vec<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct InfoArgs {
    pub(crate) serial: String,
}

#[derive(Debug, Args)]
pub(crate) struct HelpArgs {
    pub(crate) command: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command, command};
    use clap::Parser;
    use kindletool::DeviceCatalog;

    #[test]
    fn legacy_convert_long_options_are_preserved() {
        let cli = Cli::try_parse_from([
            "kindletool",
            "convert",
            "--stdout",
            "--info",
            "--keep",
            "--sig",
            "--unsigned",
            "--unwrap",
            "update.bin",
        ])
        .expect("legacy convert options should parse");
        let Command::Convert(args) = cli.command else {
            panic!("expected convert command");
        };
        assert!(args.stdout && args.inspect && args.keep && args.signature);
        assert!(args.fake_sign && args.unwrap);
    }

    #[test]
    fn legacy_create_long_options_are_preserved() {
        let cli = Cli::try_parse_from([
            "kindletool",
            "create",
            "ota2",
            "--device",
            "none",
            "--bundle",
            "FD04",
            "--srcrev",
            "min",
            "--tgtrev",
            "max",
            "--magic1",
            "0",
            "--magic2",
            "0",
            "--minor",
            "0",
            "--platform",
            "unspecified",
            "--board",
            "unspecified",
            "--hdrrev",
            "0",
            "--cert",
            "0",
            "--opt",
            "0",
            "--crit",
            "0",
            "--meta",
            "key=value",
            "--packaging",
            "--archive",
            "--ota",
            "--legacy",
            "input.tar.gz",
            "update.bin",
        ])
        .expect("legacy create options should parse");
        let Command::Create(args) = cli.command else {
            panic!("expected create command");
        };
        assert_eq!(args.source_revision.as_deref(), Some("min"));
        assert_eq!(args.target_revision.as_deref(), Some("max"));
        assert_eq!(args.metadata, ["key=value"]);
        assert!(args.packaging_metadata && args.keep_archive);
        assert!(args.official_ota && args.legacy_paths);
    }

    #[test]
    fn create_help_is_generated_from_the_device_catalog() {
        let mut command = command();
        let help = command
            .find_subcommand_mut("create")
            .unwrap()
            .render_long_help()
            .to_string();
        for (alias, _) in DeviceCatalog::aliases() {
            assert!(help.contains(alias), "create help omitted alias {alias}");
        }
        assert!(help.contains("bellatrix3"));
        assert!(help.contains("pubprodkey02.pem"));
        assert!(help.contains("FD04"));
    }
}
