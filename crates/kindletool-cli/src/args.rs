use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "kindletool",
    version,
    about = "Inspect, verify, extract, and create Kindle update packages"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Parse package metadata without claiming authenticity.
    Inspect(InspectArgs),
    /// Verify package structure, signatures, archive, and target metadata.
    Verify(VerifyArgs),
    /// Verify and atomically extract a package archive.
    Extract(ExtractArgs),
    /// Export an explicit package representation.
    Export(ExportArgs),
    /// Create a Kindle package.
    Create(CreateArgs),
    /// Apply a Kindle byte codec.
    Codec(CodecArgs),
    /// Print passwords and model information for a serial number.
    Serial(SerialArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum PolicyArg {
    Structural,
    Authentic,
}

#[derive(Debug, Args)]
pub(crate) struct InspectArgs {
    /// Package file, or `-` for stdin.
    pub(crate) input: PathBuf,
    /// Output representation.
    #[arg(long, value_enum, default_value = "human")]
    pub(crate) format: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct VerifyArgs {
    /// Package file, or `-` for stdin.
    pub(crate) input: PathBuf,
    /// Verification policy (authentic by default).
    #[arg(long, value_enum, default_value = "authentic")]
    pub(crate) policy: PolicyArg,
    /// SP01 public key in PKCS#1/SPKI PEM.
    #[arg(long)]
    pub(crate) key: Option<PathBuf>,
    /// Certificate selector associated with --key.
    #[arg(long, default_value_t = 0)]
    pub(crate) certificate: u32,
    /// Archive signature public key; defaults to --key or the built-in developer key.
    #[arg(long)]
    pub(crate) archive_key: Option<PathBuf>,
    /// Optional target device code or alias.
    #[arg(long)]
    pub(crate) device: Option<String>,
    /// Optional target firmware revision.
    #[arg(long)]
    pub(crate) firmware: Option<u64>,
    /// Optional target platform name.
    #[arg(long)]
    pub(crate) platform: Option<String>,
    /// Optional target board name.
    #[arg(long)]
    pub(crate) board: Option<String>,
    /// Output representation.
    #[arg(long, value_enum, default_value = "human")]
    pub(crate) format: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct ExtractArgs {
    /// Package file, or `-` for stdin.
    pub(crate) input: PathBuf,
    /// New or empty destination directory.
    pub(crate) output: PathBuf,
    /// Verification policy (structural by default).
    #[arg(long, value_enum, default_value = "structural")]
    pub(crate) policy: PolicyArg,
    /// SP01 public key.
    #[arg(long)]
    pub(crate) key: Option<PathBuf>,
    /// Certificate selector associated with --key.
    #[arg(long, default_value_t = 0)]
    pub(crate) certificate: u32,
    /// Archive signature public key.
    #[arg(long)]
    pub(crate) archive_key: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    #[command(subcommand)]
    pub(crate) kind: ExportKind,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ExportKind {
    /// Export decoded or exact stored payload bytes.
    Payload(PayloadExportArgs),
    /// Export the raw SP01 signature.
    Signature(IoArgs),
    /// Remove exactly one SP01 envelope.
    Inner(IoArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum PayloadViewArg {
    Decoded,
    Stored,
}

#[derive(Debug, Args)]
pub(crate) struct PayloadExportArgs {
    /// Payload representation; must be explicit.
    #[arg(long, value_enum)]
    pub(crate) view: PayloadViewArg,
    #[command(flatten)]
    pub(crate) io: IoArgs,
}

#[derive(Debug, Args)]
pub(crate) struct IoArgs {
    /// Input file, or `-` for stdin.
    pub(crate) input: PathBuf,
    /// Output file, or `-` for stdout.
    #[arg(short, long)]
    pub(crate) output: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct CodecArgs {
    #[command(subcommand)]
    pub(crate) kind: CodecKind,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CodecKind {
    Mangle(IoArgs),
    Demangle(IoArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SerialArgs {
    pub(crate) serial: String,
}

#[derive(Debug, Args)]
pub(crate) struct CreateArgs {
    #[command(subcommand)]
    pub(crate) kind: CreateKind,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CreateKind {
    OtaV1(OtaV1Args),
    OtaV2(OtaV2Args),
    RecoveryV1(RecoveryV1Args),
    RecoveryV2(RecoveryV2Args),
    Userdata(UserdataArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum EnvelopeArg {
    Auto,
    Signed,
    None,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OtaV1KindArg {
    Ota,
    Versionless,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OtaV2KindArg {
    Ota,
    Versionless,
    Language,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum RecoveryV1KindArg {
    Fb01,
    Fb02,
}

#[derive(Debug, Args)]
pub(crate) struct CreateCommon {
    /// Final package path; `-` writes staged output to stdout.
    #[arg(short, long)]
    pub(crate) output: PathBuf,
    /// Use this prebuilt archive instead of building inputs.
    #[arg(long)]
    pub(crate) archive: Option<PathBuf>,
    /// SP01 envelope policy.
    #[arg(long, value_enum, default_value = "auto")]
    pub(crate) envelope: EnvelopeArg,
    /// PKCS#1/PKCS#8 private key; defaults to the jailbreak key.
    #[arg(long)]
    pub(crate) key: Option<PathBuf>,
    /// Certificate selector.
    #[arg(long, default_value_t = 0)]
    pub(crate) certificate: u32,
    /// Preserve legacy archive path semantics.
    #[arg(long)]
    pub(crate) legacy_paths: bool,
    /// Files and directories added in command-line order.
    pub(crate) inputs: Vec<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct OtaV1Args {
    #[arg(long, value_enum, default_value = "ota")]
    pub(crate) kind: OtaV1KindArg,
    #[arg(long)]
    pub(crate) source_revision: u64,
    #[arg(long)]
    pub(crate) target_revision: u64,
    #[arg(long)]
    pub(crate) device: String,
    #[arg(long, default_value_t = 0)]
    pub(crate) optional: u8,
    #[command(flatten)]
    pub(crate) common: CreateCommon,
}

#[derive(Debug, Args)]
pub(crate) struct OtaV2Args {
    #[arg(long, value_enum, default_value = "ota")]
    pub(crate) kind: OtaV2KindArg,
    #[arg(long)]
    pub(crate) source_revision: u64,
    #[arg(long)]
    pub(crate) target_revision: u64,
    #[arg(long, required = true)]
    pub(crate) device: Vec<String>,
    #[arg(long, default_value_t = 0)]
    pub(crate) critical: u8,
    #[arg(long)]
    pub(crate) metadata: Vec<String>,
    #[command(flatten)]
    pub(crate) common: CreateCommon,
}

#[derive(Debug, Args)]
pub(crate) struct RecoveryV1Args {
    #[arg(long, value_enum, default_value = "fb02")]
    pub(crate) kind: RecoveryV1KindArg,
    #[arg(long)]
    pub(crate) target_revision: Option<u64>,
    #[arg(long, default_value_t = 0)]
    pub(crate) magic1: u32,
    #[arg(long, default_value_t = 0)]
    pub(crate) magic2: u32,
    #[arg(long, default_value_t = 0)]
    pub(crate) minor: u32,
    #[arg(long)]
    pub(crate) device: Option<u32>,
    #[arg(long, default_value = "unspecified")]
    pub(crate) platform: String,
    #[arg(long, default_value = "unspecified")]
    pub(crate) board: String,
    #[command(flatten)]
    pub(crate) common: CreateCommon,
}

#[derive(Debug, Args)]
pub(crate) struct RecoveryV2Args {
    #[arg(long)]
    pub(crate) target_revision: u64,
    #[arg(long, default_value_t = 0)]
    pub(crate) magic1: u32,
    #[arg(long, default_value_t = 0)]
    pub(crate) magic2: u32,
    #[arg(long, default_value_t = 0)]
    pub(crate) minor: u32,
    #[arg(long, default_value = "unspecified")]
    pub(crate) platform: String,
    #[arg(long, default_value_t = 2)]
    pub(crate) header_revision: u32,
    #[arg(long, default_value = "unspecified")]
    pub(crate) board: String,
    #[arg(long, required = true)]
    pub(crate) device: Vec<String>,
    #[command(flatten)]
    pub(crate) common: CreateCommon,
}

#[derive(Debug, Args)]
pub(crate) struct UserdataArgs {
    #[command(flatten)]
    pub(crate) common: CreateCommon,
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command, ExportKind};
    use clap::Parser;

    #[test]
    fn new_commands_parse_and_legacy_commands_do_not() {
        assert!(matches!(
            Cli::try_parse_from(["kindletool", "inspect", "update.bin"])
                .unwrap()
                .command,
            Command::Inspect(_)
        ));
        assert!(
            matches!(Cli::try_parse_from(["kindletool", "export", "payload", "--view", "stored", "in.bin", "--output", "-"]).unwrap().command, Command::Export(args) if matches!(args.kind, ExportKind::Payload(_)))
        );
        assert!(Cli::try_parse_from(["kindletool", "convert", "update.bin"]).is_err());
        assert!(Cli::try_parse_from(["kindletool", "md"]).is_err());
    }
}
