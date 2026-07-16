use crate::args::{
    Command, ConvertArgs, CreateArgs, CreateType, ExtractArgs, HelpArgs, TransformArgs,
};
use kindletool::archive::{
    ArchiveOptions, OTA_BLOCK_SIZE, RECOVERY_BLOCK_SIZE, UpdateArchiveBuilder, extract_archive,
};
use kindletool::codec::{copy_demangled, copy_mangled};
use kindletool::crypto::{SigningKey, md5_hex};
use kindletool::devices::{DeviceCatalog, DeviceCode, DeviceFamily};
use kindletool::model::{
    Board, BundleMagic, Certificate, OtaV1Header, OtaV2Header, PackageSpec, Platform,
    RecoveryV1Spec, RecoveryV2Header,
};
use kindletool::package::{PackageReader, PackageWriter, SigningConfiguration, WriteOptions};
use kindletool::report::{render_package_info, render_shell_metadata};
use kindletool::serial::serial_info;
use kindletool::{Error, Result};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const OFFICIAL_OTA_SOURCE: u64 = 2_443_670_049;
const OFFICIAL_OTA_TARGET: u64 = 4_556_840_002;

pub(crate) fn run(command: Command) -> Result<()> {
    match command {
        Command::Md(args) => transform(&args, true),
        Command::Dm(args) => transform(&args, false),
        Command::Convert(args) => convert(&args),
        Command::Extract(args) => extract(&args),
        Command::Create(args) => create(&args),
        Command::Info(args) => info(&args.serial),
        Command::Version => version(),
        Command::Help(args) => help(args),
    }
}

fn transform(args: &TransformArgs, mangle: bool) -> Result<()> {
    let mut input: Box<dyn Read> = match args.input.as_deref() {
        None => Box::new(io::stdin()),
        Some(path) if is_stdio(path) => Box::new(io::stdin()),
        Some(path) => Box::new(File::open(path)?),
    };
    let mut output: Box<dyn Write> = match args.output.as_deref() {
        None => Box::new(io::stdout()),
        Some(path) if is_stdio(path) => Box::new(io::stdout()),
        Some(path) => Box::new(File::create(path)?),
    };
    if mangle {
        copy_mangled(&mut input, &mut output)?;
    } else {
        copy_demangled(&mut input, &mut output)?;
    }
    output.flush()?;
    Ok(())
}

fn convert(args: &ConvertArgs) -> Result<()> {
    if args.inputs.len() > 1 && args.inputs.iter().any(|path| is_stdio(path)) {
        return invalid("convert input", "stdin may only be used as the sole input");
    }
    if !args.inspect && !args.fake_sign && args.signature && args.unwrap {
        return invalid(
            "convert mode",
            "signature and unwrap modes are mutually exclusive",
        );
    }
    if effective_signature(args) && args.inputs.iter().any(|path| is_stdio(path)) {
        return invalid(
            "convert input",
            "signature extraction requires a named input file",
        );
    }

    let mut failures = 0_usize;
    for input in &args.inputs {
        let result = if is_stdio(input) {
            convert_stream(io::stdin(), io::stdout(), args)
        } else {
            convert_file(input, args)
        };
        if let Err(error) = result {
            failures += 1;
            eprintln!("kindletool: {}: {error}", input.display());
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        invalid("conversion", format!("{failures} input package(s) failed"))
    }
}

fn convert_file(input: &Path, args: &ConvertArgs) -> Result<()> {
    if !args.inspect && !is_package_path(input) {
        return invalid(
            "convert input",
            format!(
                "{} is neither a .bin update package nor a .stgz userdata package",
                input.display()
            ),
        );
    }
    let file = File::open(input)?;
    let mut reader = PackageReader::new(file)?;
    if args.inspect {
        eprintln!("Checking update package '{}'.", input.display());
        eprint!(
            "{}",
            render_package_info(
                reader.info(),
                std::env::var_os("KT_WITH_UNKNOWN_DEVCODES").is_some()
            )
        );
        dump_metadata(reader.info())?;
        reject_android(reader.info())?;
        return Ok(());
    }

    if args.stdout {
        let signature = if effective_signature(args) {
            let signature = signature_name(input);
            atomic_write(&signature, |writer| {
                reader.copy_signature(writer)?;
                Ok(())
            })?;
            Some(signature)
        } else {
            None
        };
        let mut stdout = io::stdout().lock();
        if let Err(error) = convert_payload(&mut reader, &mut stdout, args)
            .and_then(|()| stdout.flush().map_err(Error::from))
        {
            if let Some(signature) = signature {
                let _ = fs::remove_file(signature);
            }
            return Err(error);
        }
        return Ok(());
    }

    let output = converted_name(input, args);
    let expected_hash = reader.info().header.payload_hash().map(str::to_owned);
    eprintln!("Converting {} to {}", input.display(), output.display());
    atomic_write(&output, |writer| {
        convert_payload(&mut reader, &mut *writer, args)?;
        if !args.fake_sign && !effective_unwrap(args) {
            validate_payload_hash(writer, expected_hash.as_deref())?;
        }
        Ok(())
    })?;
    if effective_signature(args) {
        let signature = signature_name(input);
        if let Err(error) = atomic_write(&signature, |writer| {
            reader.copy_signature(writer)?;
            Ok(())
        }) {
            let _ = fs::remove_file(&output);
            return Err(error);
        }
    }
    if !args.keep {
        fs::remove_file(input)?;
    }
    Ok(())
}

fn convert_stream<R: Read, W: Write>(input: R, mut output: W, args: &ConvertArgs) -> Result<()> {
    let mut reader = PackageReader::new(input)?;
    if args.inspect {
        write!(
            output,
            "{}",
            render_package_info(
                reader.info(),
                std::env::var_os("KT_WITH_UNKNOWN_DEVCODES").is_some()
            )
        )?;
        dump_metadata(reader.info())?;
        reject_android(reader.info())?;
    } else {
        convert_payload(&mut reader, &mut output, args)?;
        output.flush()?;
    }
    Ok(())
}

fn convert_payload<R: Read, W: Write>(
    reader: &mut PackageReader<R>,
    writer: W,
    args: &ConvertArgs,
) -> Result<()> {
    if effective_unwrap(args) {
        reader.copy_unwrapped(writer)?;
    } else {
        reader.copy_decoded_payload(writer, args.fake_sign)?;
    }
    Ok(())
}

fn extract(args: &ExtractArgs) -> Result<()> {
    let source = File::open(&args.input)?;
    let mut package = PackageReader::new(source)?;
    eprintln!(
        "Extracting update package '{}' to '{}'.",
        args.input.display(),
        args.output.display()
    );
    eprint!("{}", render_package_info(package.info(), false));
    let expected_hash = package.info().header.payload_hash().map(str::to_owned);
    let mut payload = tempfile::tempfile()?;
    package.copy_decoded_payload(&mut payload, args.fake_sign)?;
    payload.flush()?;

    if !args.fake_sign {
        validate_payload_hash(&mut payload, expected_hash.as_deref())?;
    }

    payload.seek(SeekFrom::Start(0))?;
    let report = extract_archive(payload, &args.output)?;
    eprintln!(
        "Extracted {} archive entries to {}",
        report.entries,
        args.output.display()
    );
    Ok(())
}

fn create(args: &CreateArgs) -> Result<()> {
    let last = args.paths.last().expect("clap requires an input path");
    let has_output = is_stdio(last) || validate_output_name(last, args).is_ok();
    let (inputs, output) = if has_output {
        (args.paths[..args.paths.len() - 1].to_vec(), last.clone())
    } else {
        (args.paths.clone(), PathBuf::from("-"))
    };
    if inputs.is_empty() {
        return invalid("archive inputs", "at least one input path is required");
    }
    validate_output_name(&output, args)?;
    validate_create_options(args)?;

    let key = load_signing_key(args.key.as_deref())?;
    let certificate = Certificate::try_from(args.certificate)?;
    key.validate_certificate(certificate)?;
    let devices = resolve_devices(&args.devices)?;
    let spec = create_spec(args, &devices)?;
    let prebuilt_archive = inputs.len() == 1 && is_tar_archive(&inputs[0]);

    if args.unsigned && !prebuilt_archive {
        return invalid(
            "unsigned create",
            "requires exactly one prebuilt tar/gzip input",
        );
    }
    if args.package_type == CreateType::Sig && !prebuilt_archive {
        return invalid(
            "signature create",
            "requires exactly one prebuilt tar/gzip input",
        );
    }
    if args.package_type == CreateType::Sig && !args.userdata {
        return invalid("signature create", "requires -U/--userdata");
    }

    let mut archive = tempfile::tempfile()?;
    if prebuilt_archive {
        let mut source = File::open(&inputs[0])?;
        io::copy(&mut source, &mut archive)?;
    } else {
        let block_size = if matches!(
            args.package_type,
            CreateType::Recovery | CreateType::Recovery2
        ) {
            RECOVERY_BLOCK_SIZE
        } else {
            OTA_BLOCK_SIZE
        };
        let report = UpdateArchiveBuilder::new(&key)
            .options(ArchiveOptions {
                legacy_paths: args.legacy_paths,
                block_size,
            })
            .build(&inputs, &mut archive)?;
        eprintln!(
            "Archived {} source entries and signed {} files",
            report.source_entries, report.signed_files
        );
    }
    archive.flush()?;

    if args.keep_archive {
        archive.seek(SeekFrom::Start(0))?;
        let archive_path = intermediate_archive_name(&output);
        atomic_write(&archive_path, |writer| {
            io::copy(&mut archive, writer)?;
            Ok(())
        })?;
        eprintln!("Kept intermediate archive at {}", archive_path.display());
    }

    let signed_envelope = !args.unsigned && should_wrap(&spec);
    let options = WriteOptions {
        fake_sign: args.unsigned,
        signing: signed_envelope.then_some(SigningConfiguration {
            key: &key,
            certificate,
        }),
    };
    archive.seek(SeekFrom::Start(0))?;
    if is_stdio(&output) {
        let mut stdout = io::stdout();
        PackageWriter::new(&mut stdout).write(&spec, &mut archive, options)?;
        stdout.flush()?;
    } else {
        atomic_write(&output, |writer| {
            archive.seek(SeekFrom::Start(0))?;
            PackageWriter::new(writer).write(&spec, &mut archive, options)?;
            Ok(())
        })?;
        eprintln!("Created {}", output.display());
    }
    Ok(())
}

fn create_spec(args: &CreateArgs, devices: &[DeviceCode]) -> Result<PackageSpec> {
    let source = args.source_revision.as_deref().map_or_else(
        || {
            Ok(if args.official_ota {
                OFFICIAL_OTA_SOURCE
            } else {
                0
            })
        },
        |value| parse_revision(value, false),
    )?;
    let target = args.target_revision.as_deref().map_or_else(
        || {
            Ok(if args.official_ota {
                OFFICIAL_OTA_TARGET
            } else {
                maximum_target_revision(args)
            })
        },
        |value| {
            if value.eq_ignore_ascii_case("max") {
                Ok(maximum_target_revision(args))
            } else {
                parse_revision(value, true)
            }
        },
    )?;
    let magic_1 = parse_number(&args.magic_1, "magic 1")?;
    let magic_2 = parse_number(&args.magic_2, "magic 2")?;
    let minor = parse_number(&args.minor, "minor")?;
    let platform = Platform::from_name(&args.platform)?;
    let board = Board::from_name(&args.board)?;

    match args.package_type {
        CreateType::Ota => {
            let device = require_single_device(devices, "OTA V1")?;
            let magic = requested_magic(args, BundleMagic::Fc02)?;
            if !matches!(magic, BundleMagic::Fc02 | BundleMagic::Fd03) {
                return invalid("bundle magic", "OTA V1 requires FC02 or FD03");
            }
            Ok(PackageSpec::OtaV1(OtaV1Header {
                magic,
                source_revision: u32::try_from(source)
                    .map_err(|_| field_range("source revision"))?,
                target_revision: u32::try_from(target)
                    .map_err(|_| field_range("target revision"))?,
                device,
                optional: args.optional,
                md5: String::new(),
            }))
        }
        CreateType::Ota2 => {
            require_devices(devices, "OTA V2")?;
            let default_magic = if devices.iter().all(|device| {
                DeviceCatalog::by_code(*device)
                    .is_some_and(|record| record.family == DeviceFamily::Kindle4)
            }) {
                BundleMagic::Fc04
            } else {
                BundleMagic::Fd04
            };
            let magic = if args.official_ota {
                BundleMagic::Fc04
            } else {
                requested_magic(args, default_magic)?
            };
            if !matches!(
                magic,
                BundleMagic::Fc04 | BundleMagic::Fd04 | BundleMagic::Fl01
            ) {
                return invalid("bundle magic", "OTA V2 requires FC04, FD04, or FL01");
            }
            let mut metadata = args
                .metadata
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect::<Vec<_>>();
            if args.packaging_metadata {
                metadata.extend(packaging_metadata()?);
            }
            Ok(PackageSpec::OtaV2(OtaV2Header {
                magic,
                source_revision: source,
                target_revision: target,
                devices: devices.to_vec(),
                critical: args.critical,
                padding: 0,
                md5: String::new(),
                metadata,
            }))
        }
        CreateType::Recovery => {
            let magic = requested_magic(args, BundleMagic::Fb02)?;
            if !matches!(magic, BundleMagic::Fb01 | BundleMagic::Fb02) {
                return invalid("bundle magic", "recovery requires FB01 or FB02");
            }
            if args.header_revision == 2 && magic != BundleMagic::Fb02 {
                return invalid("header revision", "revision 2 requires FB02");
            }
            if args.header_revision == 2 {
                Ok(PackageSpec::RecoveryV1(RecoveryV1Spec::Revision2 {
                    target_revision: target,
                    magic_1,
                    magic_2,
                    minor,
                    platform,
                    board,
                }))
            } else {
                Ok(PackageSpec::RecoveryV1(RecoveryV1Spec::Legacy {
                    magic,
                    magic_1,
                    magic_2,
                    minor,
                    device: u32::from(require_single_device(devices, "recovery")?.0),
                }))
            }
        }
        CreateType::Recovery2 => {
            let magic = requested_magic(args, BundleMagic::Fb03)?;
            if magic != BundleMagic::Fb03 {
                return invalid("bundle magic", "recovery V2 requires FB03");
            }
            Ok(PackageSpec::RecoveryV2(RecoveryV2Header {
                target_revision: target,
                md5: String::new(),
                magic_1,
                magic_2,
                minor,
                platform,
                header_revision: args.header_revision,
                board,
                devices: devices.to_vec(),
            }))
        }
        CreateType::Sig => Ok(PackageSpec::SignedUserdata),
    }
}

fn resolve_devices(aliases: &[String]) -> Result<Vec<DeviceCode>> {
    let include_unknown = std::env::var_os("KT_WITH_UNKNOWN_DEVCODES").is_some();
    let mut output = Vec::new();
    let mut seen = HashSet::new();
    for alias in aliases {
        let expanded = if alias.eq_ignore_ascii_case("auto") {
            vec![device_from_local_serial()?]
        } else if let Some(record) = DeviceCatalog::by_serial(alias) {
            vec![record.code]
        } else if let Ok(number) = parse_u16_device(alias) {
            vec![DeviceCode(number)]
        } else {
            DeviceCatalog::expand_alias(alias, include_unknown)?
        };
        for device in expanded {
            if seen.insert(device) {
                output.push(device);
            }
        }
    }
    Ok(output)
}

fn device_from_local_serial() -> Result<DeviceCode> {
    for path in ["/proc/usid", "/proc/serial"] {
        if let Ok(value) = fs::read_to_string(path) {
            let serial = value.trim();
            if serial.len() >= 16 {
                return Ok(serial_info(&serial[..16])?.device);
            }
        }
    }
    invalid(
        "device",
        "auto detection requires /proc/usid or /proc/serial",
    )
}

fn load_signing_key(path: Option<&Path>) -> Result<SigningKey> {
    if let Some(path) = path {
        SigningKey::from_pem_file(path)
    } else {
        SigningKey::default_jailbreak()
    }
}

fn info(serial: &str) -> Result<()> {
    let result = serial_info(serial)?;
    eprintln!(
        "Platform is {} [{}]",
        if result.wario_or_newer {
            "Wario or newer"
        } else {
            "pre Wario"
        },
        result.device_name
    );
    eprintln!("Root PW            {}", result.root_password);
    eprintln!("Recovery PW        {}", result.recovery_password);
    Ok(())
}

fn version() -> Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "KindleTool v{VERSION} (Rust rewrite)")?;
    writeln!(stdout, "GPL-3.0-or-later")?;
    Ok(())
}

fn help(args: HelpArgs) -> Result<()> {
    let mut command = crate::args::command();
    if let Some(name) = args.command {
        let subcommand = command
            .find_subcommand_mut(&name)
            .ok_or_else(|| Error::InvalidField {
                field: "help command",
                message: format!("unknown command {name}"),
            })?;
        subcommand.print_long_help()?;
    } else {
        command.print_long_help()?;
    }
    println!();
    Ok(())
}

fn dump_metadata(info: &kindletool::model::PackageInfo) -> Result<()> {
    if let Some(path) = std::env::var_os("KT_PKG_METADATA_DUMP") {
        fs::write(path, render_shell_metadata(info))?;
    }
    Ok(())
}

fn reject_android(info: &kindletool::model::PackageInfo) -> Result<()> {
    if matches!(info.header, kindletool::model::PackageHeader::Android) {
        Err(Error::Unsupported("Android ZIP conversion"))
    } else {
        Ok(())
    }
}

fn atomic_write<F>(path: &Path, action: F) -> Result<()>
where
    F: FnOnce(&mut File) -> Result<()>,
{
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    action(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| Error::Io(error.error))?;
    Ok(())
}

fn validate_payload_hash<R: Read + Seek>(payload: &mut R, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    payload.seek(SeekFrom::Start(0))?;
    let actual = md5_hex(payload)?;
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(Error::Integrity {
            expected: expected.to_owned(),
            actual,
        })
    }
}

fn converted_name(input: &Path, args: &ConvertArgs) -> PathBuf {
    let parent = input.parent().unwrap_or(Path::new("."));
    let name = input
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("update");
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name);
    let suffix = if effective_unwrap(args) {
        if input
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("stgz"))
        {
            "_unwrapped.tgz"
        } else {
            "_unwrapped.bin"
        }
    } else {
        "_converted.tar.gz"
    };
    parent.join(format!("{stem}{suffix}"))
}

fn signature_name(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or(Path::new("."));
    let name = input
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("update");
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name);
    parent.join(format!("{stem}.psig"))
}

fn effective_signature(args: &ConvertArgs) -> bool {
    args.signature && !args.inspect && !args.fake_sign
}

fn effective_unwrap(args: &ConvertArgs) -> bool {
    args.unwrap && !args.inspect && !args.fake_sign
}

fn intermediate_archive_name(output: &Path) -> PathBuf {
    if is_stdio(output) {
        PathBuf::from("kindletool-created.tar.gz")
    } else {
        let mut name = output.as_os_str().to_owned();
        name.push(".tar.gz");
        PathBuf::from(name)
    }
}

fn requested_magic(args: &CreateArgs, default: BundleMagic) -> Result<BundleMagic> {
    args.bundle
        .as_deref()
        .map_or(Ok(default), BundleMagic::from_str)
}

fn should_wrap(spec: &PackageSpec) -> bool {
    matches!(
        spec,
        PackageSpec::OtaV2(_)
            | PackageSpec::RecoveryV2(_)
            | PackageSpec::SignedUserdata
            | PackageSpec::RecoveryV1(RecoveryV1Spec::Revision2 { .. })
    )
}

fn validate_create_options(args: &CreateArgs) -> Result<()> {
    if args.official_ota && args.package_type != CreateType::Ota2 {
        return invalid("official OTA", "-O/--ota is only valid with the ota2 type");
    }
    if args.userdata && args.package_type != CreateType::Sig {
        return invalid(
            "userdata create",
            "-U/--userdata is only valid with the sig type",
        );
    }
    if let Some(metadata) = args.metadata.iter().find(|value| !value.contains('=')) {
        return invalid("metadata", format!("expected key=value, got {metadata}"));
    }
    Ok(())
}

fn require_devices(devices: &[DeviceCode], kind: &'static str) -> Result<()> {
    if devices.is_empty() {
        invalid(
            "devices",
            format!("{kind} requires at least one -d/--device"),
        )
    } else {
        Ok(())
    }
}

fn require_single_device(devices: &[DeviceCode], kind: &'static str) -> Result<DeviceCode> {
    if devices.len() == 1 {
        Ok(devices[0])
    } else {
        invalid(
            "devices",
            format!("{kind} requires exactly one target device"),
        )
    }
}

fn validate_output_name(output: &Path, args: &CreateArgs) -> Result<()> {
    if is_stdio(output) {
        return Ok(());
    }
    let name = output
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let extension = output.extension().and_then(|value| value.to_str());
    if args.package_type == CreateType::Sig || args.unsigned {
        if name.eq_ignore_ascii_case("data.stgz") {
            return Ok(());
        }
        return invalid(
            "output filename",
            "userdata package must be named data.stgz",
        );
    }
    if name
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("update"))
        && extension.is_some_and(|value| value.eq_ignore_ascii_case("bin"))
    {
        Ok(())
    } else {
        invalid(
            "output filename",
            "update package must start with 'update' and end in '.bin'",
        )
    }
}

fn parse_revision(value: &str, maximum: bool) -> Result<u64> {
    if value.eq_ignore_ascii_case("min") {
        Ok(0)
    } else if value.eq_ignore_ascii_case("max") {
        Ok(if maximum { u64::MAX } else { 0 })
    } else {
        parse_u64(value, "revision")
    }
}

const fn maximum_target_revision(args: &CreateArgs) -> u64 {
    match args.package_type {
        CreateType::Ota => u32::MAX as u64,
        CreateType::Recovery if args.header_revision != 2 => u32::MAX as u64,
        CreateType::Ota2 | CreateType::Recovery | CreateType::Recovery2 | CreateType::Sig => {
            u64::MAX
        }
    }
}

fn parse_number(value: &str, field: &'static str) -> Result<u32> {
    u32::try_from(parse_u64(value, field)?).map_err(|_| field_range(field))
}

fn parse_u64(value: &str, field: &'static str) -> Result<u64> {
    let (digits, radix) = if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (value, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    u64::from_str_radix(digits, radix).map_err(|error| Error::InvalidField {
        field,
        message: error.to_string(),
    })
}

fn parse_u16_device(value: &str) -> std::result::Result<u16, ()> {
    let number = if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u16::from_str_radix(value, 16)
    } else {
        value.parse()
    };
    number.map_err(|_| ())
}

fn packaging_metadata() -> Result<Vec<Vec<u8>>> {
    let now = UtcTimestamp::from_system_time(SystemTime::now())?;
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_owned());
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_owned());
    Ok(vec![
        format!("PackagedWith=KindleTool v{VERSION} (Rust)").into_bytes(),
        format!("PackagedBy={user}@{host}").into_bytes(),
        format!(
            "PackagedOn={:04}-{:02}-{:02} @ {:02}:{:02}:{:02} UTC",
            now.year, now.month, now.day, now.hour, now.minute, now.second
        )
        .into_bytes(),
    ])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UtcTimestamp {
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
}

impl UtcTimestamp {
    fn from_system_time(time: SystemTime) -> Result<Self> {
        let duration = time
            .duration_since(UNIX_EPOCH)
            .map_err(|error| Error::InvalidField {
                field: "system clock",
                message: error.to_string(),
            })?;
        Ok(Self::from_unix_seconds(duration.as_secs()))
    }

    fn from_unix_seconds(seconds: u64) -> Self {
        let days = seconds / 86_400;
        let seconds_of_day = seconds % 86_400;

        // Civil calendar conversion by Howard Hinnant, specialized for dates on or after
        // the Unix epoch. Keeping it here avoids a large date/time dependency for one UTC label.
        let shifted_days = days + 719_468;
        let era = shifted_days / 146_097;
        let day_of_era = shifted_days - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let mut year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_position = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_position + 2) / 5 + 1;
        let month = if month_position < 10 {
            month_position + 3
        } else {
            month_position - 9
        };
        year += u64::from(month <= 2);

        Self {
            year,
            month,
            day,
            hour: seconds_of_day / 3_600,
            minute: seconds_of_day % 3_600 / 60,
            second: seconds_of_day % 60,
        }
    }
}

fn is_stdio(path: &Path) -> bool {
    path.as_os_str() == "-"
}

fn is_tar_archive(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    name.get(name.len().saturating_sub(7)..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".tar.gz"))
        || path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| {
                value.eq_ignore_ascii_case("tgz") || value.eq_ignore_ascii_case("tar")
            })
}

fn is_package_path(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("bin") || value.eq_ignore_ascii_case("stgz")
        })
}

fn field_range(field: &'static str) -> Error {
    Error::InvalidField {
        field,
        message: "value is out of range".to_owned(),
    }
}

fn invalid<T>(field: &'static str, message: impl Into<String>) -> Result<T> {
    Err(Error::InvalidField {
        field,
        message: message.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::{UtcTimestamp, converted_name, create_spec, parse_u64, validate_create_options};
    use crate::args::{ConvertArgs, CreateArgs, CreateType};
    use kindletool::devices::DeviceCode;
    use kindletool::model::{BundleMagic, PackageSpec};
    use std::path::{Path, PathBuf};

    #[test]
    fn output_name_matches_legacy_convention() {
        let args = ConvertArgs {
            stdout: false,
            inspect: false,
            keep: false,
            signature: false,
            fake_sign: false,
            unwrap: false,
            inputs: Vec::new(),
        };
        assert_eq!(
            converted_name(Path::new("Update_test.bin"), &args),
            Path::new("Update_test_converted.tar.gz")
        );
    }

    #[test]
    fn numeric_parser_supports_c_base_zero_forms() {
        assert_eq!(parse_u64("0x10", "test").unwrap(), 16);
        assert_eq!(parse_u64("010", "test").unwrap(), 8);
    }

    #[test]
    fn unix_timestamp_conversion_handles_epoch_and_leap_days() {
        assert_eq!(
            UtcTimestamp::from_unix_seconds(0),
            UtcTimestamp {
                year: 1970,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            }
        );
        assert_eq!(
            UtcTimestamp::from_unix_seconds(951_868_799),
            UtcTimestamp {
                year: 2000,
                month: 2,
                day: 29,
                hour: 23,
                minute: 59,
                second: 59,
            }
        );
    }

    #[test]
    fn official_ota_forces_fc04_but_preserves_explicit_revisions() {
        let mut args = create_args(CreateType::Ota2);
        args.official_ota = true;
        args.source_revision = Some("7".to_owned());
        args.target_revision = Some("9".to_owned());
        args.bundle = Some("FD04".to_owned());
        let spec = create_spec(&args, &[DeviceCode(0x201)]).unwrap();
        let PackageSpec::OtaV2(header) = spec else {
            panic!("expected OTA V2");
        };
        assert_eq!(header.magic, BundleMagic::Fc04);
        assert_eq!(header.source_revision, 7);
        assert_eq!(header.target_revision, 9);
    }

    #[test]
    fn ota_v1_uses_the_format_specific_maximum_target_revision() {
        let args = create_args(CreateType::Ota);
        let spec = create_spec(&args, &[DeviceCode(0x06)]).unwrap();
        let PackageSpec::OtaV1(header) = spec else {
            panic!("expected OTA V1");
        };
        assert_eq!(header.target_revision, u32::MAX);
    }

    #[test]
    fn create_mode_flags_reject_incompatible_package_types() {
        let mut recovery = create_args(CreateType::Recovery2);
        recovery.official_ota = true;
        assert!(validate_create_options(&recovery).is_err());

        let mut ota = create_args(CreateType::Ota2);
        ota.userdata = true;
        assert!(validate_create_options(&ota).is_err());

        ota.userdata = false;
        ota.metadata.push("missing-equals".to_owned());
        assert!(validate_create_options(&ota).is_err());
    }

    fn create_args(package_type: CreateType) -> CreateArgs {
        CreateArgs {
            package_type,
            devices: Vec::new(),
            key: None,
            bundle: None,
            source_revision: None,
            target_revision: None,
            magic_1: "0".to_owned(),
            magic_2: "0".to_owned(),
            minor: "0".to_owned(),
            platform: "unspecified".to_owned(),
            board: "unspecified".to_owned(),
            header_revision: 0,
            certificate: 0,
            optional: 0,
            critical: 0,
            metadata: Vec::new(),
            keep_archive: false,
            unsigned: false,
            userdata: false,
            official_ota: false,
            legacy_paths: false,
            packaging_metadata: false,
            help: None,
            paths: vec![PathBuf::from("input.tar.gz")],
        }
    }
}
