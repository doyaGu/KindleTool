use crate::args::{
    Command, ConvertArgs, CreateArgs, CreateType, ExtractArgs, HelpArgs, TransformArgs,
};
use kindletool::archive::{
    ArchiveInput, ArchiveOptions, OTA_BLOCK_SIZE, RECOVERY_BLOCK_SIZE, UpdateArchiveBuilder,
    extract_archive,
};
use kindletool::codec::{copy_demangled, copy_mangled};
use kindletool::crypto::md5_hex;
use kindletool::report::{render_package_info, render_shell_metadata};
use kindletool::serial::serial_info;
use kindletool::{
    Board, BundleMagic, Certificate, DeviceCatalog, DeviceCode, DeviceFamily, EncodeOptions, Error,
    FirmwareRange, FirmwareRevision, OtaV1Kind, OtaV1Spec, OtaV2Kind, OtaV2Spec, Package,
    PackageDescriptor, PackageEncoder, PackageHeader, PackageSpec, PayloadDigest, PayloadSource,
    PayloadView, Platform, RecoveryV1Kind, RecoveryV1Spec, RecoveryV2Spec, Result, SigningKey,
    UserdataSpec, VerificationContext, VerificationPolicy,
};
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
    let output = args.output.as_deref().unwrap_or_else(|| Path::new("-"));
    staged_output(output, |writer| {
        if mangle {
            copy_mangled(&mut input, writer)?;
        } else {
            copy_demangled(&mut input, writer)?;
        }
        Ok(())
    })
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
    let package = Package::parse(File::open(input)?)?;
    let descriptor = package.descriptor().clone();
    if args.inspect {
        eprintln!("Checking update package '{}'.", input.display());
        eprint!(
            "{}",
            render_package_info(
                &descriptor,
                std::env::var_os("KT_WITH_UNKNOWN_DEVCODES").is_some()
            )
        );
        dump_metadata(&descriptor)?;
        return reject_android(&descriptor);
    }

    let signature = if effective_signature(args) {
        Some(
            descriptor
                .envelope()
                .ok_or(Error::UnsupportedFormat {
                    operation: "extract missing SP01 signature",
                })?
                .signature()
                .to_vec(),
        )
    } else {
        None
    };
    let expected_hash = descriptor_md5(&descriptor);

    if args.stdout {
        let signature_path = if let Some(bytes) = signature.as_deref() {
            let path = signature_name(input);
            atomic_write(&path, |writer| {
                writer.write_all(bytes)?;
                Ok(())
            })?;
            Some(path)
        } else {
            None
        };
        if let Err(error) = staged_output(Path::new("-"), |writer| {
            convert_to_file(package, writer, args, expected_hash)
        }) {
            if let Some(path) = signature_path {
                let _ = fs::remove_file(path);
            }
            return Err(error);
        }
        return Ok(());
    }

    let output = converted_name(input, args);
    eprintln!("Converting {} to {}", input.display(), output.display());
    atomic_write(&output, |writer| {
        convert_to_file(package, writer, args, expected_hash)
    })?;
    if let Some(bytes) = signature.as_deref() {
        let signature_path = signature_name(input);
        if let Err(error) = atomic_write(&signature_path, |writer| {
            writer.write_all(bytes)?;
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
    let package = Package::parse(input)?;
    let descriptor = package.descriptor().clone();
    if args.inspect {
        write!(
            output,
            "{}",
            render_package_info(
                &descriptor,
                std::env::var_os("KT_WITH_UNKNOWN_DEVCODES").is_some()
            )
        )?;
        dump_metadata(&descriptor)?;
        reject_android(&descriptor)?;
    } else {
        let mut staged = tempfile::tempfile()?;
        convert_to_file(package, &mut staged, args, descriptor_md5(&descriptor))?;
        staged.seek(SeekFrom::Start(0))?;
        io::copy(&mut staged, &mut output)?;
        output.flush()?;
    }
    Ok(())
}

fn convert_payload<R: Read, W: Write>(
    package: Package<R>,
    writer: W,
    args: &ConvertArgs,
) -> Result<()> {
    if effective_unwrap(args) {
        package.copy_inner(writer)?;
    } else {
        let view = if args.fake_sign {
            PayloadView::Stored
        } else {
            PayloadView::Decoded
        };
        package.copy_payload(view, writer)?;
    }
    Ok(())
}

fn convert_to_file<R: Read>(
    package: Package<R>,
    writer: &mut File,
    args: &ConvertArgs,
    expected_hash: Option<kindletool::Md5Digest>,
) -> Result<()> {
    convert_payload(package, &mut *writer, args)?;
    writer.flush()?;
    if !args.fake_sign && !effective_unwrap(args) {
        validate_payload_hash(writer, expected_hash)?;
    }
    Ok(())
}

fn extract(args: &ExtractArgs) -> Result<()> {
    let mut package = Package::parse(File::open(&args.input)?)?;
    let descriptor = package.descriptor().clone();
    eprintln!(
        "Extracting update package '{}' to '{}'.",
        args.input.display(),
        args.output.display()
    );
    eprint!("{}", render_package_info(&descriptor, false));
    if !args.fake_sign {
        let outcome = package.verify(
            &VerificationContext::new(),
            VerificationPolicy::structural(),
        )?;
        if !outcome.is_accepted() {
            return Err(Error::ArchiveMismatch {
                path: None,
                expected: "structurally valid package and update archive".to_owned(),
                actual: format!("{:?}", outcome.report()),
            });
        }
    }
    let expected_hash = descriptor_md5(&descriptor);
    let mut payload = tempfile::tempfile()?;
    let view = if args.fake_sign {
        PayloadView::Stored
    } else {
        PayloadView::Decoded
    };
    package.copy_payload(view, &mut payload)?;
    payload.flush()?;

    if !args.fake_sign {
        validate_payload_hash(&mut payload, expected_hash)?;
    }

    payload.seek(SeekFrom::Start(0))?;
    let report = extract_archive(payload, &args.output)?;
    eprintln!(
        "Extracted {} archive entries to {}",
        report.entries(),
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
        io::copy(&mut File::open(&inputs[0])?, &mut archive)?;
    } else {
        let block_size = if matches!(
            args.package_type,
            CreateType::Recovery | CreateType::Recovery2
        ) {
            RECOVERY_BLOCK_SIZE
        } else {
            OTA_BLOCK_SIZE
        };
        let archive_inputs = inputs
            .iter()
            .cloned()
            .map(ArchiveInput::from_source)
            .collect::<Result<Vec<_>>>()?;
        let report = UpdateArchiveBuilder::new(&key)
            .options(ArchiveOptions::new(args.legacy_paths, block_size)?)
            .build(&archive_inputs, &mut archive)?;
        eprintln!(
            "Archived {} source entries and signed {} files",
            report.source_entries(),
            report.signed_files()
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

    let source = if args.unsigned {
        PayloadSource::Stored
    } else {
        PayloadSource::Decoded
    };
    let signed = !args.unsigned && spec.default_envelope();
    let options = if signed {
        EncodeOptions::signed(source, &key, certificate)?
    } else {
        EncodeOptions::unsigned(source)
    };
    archive.seek(SeekFrom::Start(0))?;
    staged_output(&output, |writer| {
        let report = PackageEncoder::encode(&spec, &mut archive, &mut *writer, options)?;
        writer.flush()?;
        writer.seek(SeekFrom::Start(0))?;
        let mut package = Package::parse(writer.try_clone()?)?;
        if package.descriptor().format() != report.format() {
            return Err(Error::ArchiveMismatch {
                path: None,
                expected: format!("{:?}", report.format()),
                actual: format!("{:?}", package.descriptor().format()),
            });
        }
        let public_key = key.verification_key();
        let context = VerificationContext::new()
            .with_package_key(certificate, public_key.clone())
            .with_archive_key(public_key);
        let policy = if signed {
            VerificationPolicy::authentic()
        } else {
            VerificationPolicy::structural()
        };
        let outcome = package.verify(&context, policy)?;
        if !outcome.is_accepted() {
            return Err(Error::ArchiveMismatch {
                path: None,
                expected: "self-verified package".to_owned(),
                actual: format!("{:?}", outcome.report()),
            });
        }
        Ok(())
    })?;
    if !is_stdio(&output) {
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
            let kind = match magic {
                BundleMagic::Fc02 => OtaV1Kind::Ota,
                BundleMagic::Fd03 => OtaV1Kind::Versionless,
                _ => return invalid("bundle magic", "OTA V1 requires FC02 or FD03"),
            };
            let revisions = FirmwareRange::new(source.into(), target.into())?;
            Ok(PackageSpec::OtaV1(OtaV1Spec::new(
                kind,
                revisions,
                device,
                args.optional,
            )?))
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
            let kind = match magic {
                BundleMagic::Fc04 => OtaV2Kind::Ota,
                BundleMagic::Fd04 => OtaV2Kind::Versionless,
                BundleMagic::Fl01 => OtaV2Kind::Language,
                _ => {
                    return invalid("bundle magic", "OTA V2 requires FC04, FD04, or FL01");
                }
            };
            let mut metadata = args
                .metadata
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect::<Vec<_>>();
            if args.packaging_metadata {
                metadata.extend(packaging_metadata()?);
            }
            Ok(PackageSpec::OtaV2(OtaV2Spec::new(
                kind,
                FirmwareRange::new(source.into(), target.into())?,
                devices.to_vec(),
                args.critical,
                metadata,
            )?))
        }
        CreateType::Recovery => {
            let magic = requested_magic(args, BundleMagic::Fb02)?;
            let kind = match magic {
                BundleMagic::Fb01 => RecoveryV1Kind::Fb01,
                BundleMagic::Fb02 => RecoveryV1Kind::Fb02,
                _ => return invalid("bundle magic", "recovery requires FB01 or FB02"),
            };
            if args.header_revision == 2 && magic != BundleMagic::Fb02 {
                return invalid("header revision", "revision 2 requires FB02");
            }
            if args.header_revision == 2 {
                Ok(PackageSpec::RecoveryV1(RecoveryV1Spec::revision2(
                    FirmwareRevision::new(target),
                    magic_1,
                    magic_2,
                    minor,
                    platform,
                    board,
                )))
            } else {
                Ok(PackageSpec::RecoveryV1(RecoveryV1Spec::legacy(
                    kind,
                    magic_1,
                    magic_2,
                    minor,
                    u32::from(require_single_device(devices, "recovery")?.0),
                )))
            }
        }
        CreateType::Recovery2 => {
            let magic = requested_magic(args, BundleMagic::Fb03)?;
            if magic != BundleMagic::Fb03 {
                return invalid("bundle magic", "recovery V2 requires FB03");
            }
            Ok(PackageSpec::RecoveryV2(RecoveryV2Spec::new(
                FirmwareRevision::new(target),
                magic_1,
                magic_2,
                minor,
                platform,
                args.header_revision,
                board,
                devices.to_vec(),
            )?))
        }
        CreateType::Sig => Ok(PackageSpec::Userdata(UserdataSpec)),
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
                return Ok(serial_info(&serial[..16])?.device());
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
        if result.wario_or_newer() {
            "Wario or newer"
        } else {
            "pre Wario"
        },
        result.device_name()
    );
    eprintln!("Root PW            {}", result.root_password());
    eprintln!("Recovery PW        {}", result.recovery_password());
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

fn dump_metadata(info: &PackageDescriptor) -> Result<()> {
    if let Some(path) = std::env::var_os("KT_PKG_METADATA_DUMP") {
        fs::write(path, render_shell_metadata(info))?;
    }
    Ok(())
}

fn reject_android(info: &PackageDescriptor) -> Result<()> {
    if matches!(info.header(), PackageHeader::Android) {
        Err(Error::UnsupportedFormat {
            operation: "convert Android ZIP payload",
        })
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
        .unwrap_or_else(|| Path::new("."));
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

fn staged_output<F>(path: &Path, action: F) -> Result<()>
where
    F: FnOnce(&mut File) -> Result<()>,
{
    if !is_stdio(path) {
        return atomic_write(path, action);
    }
    let mut temporary = NamedTempFile::new()?;
    action(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut stdout = io::stdout().lock();
    io::copy(temporary.as_file_mut(), &mut stdout)?;
    stdout.flush()?;
    Ok(())
}

fn descriptor_md5(info: &PackageDescriptor) -> Option<kindletool::Md5Digest> {
    match info.payload_digest() {
        Some(PayloadDigest::Md5(digest)) => Some(digest),
        _ => None,
    }
}

fn validate_payload_hash<R: Read + Seek>(
    payload: &mut R,
    expected: Option<kindletool::Md5Digest>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    payload.seek(SeekFrom::Start(0))?;
    let actual = md5_hex(payload)?;
    if actual.eq_ignore_ascii_case(&expected.to_string()) {
        Ok(())
    } else {
        Err(Error::ArchiveMismatch {
            path: None,
            expected: expected.to_string(),
            actual,
        })
    }
}

fn converted_name(input: &Path, args: &ConvertArgs) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
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
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
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
            .is_some_and(|value| value.eq_ignore_ascii_case("tgz"))
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
    use super::{UtcTimestamp, converted_name, parse_u64};
    use crate::args::ConvertArgs;
    use std::path::Path;

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
}
