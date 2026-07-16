use crate::args::{
    CodecArgs, CodecKind, Command, CreateArgs, CreateCommon, CreateKind, EnvelopeArg, ExportArgs,
    ExportKind, ExtractArgs, InspectArgs, OtaV1KindArg, OtaV2KindArg, OutputFormat, PayloadViewArg,
    PolicyArg, RecoveryV1KindArg, SerialArgs, VerifyArgs,
};
use kindletool::{
    ArchiveInput, ArchiveOptions, Board, Certificate, DeviceCatalog, DeviceCode, EncodeOptions,
    Error, FirmwareRange, FirmwareRevision, OtaV1Kind, OtaV1Spec, OtaV2Kind, OtaV2Spec, Package,
    PackageEncoder, PackageSpec, PayloadSource, PayloadView, Platform, RecoveryV1Kind,
    RecoveryV1Spec, RecoveryV2Spec, Result, SigningKey, UpdateArchiveBuilder, UserdataSpec,
    ValidationOutcome, VerificationContext, VerificationKey, VerificationPolicy,
};
use serde_json::{Value, json};
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandStatus {
    Success,
    Rejected,
}

pub(crate) fn run(command: Command) -> Result<CommandStatus> {
    match command {
        Command::Inspect(args) => inspect(&args),
        Command::Verify(args) => verify(&args),
        Command::Extract(args) => extract(&args),
        Command::Export(args) => export(args),
        Command::Create(args) => create(args),
        Command::Codec(args) => codec(args),
        Command::Serial(args) => serial(&args),
    }
}

fn inspect(args: &InspectArgs) -> Result<CommandStatus> {
    let input = spool_input(&args.input)?;
    let package = Package::parse(input.reopen()?)?;
    match args.format {
        OutputFormat::Human => print!(
            "{}",
            kindletool::report::render_package_info(package.descriptor(), true)
        ),
        OutputFormat::Json => print_json(&json_document(
            "inspect",
            "parsed",
            &package_json(package.descriptor()),
            &Value::Null,
        ))?,
    }
    Ok(CommandStatus::Success)
}

fn verify(args: &VerifyArgs) -> Result<CommandStatus> {
    let input = spool_input(&args.input)?;
    let mut package = Package::parse(input.reopen()?)?;
    let context = verification_context(
        args.key.as_deref(),
        args.certificate,
        args.archive_key.as_deref(),
        args.device.as_deref(),
        args.firmware,
        args.platform.as_deref(),
        args.board.as_deref(),
    )?;
    let outcome = package.verify(&context, policy(args.policy))?;
    match args.format {
        OutputFormat::Human => print_verification(&outcome),
        OutputFormat::Json => print_json(&json_document(
            "verify",
            if outcome.is_accepted() {
                "accepted"
            } else {
                "rejected"
            },
            &package_json(package.descriptor()),
            &verification_json(&outcome),
        ))?,
    }
    Ok(if outcome.is_accepted() {
        CommandStatus::Success
    } else {
        CommandStatus::Rejected
    })
}

fn extract(args: &ExtractArgs) -> Result<CommandStatus> {
    let input = spool_input(&args.input)?;
    let mut package = Package::parse(input.reopen()?)?;
    let context = verification_context(
        args.key.as_deref(),
        args.certificate,
        args.archive_key.as_deref(),
        None,
        None,
        None,
        None,
    )?;
    let outcome = package.verify(&context, policy(args.policy))?;
    if !outcome.is_accepted() {
        print_verification(&outcome);
        return Ok(CommandStatus::Rejected);
    }
    let mut payload = tempfile::tempfile()?;
    package.copy_payload(PayloadView::Decoded, &mut payload)?;
    payload.seek(SeekFrom::Start(0))?;
    let report = kindletool::extract_archive(payload, &args.output)?;
    println!(
        "Extracted {} entries to {}",
        report.entries(),
        args.output.display()
    );
    Ok(CommandStatus::Success)
}

fn export(args: ExportArgs) -> Result<CommandStatus> {
    match args.kind {
        ExportKind::Payload(args) => {
            let input = spool_input(&args.io.input)?;
            let package = Package::parse(input.reopen()?)?;
            let view = match args.view {
                PayloadViewArg::Decoded => PayloadView::Decoded,
                PayloadViewArg::Stored => PayloadView::Stored,
            };
            staged_output(&args.io.output, |writer| {
                package.copy_payload(view, writer).map(|_| ())
            })?;
        }
        ExportKind::Signature(args) => {
            let input = spool_input(&args.input)?;
            let package = Package::parse(input.reopen()?)?;
            let signature = package
                .descriptor()
                .envelope()
                .ok_or(Error::UnsupportedFormat {
                    operation: "export missing SP01 signature",
                })?
                .signature()
                .to_vec();
            staged_output(&args.output, |writer| {
                writer.write_all(&signature).map_err(Into::into)
            })?;
        }
        ExportKind::Inner(args) => {
            let input = spool_input(&args.input)?;
            let package = Package::parse(input.reopen()?)?;
            staged_output(&args.output, |writer| {
                package.copy_inner(writer).map(|_| ())
            })?;
        }
    }
    Ok(CommandStatus::Success)
}

fn codec(args: CodecArgs) -> Result<CommandStatus> {
    let (io, mangle) = match args.kind {
        CodecKind::Mangle(io) => (io, true),
        CodecKind::Demangle(io) => (io, false),
    };
    let input = spool_input(&io.input)?;
    staged_output(&io.output, |writer| {
        let mut reader = input.reopen()?;
        if mangle {
            io::copy(&mut kindletool::MangleReader::new(&mut reader), writer)?;
        } else {
            io::copy(&mut kindletool::DemangleReader::new(&mut reader), writer)?;
        }
        Ok(())
    })?;
    Ok(CommandStatus::Success)
}

fn serial(args: &SerialArgs) -> Result<CommandStatus> {
    let info = kindletool::serial::serial_info(&args.serial)?;
    println!(
        "Device: {} ({})",
        info.device_name(),
        info.device().serial_code()
    );
    println!("Root password: {}", info.root_password());
    println!("Recovery password: {}", info.recovery_password());
    Ok(CommandStatus::Success)
}

fn create(args: CreateArgs) -> Result<CommandStatus> {
    let (spec, common, block_size) = create_spec(args.kind)?;
    let certificate = Certificate::from_raw(common.certificate)?;
    let signing_key = match &common.key {
        Some(path) => SigningKey::from_pem_file(path)?,
        None => SigningKey::default_jailbreak()?,
    };
    let payload = if let Some(path) = &common.archive {
        if !common.inputs.is_empty() {
            return Err(invalid(
                "inputs",
                "cannot combine positional inputs with --archive",
            ));
        }
        spool_input(path)?
    } else {
        if common.inputs.is_empty() {
            return Err(invalid(
                "inputs",
                "at least one input or --archive is required",
            ));
        }
        let archive = tempfile::NamedTempFile::new()?;
        let writer = archive.reopen()?;
        let inputs = common
            .inputs
            .iter()
            .cloned()
            .map(ArchiveInput::from_source)
            .collect::<Result<Vec<_>>>()?;
        UpdateArchiveBuilder::new(&signing_key)
            .options(ArchiveOptions::new(common.legacy_paths, block_size)?)
            .build(&inputs, writer)?;
        archive
    };
    let signed = match common.envelope {
        EnvelopeArg::Auto => spec.default_envelope(),
        EnvelopeArg::Signed => true,
        EnvelopeArg::None => false,
    };
    let options = if signed {
        EncodeOptions::signed(PayloadSource::Decoded, &signing_key, certificate)?
    } else {
        EncodeOptions::unsigned(PayloadSource::Decoded)
    };
    staged_output(&common.output, |writer| {
        let encode_report =
            PackageEncoder::encode(&spec, payload.reopen()?, &mut *writer, options)?;
        writer.flush()?;
        writer.seek(SeekFrom::Start(0))?;
        let mut package = Package::parse(writer.try_clone()?)?;
        if package.descriptor().format() != encode_report.format() {
            return Err(Error::ArchiveMismatch {
                path: None,
                expected: format!("{:?}", encode_report.format()),
                actual: format!("{:?}", package.descriptor().format()),
            });
        }
        let public_key = signing_key.verification_key();
        let context = VerificationContext::new()
            .with_package_key(certificate, public_key.clone())
            .with_archive_key(public_key);
        let verification_policy = if signed {
            VerificationPolicy::authentic()
        } else {
            VerificationPolicy::structural()
        };
        let outcome = package.verify(&context, verification_policy)?;
        if !outcome.is_accepted() {
            return Err(Error::ArchiveMismatch {
                path: None,
                expected: "self-verified package".to_owned(),
                actual: format!("{:?}", outcome.report()),
            });
        }
        Ok(())
    })?;
    eprintln!("Created {}", common.output.display());
    Ok(CommandStatus::Success)
}

fn create_spec(kind: CreateKind) -> Result<(PackageSpec, CreateCommon, u64)> {
    match kind {
        CreateKind::OtaV1(args) => {
            let revisions = firmware_range(args.source_revision, args.target_revision)?;
            let devices = parse_devices(&[args.device])?;
            if devices.len() != 1 {
                return Err(invalid("device", "OTA V1 requires exactly one device"));
            }
            let kind = match args.kind {
                OtaV1KindArg::Ota => OtaV1Kind::Ota,
                OtaV1KindArg::Versionless => OtaV1Kind::Versionless,
            };
            Ok((
                PackageSpec::OtaV1(OtaV1Spec::new(kind, revisions, devices[0], args.optional)?),
                args.common,
                64,
            ))
        }
        CreateKind::OtaV2(args) => {
            let kind = match args.kind {
                OtaV2KindArg::Ota => OtaV2Kind::Ota,
                OtaV2KindArg::Versionless => OtaV2Kind::Versionless,
                OtaV2KindArg::Language => OtaV2Kind::Language,
            };
            let spec = OtaV2Spec::new(
                kind,
                firmware_range(args.source_revision, args.target_revision)?,
                parse_devices(&args.device)?,
                args.critical,
                args.metadata.into_iter().map(String::into_bytes).collect(),
            )?;
            Ok((PackageSpec::OtaV2(spec), args.common, 64))
        }
        CreateKind::RecoveryV1(args) => {
            let spec = if let Some(target) = args.target_revision {
                if !matches!(args.kind, RecoveryV1KindArg::Fb02) {
                    return Err(invalid("kind", "revision-2 recovery requires FB02"));
                }
                RecoveryV1Spec::revision2(
                    FirmwareRevision::new(target),
                    args.magic1,
                    args.magic2,
                    args.minor,
                    Platform::from_name(&args.platform)?,
                    Board::from_name(&args.board)?,
                )
            } else {
                let device = args
                    .device
                    .as_ref()
                    .ok_or_else(|| invalid("device", "legacy recovery requires --device"))?;
                let devices = parse_devices(std::slice::from_ref(device))?;
                if devices.len() != 1 {
                    return Err(invalid(
                        "device",
                        "legacy recovery requires exactly one device",
                    ));
                }
                let kind = match args.kind {
                    RecoveryV1KindArg::Fb01 => RecoveryV1Kind::Fb01,
                    RecoveryV1KindArg::Fb02 => RecoveryV1Kind::Fb02,
                };
                RecoveryV1Spec::legacy(
                    kind,
                    args.magic1,
                    args.magic2,
                    args.minor,
                    u32::from(devices[0].0),
                )
            };
            Ok((PackageSpec::RecoveryV1(spec), args.common, 131_072))
        }
        CreateKind::RecoveryV2(args) => {
            let spec = RecoveryV2Spec::new(
                FirmwareRevision::new(args.target_revision),
                args.magic1,
                args.magic2,
                args.minor,
                Platform::from_name(&args.platform)?,
                args.header_revision,
                Board::from_name(&args.board)?,
                parse_devices(&args.device)?,
            )?;
            Ok((PackageSpec::RecoveryV2(spec), args.common, 131_072))
        }
        CreateKind::Userdata(args) => Ok((PackageSpec::Userdata(UserdataSpec), args.common, 64)),
    }
}

fn spool_input(path: &Path) -> Result<tempfile::NamedTempFile> {
    let mut temporary = tempfile::NamedTempFile::new()?;
    if path == Path::new("-") {
        io::copy(&mut io::stdin().lock(), &mut temporary)?;
    } else {
        io::copy(&mut File::open(path)?, &mut temporary)?;
    }
    temporary.flush()?;
    Ok(temporary)
}

fn staged_output(path: &Path, operation: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    operation(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    if path == Path::new("-") {
        temporary.as_file_mut().seek(SeekFrom::Start(0))?;
        io::copy(temporary.as_file_mut(), &mut io::stdout().lock())?;
    } else {
        temporary
            .persist(path)
            .map_err(|error| Error::Io(error.error))?;
    }
    Ok(())
}

fn verification_context(
    key: Option<&Path>,
    certificate: u32,
    archive_key: Option<&Path>,
    device: Option<&str>,
    firmware: Option<u64>,
    platform: Option<&str>,
    board: Option<&str>,
) -> Result<VerificationContext> {
    let builtin = SigningKey::default_jailbreak()?.verification_key();
    let mut context = VerificationContext::new()
        .with_package_key(Certificate::Developer, builtin.clone())
        .with_archive_key(builtin);
    if let Some(path) = key {
        let key = VerificationKey::from_pem_file(path)?;
        context = context.with_package_key(Certificate::from_raw(certificate)?, key.clone());
        if archive_key.is_none() {
            context = context.with_archive_key(key);
        }
    }
    if let Some(path) = archive_key {
        context = context.with_archive_key(VerificationKey::from_pem_file(path)?);
    }
    if let Some(device) = device {
        let devices = parse_devices(&[device.to_owned()])?;
        if devices.len() != 1 {
            return Err(invalid(
                "device",
                "target must resolve to exactly one device",
            ));
        }
        context = context.with_target_device(devices[0]);
    }
    if let Some(value) = firmware {
        context = context.with_target_firmware(FirmwareRevision::new(value));
    }
    if let Some(value) = platform {
        context = context.with_target_platform(Platform::from_name(value)?);
    }
    if let Some(value) = board {
        context = context.with_target_board(Board::from_name(value)?);
    }
    Ok(context)
}

fn parse_devices(values: &[String]) -> Result<Vec<DeviceCode>> {
    let include_unknown = std::env::var_os("KT_WITH_UNKNOWN_DEVCODES").is_some();
    let mut output = Vec::new();
    for value in values {
        let parsed = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map_or_else(|| value.parse::<u16>(), |hex| u16::from_str_radix(hex, 16));
        match parsed {
            Ok(code) => output.push(DeviceCode(code)),
            Err(_) => output.extend(DeviceCatalog::expand_alias(value, include_unknown)?),
        }
    }
    Ok(output)
}

fn firmware_range(minimum: u64, maximum: u64) -> Result<FirmwareRange> {
    FirmwareRange::new(
        FirmwareRevision::new(minimum),
        FirmwareRevision::new(maximum),
    )
}

const fn policy(value: PolicyArg) -> VerificationPolicy {
    match value {
        PolicyArg::Structural => VerificationPolicy::structural(),
        PolicyArg::Authentic => VerificationPolicy::authentic(),
    }
}

fn package_json(descriptor: &kindletool::PackageDescriptor) -> Value {
    json!({
        "format": format!("{:?}", descriptor.format()),
        "magic": descriptor.magic().to_string(),
        "envelope": descriptor.envelope().map(|value| json!({"certificate": value.certificate().raw(), "signature_bytes": value.signature().len()})),
        "payload_digest": descriptor.payload_digest().map(|value| format!("{value:?}")),
        "target_devices": descriptor.target_devices().iter().map(|value| value.0).collect::<Vec<_>>(),
        "firmware_range": descriptor.firmware_range().map(|value| json!({"minimum": value.minimum().get(), "maximum": value.maximum().get()})),
        "platform": descriptor.platform().map(Platform::raw),
        "board": descriptor.board().map(Board::raw),
        "archive_kind": descriptor.archive_kind().map(|value| format!("{value:?}")),
        "raw_header_bytes": descriptor.raw_header().len(),
    })
}

fn verification_json(outcome: &ValidationOutcome) -> Value {
    let report = outcome.report();
    json!({
        "signature": format!("{:?}", report.signature()),
        "payload": format!("{:?}", report.payload()),
        "archive": format!("{:?}", report.archive()),
        "target": {
            "device": format!("{:?}", report.target().device()),
            "firmware": format!("{:?}", report.target().firmware()),
            "platform": format!("{:?}", report.target().platform()),
            "board": format!("{:?}", report.target().board()),
        }
    })
}

fn json_document(command: &str, status: &str, package: &Value, verification: &Value) -> Value {
    json!({"schema_version": 1, "command": command, "status": status, "package": package, "verification": verification, "diagnostics": []})
}

fn print_json(value: &Value) -> Result<()> {
    serde_json::to_writer_pretty(io::stdout().lock(), value)
        .map_err(|error| Error::Io(io::Error::other(error)))?;
    println!();
    Ok(())
}

fn print_verification(outcome: &ValidationOutcome) {
    let report = outcome.report();
    println!(
        "Status: {}",
        if outcome.is_accepted() {
            "Accepted"
        } else {
            "Rejected"
        }
    );
    println!("Signature: {:?}", report.signature());
    println!("Payload: {:?}", report.payload());
    println!("Archive: {:?}", report.archive());
    println!("Target device: {:?}", report.target().device());
    println!("Target firmware: {:?}", report.target().firmware());
    println!("Target platform: {:?}", report.target().platform());
    println!("Target board: {:?}", report.target().board());
}

fn invalid(field: &'static str, message: &'static str) -> Error {
    Error::InvalidField {
        field,
        message: message.to_owned(),
    }
}
