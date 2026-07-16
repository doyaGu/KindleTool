use crate::archive::{ComponentContentCheck, UpdateArchiveVerifier};
use crate::codec::{DemangleReader, copy_demangled, copy_mangled, demangle, mangle};
use crate::crypto::{SigningKey, md5_hex, md5_hex_reader};
use crate::devices::DeviceCode;
use crate::format::{HeaderLayout, PayloadStorage};
use crate::model::{
    Board, BundleMagic, Certificate, ComponentHeader, OTA_V1_HEADER_LEN, OtaV1Header, OtaV2Header,
    OtaV2Spec, PackageDescriptor, PackageHeader, PackageSpec, Platform, RECOVERY_HEADER_LEN,
    RecoveryV1Header, RecoveryV1Layout, RecoveryV1Spec, RecoveryV2Header, RecoveryV2Spec,
    SIGNATURE_HEADER_LEN, SignatureEnvelope,
};
use crate::verification::{
    ArchiveCheck, PayloadIntegrityCheck, SignatureCheck, ValidationOutcome, VerificationContext,
    VerificationPolicy, VerificationReport, accepts, target_check,
};
use crate::{Error, FirmwareRange, Md5Digest, Result};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::str::FromStr;

const OTA_V2_FIXED_1: usize = 18;
const OTA_V2_FIXED_2: usize = 36;
const DEFAULT_MAX_METADATA_ITEMS: usize = 4096;
const DEFAULT_MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;

/// Interpretation of payload bytes supplied to [`PackageEncoder`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadSource {
    /// Input bytes are decoded content and normal format transforms should be applied.
    Decoded,
    /// Input bytes are already in their exact on-disk representation.
    Stored,
}

/// Payload representation copied from a parsed package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadView {
    /// Decode the format's normal payload transform.
    Decoded,
    /// Preserve the exact stored payload bytes.
    Stored,
}

/// Explicit package encoding behavior.
#[derive(Clone, Copy, Debug)]
pub struct EncodeOptions<'key> {
    source: PayloadSource,
    signing: Option<SigningConfiguration<'key>>,
}

impl<'key> EncodeOptions<'key> {
    /// Encode without an SP01 envelope.
    #[must_use]
    pub const fn unsigned(source: PayloadSource) -> Self {
        Self {
            source,
            signing: None,
        }
    }

    /// Encode with an SP01 envelope.
    pub fn signed(
        source: PayloadSource,
        key: &'key SigningKey,
        certificate: Certificate,
    ) -> Result<Self> {
        key.validate_certificate(certificate)?;
        Ok(Self {
            source,
            signing: Some(SigningConfiguration { key, certificate }),
        })
    }
}

/// Summary of one package encoding operation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EncodeReport {
    format: crate::PackageFormat,
    payload_bytes: u64,
    output_bytes: u64,
    payload_digest: Option<crate::Md5Digest>,
    envelope: Option<Certificate>,
}

impl EncodeReport {
    /// Encoded package format.
    #[must_use]
    pub const fn format(&self) -> crate::PackageFormat {
        self.format
    }

    /// Number of source payload bytes consumed.
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    /// Number of package bytes written.
    #[must_use]
    pub const fn output_bytes(&self) -> u64 {
        self.output_bytes
    }

    /// MD5 of the decoded payload when the format stores one.
    #[must_use]
    pub const fn payload_digest(&self) -> Option<crate::Md5Digest> {
        self.payload_digest
    }

    /// Whether an SP01 envelope was emitted.
    #[must_use]
    pub const fn envelope(&self) -> Option<Certificate> {
        self.envelope
    }
}

/// High-level package encoder with explicit payload and signing semantics.
pub struct PackageEncoder;

impl PackageEncoder {
    /// Encode one package, spooling the input so callers only need [`Read`].
    pub fn encode<R: Read, W: Write>(
        spec: &PackageSpec,
        mut payload: R,
        output: W,
        options: EncodeOptions<'_>,
    ) -> Result<EncodeReport> {
        let mut spool = tempfile::tempfile()?;
        let payload_bytes = io::copy(&mut payload, &mut spool)?;
        spool.seek(SeekFrom::Start(0))?;

        let profile = spec.magic().profile();
        debug_assert!(profile.writable());
        let payload_digest = if matches!(spec, PackageSpec::Userdata(_)) {
            None
        } else {
            let text = match options.source {
                PayloadSource::Decoded => md5_hex(&mut spool)?,
                PayloadSource::Stored => {
                    let digest = with_preserved_position(&mut spool, |reader| {
                        md5_hex_reader(DemangleReader::new(reader))
                    })?;
                    spool.seek(SeekFrom::Start(0))?;
                    digest
                }
            };
            Some(crate::Md5Digest::from_str(&text)?)
        };

        let write_options = WriteOptions {
            fake_sign: matches!(options.source, PayloadSource::Stored),
            signing: options.signing,
        };
        let output_bytes = PackageWriter::new(output).write(spec, &mut spool, write_options)?;
        Ok(EncodeReport {
            format: profile.format(),
            payload_bytes,
            output_bytes,
            payload_digest,
            envelope: options.signing.map(|signing| signing.certificate),
        })
    }
}

/// Parsed package whose consuming operations cannot be called twice.
pub struct Package<R> {
    inner: PackageReader<R>,
}

impl<R: Read> Package<R> {
    /// Parse with default resource limits.
    pub fn parse(reader: R) -> Result<Self> {
        Ok(Self {
            inner: PackageReader::new(reader)?,
        })
    }

    /// Parse with explicit resource limits.
    pub fn parse_with_limits(reader: R, limits: ParseLimits) -> Result<Self> {
        Ok(Self {
            inner: PackageReader::with_limits(reader, limits)?,
        })
    }

    /// Parsed descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &crate::model::PackageDescriptor {
        self.inner.info()
    }

    /// Copy one payload representation and consume the package.
    pub fn copy_payload<W: Write>(mut self, view: PayloadView, writer: W) -> Result<u64> {
        self.inner
            .copy_decoded_payload(writer, matches!(view, PayloadView::Stored))
    }

    /// Remove exactly one SP01 envelope and consume the package.
    pub fn copy_inner<W: Write>(mut self, writer: W) -> Result<u64> {
        self.inner.copy_unwrapped(writer)
    }

    /// Return the source reader positioned at the stored payload.
    #[must_use]
    pub fn into_reader(self) -> R {
        self.inner.into_inner()
    }
}

impl<R: Read + Seek> Package<R> {
    /// Verify this package while preserving the stored-payload position.
    pub fn verify(
        &mut self,
        context: &VerificationContext,
        policy: VerificationPolicy,
    ) -> Result<ValidationOutcome> {
        let signature = verify_signature(&mut self.inner, context)?;
        let mut payload = verify_payload_integrity(&mut self.inner)?;
        let (archive, archive_report) =
            verify_archive(&mut self.inner, context, policy, &mut payload)?;
        let target = target_check(self.inner.info(), context);
        let report = VerificationReport::new(signature, payload, archive, archive_report, target);
        Ok(if accepts(policy, &report) {
            ValidationOutcome::Accepted(report)
        } else {
            ValidationOutcome::Rejected(report)
        })
    }
}

/// Limits used while parsing untrusted package headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    /// Maximum OTA V2 metadata item count accepted by the parser.
    pub(crate) max_metadata_items: usize,
    /// Maximum combined OTA V2 metadata value bytes accepted by the parser.
    pub(crate) max_metadata_bytes: usize,
}

impl ParseLimits {
    /// Construct explicit non-zero OTA metadata limits.
    pub fn new(max_metadata_items: usize, max_metadata_bytes: usize) -> Result<Self> {
        if max_metadata_items == 0 || max_metadata_bytes == 0 {
            return Err(Error::InvalidField {
                field: "parse limits",
                message: "all limits must be greater than zero".to_owned(),
            });
        }
        Ok(Self {
            max_metadata_items,
            max_metadata_bytes,
        })
    }
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_metadata_items: DEFAULT_MAX_METADATA_ITEMS,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
        }
    }
}

/// Local signing configuration used by [`PackageWriter`].
#[derive(Clone, Copy, Debug)]
struct SigningConfiguration<'key> {
    /// RSA private key.
    pub key: &'key SigningKey,
    /// Kindle certificate selector written to SP01.
    pub certificate: Certificate,
}

/// Package encoding behavior.
#[derive(Clone, Copy, Debug, Default)]
struct WriteOptions<'key> {
    /// Leave payload bytes unmangled and do not implicitly add SP01.
    pub fake_sign: bool,
    /// Optional SP01 signing configuration.
    pub signing: Option<SigningConfiguration<'key>>,
}

/// Streaming Kindle package reader.
struct PackageReader<R> {
    reader: R,
    info: PackageDescriptor,
}

impl<R: Read> PackageReader<R> {
    /// Parse a package with default safety limits.
    pub fn new(reader: R) -> Result<Self> {
        Self::with_limits(reader, ParseLimits::default())
    }

    /// Parse a package with explicit safety limits.
    pub fn with_limits(mut reader: R, options: ParseLimits) -> Result<Self> {
        let outer_magic_bytes = read_array::<4, _>(&mut reader, "bundle magic")?;
        let outer_magic = BundleMagic::from_bytes(outer_magic_bytes)?;

        let envelope = if outer_magic == BundleMagic::Sp01 {
            let header = read_vec(&mut reader, SIGNATURE_HEADER_LEN, "SP01 header")?;
            let certificate = Certificate::from_raw(u32::from_le_bytes(
                header[0..4].try_into().expect("fixed slice"),
            ))?;
            let signature = read_vec(&mut reader, certificate.signature_len(), "SP01 signature")?;
            Some(SignatureEnvelope {
                certificate,
                reserved: header[4..].to_vec(),
                signature,
            })
        } else {
            None
        };

        let inner_magic_bytes = if envelope.is_some() {
            read_array::<4, _>(&mut reader, "inner bundle magic")?
        } else {
            outer_magic_bytes
        };
        let inner_magic = BundleMagic::from_bytes(inner_magic_bytes)?;
        if inner_magic == BundleMagic::Sp01 {
            return Err(Error::InvalidField {
                field: "signature envelope",
                message: "nested SP01 envelopes are not supported".to_owned(),
            });
        }

        let (header, raw_tail) = parse_inner_header(&mut reader, inner_magic, options)?;
        let mut encoded_inner_header = Vec::with_capacity(4 + raw_tail.len());
        encoded_inner_header.extend_from_slice(&inner_magic_bytes);
        encoded_inner_header.extend_from_slice(&raw_tail);

        Ok(Self {
            reader,
            info: PackageDescriptor {
                header,
                envelope,
                raw_inner_header: encoded_inner_header,
            },
        })
    }

    /// Parsed package information.
    #[must_use]
    pub const fn info(&self) -> &PackageDescriptor {
        &self.info
    }

    /// Consume the parser and return the underlying reader at the payload offset.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Write the decoded tar/gzip payload.
    pub fn copy_decoded_payload<W: Write>(
        &mut self,
        mut writer: W,
        fake_sign: bool,
    ) -> Result<u64> {
        match (&self.info.header, fake_sign) {
            (PackageHeader::Android, false) => Err(Error::UnsupportedFormat {
                operation: "decode Android ZIP payload",
            }),
            (PackageHeader::Android, true) => {
                writer.write_all(&BundleMagic::Zip.as_bytes())?;
                Ok(4 + io::copy(&mut self.reader, &mut writer)?)
            }
            (PackageHeader::Userdata { magic }, _) => {
                writer.write_all(magic)?;
                Ok(4 + io::copy(&mut self.reader, &mut writer)?)
            }
            (_, true) => Ok(io::copy(&mut self.reader, &mut writer)?),
            _ => Ok(copy_demangled(&mut self.reader, &mut writer)?),
        }
    }

    /// Write the exact inner package, removing one outer SP01 envelope.
    pub fn copy_unwrapped<W: Write>(&mut self, mut writer: W) -> Result<u64> {
        if self.info.envelope.is_none() {
            return Err(Error::UnsupportedFormat {
                operation: "unwrap package without SP01",
            });
        }
        writer.write_all(&self.info.raw_inner_header)?;
        Ok(self.info.raw_inner_header.len() as u64 + io::copy(&mut self.reader, &mut writer)?)
    }
}

fn verify_payload_integrity<R: Read + Seek>(
    package: &mut PackageReader<R>,
) -> Result<PayloadIntegrityCheck> {
    let Some(expected) = package.info.header.payload_digest() else {
        return Ok(if package.info.header.component_sha256().is_some() {
            PayloadIntegrityCheck::UnsupportedScope
        } else {
            PayloadIntegrityCheck::NotPresent
        });
    };
    let actual = with_preserved_position(&mut package.reader, |reader| {
        Md5Digest::from_str(&md5_hex_reader(DemangleReader::new(reader))?)
    })?;
    Ok(if actual == expected {
        PayloadIntegrityCheck::Valid { digest: actual }
    } else {
        PayloadIntegrityCheck::Invalid { expected, actual }
    })
}

fn verify_signature<R: Read + Seek>(
    package: &mut PackageReader<R>,
    context: &VerificationContext,
) -> Result<SignatureCheck> {
    let Some(envelope) = package.info.envelope.as_ref() else {
        return Ok(SignatureCheck::Unsigned);
    };
    let certificate = envelope.certificate;
    let Some(key) = context.package_key(certificate) else {
        return Ok(SignatureCheck::MissingKey { certificate });
    };
    if key.size() != certificate.signature_len() {
        return Ok(SignatureCheck::KeyMismatch { certificate });
    }
    let valid = with_preserved_position(&mut package.reader, |reader| {
        let signed_bytes =
            std::io::Cursor::new(package.info.raw_inner_header.as_slice()).chain(reader);
        key.verify_reader(signed_bytes, &envelope.signature)
    })?;
    Ok(if valid {
        SignatureCheck::Valid { certificate }
    } else {
        SignatureCheck::Invalid { certificate }
    })
}

fn verify_archive<R: Read + Seek>(
    package: &mut PackageReader<R>,
    context: &VerificationContext,
    policy: VerificationPolicy,
    payload: &mut PayloadIntegrityCheck,
) -> Result<(ArchiveCheck, Option<crate::ArchiveVerificationReport>)> {
    let descriptor = package.info();
    let Some(kind) = descriptor.archive_kind() else {
        return Ok((ArchiveCheck::NotArchive, None));
    };
    let storage = descriptor.magic().profile().payload_storage;
    let gzip_magic = match descriptor.header() {
        PackageHeader::Userdata { magic } => Some(*magic),
        _ => None,
    };
    let expected_component = descriptor.header().component_sha256();
    let mut decoded = with_preserved_position(&mut package.reader, |reader| {
        let mut decoded = tempfile::tempfile()?;
        if let Some(magic) = gzip_magic {
            decoded.write_all(&magic)?;
        }
        match storage {
            PayloadStorage::Mangled => {
                copy_demangled(reader, &mut decoded)?;
            }
            PayloadStorage::Raw => {
                io::copy(reader, &mut decoded)?;
            }
        }
        Ok(decoded)
    })?;
    decoded.seek(SeekFrom::Start(0))?;
    let report =
        match UpdateArchiveVerifier::new(kind, policy, context.archive_key(), context.limits())
            .verify(decoded)
        {
            Ok(report) => report,
            Err(Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::InvalidData
                        | io::ErrorKind::InvalidInput
                        | io::ErrorKind::UnexpectedEof
                ) =>
            {
                let report = crate::ArchiveVerificationReport::malformed();
                return Ok((ArchiveCheck::Invalid, Some(report)));
            }
            Err(error) => return Err(error),
        };
    if let Some(expected) = expected_component {
        *payload = match report.component_content() {
            ComponentContentCheck::Unique(actual) if actual == expected => {
                PayloadIntegrityCheck::ComponentValid { digest: actual }
            }
            ComponentContentCheck::Unique(actual) => {
                PayloadIntegrityCheck::ComponentInvalid { expected, actual }
            }
            ComponentContentCheck::Ambiguous { candidates } => {
                PayloadIntegrityCheck::ComponentAmbiguous { candidates }
            }
            ComponentContentCheck::NotApplicable => PayloadIntegrityCheck::UnsupportedScope,
        };
    }
    let check = if report.is_valid() {
        ArchiveCheck::Valid
    } else {
        ArchiveCheck::Invalid
    };
    Ok((check, Some(report)))
}

fn with_preserved_position<R: Seek, T>(
    reader: &mut R,
    operation: impl FnOnce(&mut R) -> Result<T>,
) -> Result<T> {
    let position = reader.stream_position()?;
    let result = operation(reader);
    reader.seek(SeekFrom::Start(position))?;
    result
}

/// Streaming Kindle package writer.
struct PackageWriter<W> {
    writer: W,
}

impl<W: Write> PackageWriter<W> {
    /// Create a writer around an output stream.
    #[must_use]
    pub const fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Encode a seekable payload according to a typed package specification.
    pub fn write<R: Read + Seek>(
        &mut self,
        spec: &PackageSpec,
        payload: &mut R,
        options: WriteOptions<'_>,
    ) -> Result<u64> {
        if let Some(signing) = options.signing {
            signing.key.validate_certificate(signing.certificate)?;
        }

        let mut inner = tempfile::tempfile()?;
        match spec {
            PackageSpec::Userdata(_) => {
                payload.seek(SeekFrom::Start(0))?;
                io::copy(payload, &mut inner)?;
            }
            _ => {
                write_inner_package(&mut inner, spec, payload, options.fake_sign)?;
            }
        }
        inner.seek(SeekFrom::Start(0))?;

        let mut written = 0_u64;
        if let Some(signing) = options.signing {
            let signature = signing.key.sign(&mut inner)?;
            self.writer.write_all(b"SP01")?;
            let mut envelope_header = [0_u8; SIGNATURE_HEADER_LEN];
            envelope_header[0..4].copy_from_slice(&signing.certificate.raw().to_le_bytes());
            self.writer.write_all(&envelope_header)?;
            self.writer.write_all(&signature)?;
            written += 4 + SIGNATURE_HEADER_LEN as u64 + signature.len() as u64;
        }
        inner.seek(SeekFrom::Start(0))?;
        written += io::copy(&mut inner, &mut self.writer)?;
        Ok(written)
    }
}

fn parse_inner_header<R: Read>(
    reader: &mut R,
    magic: BundleMagic,
    options: ParseLimits,
) -> Result<(PackageHeader, Vec<u8>)> {
    match magic.profile().layout {
        HeaderLayout::OtaV1 => {
            let raw = read_vec(reader, OTA_V1_HEADER_LEN, "OTA V1 header")?;
            Ok((parse_ota_v1(magic, &raw)?, raw))
        }
        HeaderLayout::OtaV2 => {
            let (header, raw) = parse_ota_v2(reader, magic, options)?;
            Ok((PackageHeader::OtaV2(header), raw))
        }
        HeaderLayout::RecoveryV1 => {
            let raw = read_vec(reader, RECOVERY_HEADER_LEN, "recovery header")?;
            Ok((parse_recovery_v1(magic, &raw)?, raw))
        }
        HeaderLayout::RecoveryV2 => {
            let raw = read_vec(reader, RECOVERY_HEADER_LEN, "recovery V2 header")?;
            Ok((parse_recovery_v2(&raw)?, raw))
        }
        HeaderLayout::Component => {
            let raw = read_vec(reader, RECOVERY_HEADER_LEN, "component header")?;
            Ok((parse_component(&raw)?, raw))
        }
        HeaderLayout::Raw => match magic {
            BundleMagic::Gzip(bytes) => Ok((PackageHeader::Userdata { magic: bytes }, Vec::new())),
            BundleMagic::Zip => Ok((PackageHeader::Android, Vec::new())),
            _ => unreachable!("raw layout is only used by gzip and ZIP"),
        },
        HeaderLayout::Envelope => Err(Error::InvalidField {
            field: "signature envelope",
            message: "nested SP01 envelope".to_owned(),
        }),
    }
}

fn parse_ota_v1(magic: BundleMagic, raw: &[u8]) -> Result<PackageHeader> {
    let mut cursor = ByteCursor::new(raw);
    let source_revision = cursor.u32("source revision")?;
    let target_revision = cursor.u32("target revision")?;
    let device = DeviceCode(cursor.u16("device")?);
    let optional = cursor.u8("optional")?;
    let _unused = cursor.u8("unused")?;
    let md5 = Md5Digest::from_str(&decode_obfuscated_hex(cursor.take(32, "MD5")?, 32, "MD5")?)?;
    FirmwareRange::new(source_revision.into(), target_revision.into())?;
    Ok(PackageHeader::OtaV1(OtaV1Header {
        magic,
        source_revision,
        target_revision,
        device,
        optional,
        md5,
    }))
}

fn parse_ota_v2<R: Read>(
    reader: &mut R,
    magic: BundleMagic,
    options: ParseLimits,
) -> Result<(OtaV2Header, Vec<u8>)> {
    let mut raw = read_vec(reader, OTA_V2_FIXED_1, "OTA V2 fixed header")?;
    let mut cursor = ByteCursor::new(&raw);
    let source_revision = cursor.u64("source revision")?;
    let target_revision = cursor.u64("target revision")?;
    let device_count = usize::from(cursor.u16("device count")?);

    let device_bytes = read_vec(
        reader,
        device_count
            .checked_mul(2)
            .ok_or_else(|| invalid("device count", "size overflow"))?,
        "OTA V2 device list",
    )?;
    let mut device_cursor = ByteCursor::new(&device_bytes);
    let devices = (0..device_count)
        .map(|_| device_cursor.u16("device").map(DeviceCode))
        .collect::<Result<Vec<_>>>()?;
    raw.extend_from_slice(&device_bytes);

    let fixed_2 = read_vec(reader, OTA_V2_FIXED_2, "OTA V2 trailing header")?;
    let mut cursor = ByteCursor::new(&fixed_2);
    let critical = cursor.u8("critical")?;
    let padding = cursor.u8("padding")?;
    let md5 = Md5Digest::from_str(&decode_obfuscated_hex(cursor.take(32, "MD5")?, 32, "MD5")?)?;
    FirmwareRange::new(source_revision.into(), target_revision.into())?;
    let metadata_count = usize::from(cursor.u16("metadata count")?);
    if metadata_count > options.max_metadata_items {
        return Err(invalid(
            "metadata count",
            format!(
                "{metadata_count} exceeds limit {}",
                options.max_metadata_items
            ),
        ));
    }
    raw.extend_from_slice(&fixed_2);

    let mut metadata = Vec::with_capacity(metadata_count);
    let mut metadata_bytes = 0_usize;
    for _ in 0..metadata_count {
        let length_bytes = read_array::<2, _>(reader, "metadata length")?;
        let length = usize::from(u16::from_be_bytes(length_bytes));
        metadata_bytes = metadata_bytes
            .checked_add(length)
            .ok_or_else(|| invalid("metadata size", "size overflow"))?;
        if metadata_bytes > options.max_metadata_bytes {
            return Err(invalid(
                "metadata size",
                format!(
                    "{metadata_bytes} bytes exceeds limit {}",
                    options.max_metadata_bytes
                ),
            ));
        }
        let mut value = read_vec(reader, length, "metadata value")?;
        demangle(&mut value);
        raw.extend_from_slice(&length_bytes);
        let mut encoded = value.clone();
        mangle(&mut encoded);
        raw.extend_from_slice(&encoded);
        metadata.push(value);
    }
    Ok((
        OtaV2Header {
            magic,
            source_revision,
            target_revision,
            devices,
            critical,
            padding,
            md5,
            metadata,
        },
        raw,
    ))
}

fn parse_recovery_v1(magic: BundleMagic, raw: &[u8]) -> Result<PackageHeader> {
    let header_revision = le_u32_at(raw, 60, "header revision")?;
    if header_revision == 2 {
        Ok(PackageHeader::RecoveryV1(RecoveryV1Header {
            magic,
            target_revision: Some(le_u64_at(raw, 4, "target revision")?),
            md5: Md5Digest::from_str(&decode_obfuscated_hex(
                slice_at(raw, 12, 32, "MD5")?,
                32,
                "MD5",
            )?)?,
            magic_1: le_u32_at(raw, 44, "magic 1")?,
            magic_2: le_u32_at(raw, 48, "magic 2")?,
            minor: le_u32_at(raw, 52, "minor")?,
            device: None,
            device_code: None,
            platform: Some(Platform(le_u32_at(raw, 56, "platform")?)),
            header_revision,
            board: Some(Board(le_u32_at(raw, 64, "board")?)),
        }))
    } else {
        let device = le_u32_at(raw, 56, "device")?;
        Ok(PackageHeader::RecoveryV1(RecoveryV1Header {
            magic,
            target_revision: None,
            md5: Md5Digest::from_str(&decode_obfuscated_hex(
                slice_at(raw, 12, 32, "MD5")?,
                32,
                "MD5",
            )?)?,
            magic_1: le_u32_at(raw, 44, "magic 1")?,
            magic_2: le_u32_at(raw, 48, "magic 2")?,
            minor: le_u32_at(raw, 52, "minor")?,
            device: Some(device),
            device_code: u16::try_from(device).ok().map(DeviceCode),
            platform: None,
            header_revision,
            board: None,
        }))
    }
}

fn parse_recovery_v2(raw: &[u8]) -> Result<PackageHeader> {
    let count = usize::from(
        *slice_at(raw, 75, 1, "device count")?
            .first()
            .expect("one byte"),
    );
    let list_len = count
        .checked_mul(2)
        .ok_or_else(|| invalid("device count", "size overflow"))?;
    let mut devices_cursor = ByteCursor::new(slice_at(raw, 76, list_len, "device list")?);
    let devices = (0..count)
        .map(|_| devices_cursor.u16("device").map(DeviceCode))
        .collect::<Result<Vec<_>>>()?;
    Ok(PackageHeader::RecoveryV2(RecoveryV2Header {
        target_revision: le_u64_at(raw, 4, "target revision")?,
        md5: Md5Digest::from_str(&decode_obfuscated_hex(
            slice_at(raw, 12, 32, "MD5")?,
            32,
            "MD5",
        )?)?,
        magic_1: le_u32_at(raw, 44, "magic 1")?,
        magic_2: le_u32_at(raw, 48, "magic 2")?,
        minor: le_u32_at(raw, 52, "minor")?,
        platform: Platform(le_u32_at(raw, 56, "platform")?),
        header_revision: le_u32_at(raw, 60, "header revision")?,
        board: Board(le_u32_at(raw, 64, "board")?),
        devices,
    }))
}

fn parse_component(raw: &[u8]) -> Result<PackageHeader> {
    let minimum_revision = le_u64_at(raw, 0, "minimum revision")?;
    let target_revision = le_u64_at(raw, 8, "target revision")?;
    FirmwareRange::new(minimum_revision.into(), target_revision.into())?;
    let count = usize::try_from(le_u32_at(raw, 92, "device count")?).map_err(|_| {
        invalid(
            "device count",
            "value is not representable on this platform",
        )
    })?;
    let list_len = count
        .checked_mul(2)
        .ok_or_else(|| invalid("device count", "size overflow"))?;
    let mut devices_cursor = ByteCursor::new(slice_at(raw, 96, list_len, "device list")?);
    let devices = (0..count)
        .map(|_| devices_cursor.u16("device").map(DeviceCode))
        .collect::<Result<Vec<_>>>()?;
    Ok(PackageHeader::Component(ComponentHeader {
        minimum_revision,
        target_revision,
        sha256: crate::Sha256Digest::from_str(&decode_clear_hex(
            slice_at(raw, 16, 64, "SHA-256")?,
            64,
            "SHA-256",
        )?)?,
        component: le_u32_at(raw, 80, "component")?,
        platform: Platform(le_u32_at(raw, 84, "platform")?),
        header_revision: le_u32_at(raw, 88, "header revision")?,
        devices,
    }))
}

fn write_inner_package<R: Read + Seek, W: Write>(
    writer: &mut W,
    spec: &PackageSpec,
    payload: &mut R,
    fake_sign: bool,
) -> Result<u64> {
    let hash = payload_md5(payload, fake_sign)?;
    let header = encode_header(spec, &hash)?;
    writer.write_all(&header)?;
    payload.seek(SeekFrom::Start(0))?;
    let payload_len = if fake_sign {
        io::copy(payload, writer)?
    } else {
        copy_mangled(payload, writer)?
    };
    Ok(header.len() as u64 + payload_len)
}

fn payload_md5<R: Read + Seek>(payload: &mut R, fake_sign: bool) -> Result<String> {
    if !fake_sign {
        return md5_hex(payload);
    }
    payload.seek(SeekFrom::Start(0))?;
    let mut decoded = tempfile::tempfile()?;
    copy_demangled(&mut *payload, &mut decoded)?;
    payload.seek(SeekFrom::Start(0))?;
    md5_hex(&mut decoded)
}

fn encode_header(spec: &PackageSpec, payload_md5: &str) -> Result<Vec<u8>> {
    let mut encoded_hash = payload_md5.as_bytes().to_vec();
    validate_hex(&encoded_hash, 32, "MD5")?;
    mangle(&mut encoded_hash);
    match spec {
        PackageSpec::OtaV1(header) => {
            let mut output = Vec::with_capacity(4 + OTA_V1_HEADER_LEN);
            output.extend_from_slice(&header.kind.magic().as_bytes());
            let source_revision = u32::try_from(header.revisions.minimum().get())
                .map_err(|_| invalid("source revision", "value exceeds OTA V1"))?;
            let target_revision = u32::try_from(header.revisions.maximum().get())
                .map_err(|_| invalid("target revision", "value exceeds OTA V1"))?;
            output.extend_from_slice(&source_revision.to_le_bytes());
            output.extend_from_slice(&target_revision.to_le_bytes());
            output.extend_from_slice(&header.device.0.to_le_bytes());
            output.push(header.optional);
            output.push(0);
            output.extend_from_slice(&encoded_hash);
            output.resize(4 + OTA_V1_HEADER_LEN, 0);
            Ok(output)
        }
        PackageSpec::OtaV2(header) => encode_ota_v2(header, &encoded_hash),
        PackageSpec::RecoveryV1(header) => Ok(encode_recovery_v1(header, &encoded_hash)),
        PackageSpec::RecoveryV2(header) => encode_recovery_v2(header, &encoded_hash),
        PackageSpec::Userdata(_) => Err(Error::UnsupportedFormat {
            operation: "encode userdata inner header",
        }),
    }
}

fn encode_ota_v2(header: &OtaV2Spec, encoded_hash: &[u8]) -> Result<Vec<u8>> {
    let count = u16::try_from(header.devices.len())
        .map_err(|_| invalid("devices", "OTA V2 supports at most 65535 devices"))?;
    let metadata_count = u16::try_from(header.metadata.len())
        .map_err(|_| invalid("metadata", "OTA V2 supports at most 65535 entries"))?;
    let mut output = Vec::new();
    output.extend_from_slice(&header.kind.magic().as_bytes());
    output.extend_from_slice(&header.revisions.minimum().get().to_le_bytes());
    output.extend_from_slice(&header.revisions.maximum().get().to_le_bytes());
    output.extend_from_slice(&count.to_le_bytes());
    for device in &header.devices {
        output.extend_from_slice(&device.0.to_le_bytes());
    }
    output.push(header.critical);
    output.push(0);
    output.extend_from_slice(encoded_hash);
    output.extend_from_slice(&metadata_count.to_le_bytes());
    for metadata in &header.metadata {
        let length = u16::try_from(metadata.len())
            .map_err(|_| invalid("metadata", "entry exceeds 65535 bytes"))?;
        output.extend_from_slice(&length.to_be_bytes());
        let mut encoded = metadata.clone();
        mangle(&mut encoded);
        output.extend_from_slice(&encoded);
    }
    Ok(output)
}

fn encode_recovery_v1(spec: &RecoveryV1Spec, encoded_hash: &[u8]) -> Vec<u8> {
    let mut output = vec![0_u8; 4 + RECOVERY_HEADER_LEN];
    let magic = match spec.layout() {
        RecoveryV1Layout::Legacy { kind, .. } => kind.magic(),
        RecoveryV1Layout::Revision2 { .. } => BundleMagic::Fb02,
    };
    output[0..4].copy_from_slice(&magic.as_bytes());
    let raw = &mut output[4..];
    match spec.layout() {
        RecoveryV1Layout::Legacy {
            magic_1,
            magic_2,
            minor,
            device,
            ..
        } => {
            raw[12..44].copy_from_slice(encoded_hash);
            raw[44..48].copy_from_slice(&magic_1.to_le_bytes());
            raw[48..52].copy_from_slice(&magic_2.to_le_bytes());
            raw[52..56].copy_from_slice(&minor.to_le_bytes());
            raw[56..60].copy_from_slice(&device.to_le_bytes());
        }
        RecoveryV1Layout::Revision2 {
            target_revision,
            magic_1,
            magic_2,
            minor,
            platform,
            board,
        } => {
            raw[4..12].copy_from_slice(&target_revision.get().to_le_bytes());
            raw[12..44].copy_from_slice(encoded_hash);
            raw[44..48].copy_from_slice(&magic_1.to_le_bytes());
            raw[48..52].copy_from_slice(&magic_2.to_le_bytes());
            raw[52..56].copy_from_slice(&minor.to_le_bytes());
            raw[56..60].copy_from_slice(&platform.0.to_le_bytes());
            raw[60..64].copy_from_slice(&2_u32.to_le_bytes());
            raw[64..68].copy_from_slice(&board.0.to_le_bytes());
        }
    }
    output
}

fn encode_recovery_v2(header: &RecoveryV2Spec, encoded_hash: &[u8]) -> Result<Vec<u8>> {
    let count = u8::try_from(header.devices.len())
        .map_err(|_| invalid("devices", "recovery V2 supports at most 255 devices"))?;
    let last = 76_usize
        .checked_add(header.devices.len() * 2)
        .ok_or_else(|| invalid("devices", "size overflow"))?;
    if last > RECOVERY_HEADER_LEN {
        return Err(invalid("devices", "device list exceeds fixed header"));
    }
    let mut output = vec![0_u8; 4 + RECOVERY_HEADER_LEN];
    output[0..4].copy_from_slice(b"FB03");
    let raw = &mut output[4..];
    raw[4..12].copy_from_slice(&header.target_revision.get().to_le_bytes());
    raw[12..44].copy_from_slice(encoded_hash);
    raw[44..48].copy_from_slice(&header.magic_1.to_le_bytes());
    raw[48..52].copy_from_slice(&header.magic_2.to_le_bytes());
    raw[52..56].copy_from_slice(&header.minor.to_le_bytes());
    raw[56..60].copy_from_slice(&header.platform.0.to_le_bytes());
    raw[60..64].copy_from_slice(&header.header_revision.to_le_bytes());
    raw[64..68].copy_from_slice(&header.board.0.to_le_bytes());
    raw[75] = count;
    for (index, device) in header.devices.iter().enumerate() {
        let offset = 76 + index * 2;
        raw[offset..offset + 2].copy_from_slice(&device.0.to_le_bytes());
    }
    Ok(output)
}

fn decode_obfuscated_hex(bytes: &[u8], expected: usize, field: &'static str) -> Result<String> {
    let mut decoded = bytes.to_vec();
    demangle(&mut decoded);
    decode_clear_hex(&decoded, expected, field)
}

fn decode_clear_hex(bytes: &[u8], expected: usize, field: &'static str) -> Result<String> {
    validate_hex(bytes, expected, field)?;
    String::from_utf8(bytes.to_vec()).map_err(|error| invalid(field, error.to_string()))
}

fn validate_hex(bytes: &[u8], expected: usize, field: &'static str) -> Result<()> {
    if bytes.len() != expected || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid(
            field,
            format!("expected {expected} ASCII hexadecimal bytes"),
        ));
    }
    Ok(())
}

fn read_vec<R: Read>(reader: &mut R, length: usize, context: &'static str) -> Result<Vec<u8>> {
    let mut output = vec![0_u8; length];
    reader.read_exact(&mut output).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::Truncated {
                context,
                needed: length,
                remaining: 0,
            }
        } else {
            Error::Io(error)
        }
    })?;
    Ok(output)
}

fn read_array<const N: usize, R: Read>(reader: &mut R, context: &'static str) -> Result<[u8; N]> {
    let mut output = [0_u8; N];
    reader.read_exact(&mut output).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::Truncated {
                context,
                needed: N,
                remaining: 0,
            }
        } else {
            Error::Io(error)
        }
    })?;
    Ok(output)
}

fn slice_at<'input>(
    bytes: &'input [u8],
    offset: usize,
    length: usize,
    context: &'static str,
) -> Result<&'input [u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid(context, "offset overflow"))?;
    bytes.get(offset..end).ok_or(Error::Truncated {
        context,
        needed: length,
        remaining: bytes.len().saturating_sub(offset),
    })
}

fn le_u32_at(bytes: &[u8], offset: usize, context: &'static str) -> Result<u32> {
    Ok(u32::from_le_bytes(
        slice_at(bytes, offset, 4, context)?
            .try_into()
            .expect("four-byte slice"),
    ))
}

fn le_u64_at(bytes: &[u8], offset: usize, context: &'static str) -> Result<u64> {
    Ok(u64::from_le_bytes(
        slice_at(bytes, offset, 8, context)?
            .try_into()
            .expect("eight-byte slice"),
    ))
}

fn invalid(field: &'static str, message: impl Into<String>) -> Error {
    Error::InvalidField {
        field,
        message: message.into(),
    }
}

struct ByteCursor<'input> {
    bytes: &'input [u8],
    offset: usize,
}

impl<'input> ByteCursor<'input> {
    const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize, context: &'static str) -> Result<&'input [u8]> {
        let bytes = slice_at(self.bytes, self.offset, length, context)?;
        self.offset += length;
        Ok(bytes)
    }

    fn u8(&mut self, context: &'static str) -> Result<u8> {
        Ok(self.take(1, context)?[0])
    }

    fn u16(&mut self, context: &'static str) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2, context)?.try_into().expect("two-byte slice"),
        ))
    }

    fn u32(&mut self, context: &'static str) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4, context)?.try_into().expect("four-byte slice"),
        ))
    }

    fn u64(&mut self, context: &'static str) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8, context)?.try_into().expect("eight-byte slice"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PackageReader, PackageWriter, ParseLimits, SigningConfiguration, WriteOptions,
        verify_payload_integrity,
    };
    use crate::PayloadIntegrityCheck;
    use crate::crypto::SigningKey;
    use crate::devices::DeviceCode;
    use crate::model::{
        Board, BundleMagic, Certificate, OtaV1Kind, OtaV1Spec, OtaV2Kind, OtaV2Spec, PackageHeader,
        PackageSpec, Platform, RECOVERY_HEADER_LEN, RecoveryV1Kind, RecoveryV1Spec, RecoveryV2Spec,
        UserdataSpec,
    };
    use crate::values::{FirmwareRange, FirmwareRevision};
    use std::io::Cursor;

    #[test]
    fn ota_v2_round_trip() {
        let spec = PackageSpec::OtaV2(
            OtaV2Spec::new(
                OtaV2Kind::Versionless,
                revision_range(0, u64::MAX),
                vec![DeviceCode(0x201), DeviceCode(0xC6)],
                0,
                vec![b"PackageName=test".to_vec()],
            )
            .unwrap(),
        );
        let payload = b"payload".to_vec();
        let mut package = Vec::new();
        PackageWriter::new(&mut package)
            .write(
                &spec,
                &mut Cursor::new(payload.clone()),
                WriteOptions::default(),
            )
            .unwrap();

        let mut reader = PackageReader::new(Cursor::new(package)).unwrap();
        let PackageHeader::OtaV2(header) = &reader.info().header else {
            panic!("wrong header");
        };
        assert_eq!(header.devices.len(), 2);
        assert_eq!(header.metadata[0], b"PackageName=test");
        let mut decoded = Vec::new();
        reader.copy_decoded_payload(&mut decoded, false).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn truncated_header_is_rejected() {
        let error = PackageReader::new(Cursor::new(b"FC04".to_vec()))
            .err()
            .expect("must reject truncated header");
        assert!(matches!(error, crate::Error::Truncated { .. }));
    }

    #[test]
    fn every_writable_bundle_header_round_trips() {
        let payload = b"round-trip payload";
        let cases = vec![
            (
                ota_v1_spec(
                    OtaV1Kind::Ota,
                    0x0102_0304,
                    0xF1F2_F3F4,
                    DeviceCode(0x201),
                    7,
                ),
                BundleMagic::Fc02,
            ),
            (
                ota_v1_spec(OtaV1Kind::Versionless, 1, 2, DeviceCode(0xFFFF), 0),
                BundleMagic::Fd03,
            ),
            (ota_v2_spec(BundleMagic::Fc04), BundleMagic::Fc04),
            (ota_v2_spec(BundleMagic::Fd04), BundleMagic::Fd04),
            (ota_v2_spec(BundleMagic::Fl01), BundleMagic::Fl01),
            (recovery_v1_spec(BundleMagic::Fb01, 0), BundleMagic::Fb01),
            (recovery_v1_spec(BundleMagic::Fb02, 0), BundleMagic::Fb02),
            (recovery_v1_spec(BundleMagic::Fb02, 2), BundleMagic::Fb02),
            (recovery_v2_spec(), BundleMagic::Fb03),
        ];

        for (spec, expected_magic) in cases {
            let mut package = Vec::new();
            PackageWriter::new(&mut package)
                .write(&spec, &mut Cursor::new(payload), WriteOptions::default())
                .unwrap();
            let mut reader = PackageReader::new(Cursor::new(package)).unwrap();
            assert_eq!(reader.info().header.magic(), expected_magic);
            assert_eq!(
                verify_payload_integrity(&mut reader).unwrap(),
                PayloadIntegrityCheck::Valid {
                    digest: reader.info().header.payload_digest().unwrap()
                }
            );
            let mut decoded = Vec::new();
            reader.copy_decoded_payload(&mut decoded, false).unwrap();
            assert_eq!(decoded, payload);
        }
    }

    #[test]
    fn signed_envelope_and_userdata_round_trip() {
        let key = SigningKey::default_jailbreak().unwrap();
        let options = WriteOptions {
            fake_sign: false,
            signing: Some(SigningConfiguration {
                key: &key,
                certificate: Certificate::Developer,
            }),
        };
        let payload = b"\x1F\x8B\x08\x00signed userdata";
        let mut package = Vec::new();
        PackageWriter::new(&mut package)
            .write(
                &PackageSpec::Userdata(UserdataSpec),
                &mut Cursor::new(payload),
                options,
            )
            .unwrap();
        let mut reader = PackageReader::new(Cursor::new(package)).unwrap();
        assert_eq!(
            reader.info().header.magic(),
            BundleMagic::Gzip([0x1F, 0x8B, 8, 0])
        );
        assert_eq!(
            reader.info().envelope.as_ref().unwrap().signature.len(),
            128
        );
        let mut decoded = Vec::new();
        reader.copy_decoded_payload(&mut decoded, false).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn gzip_zip_and_component_are_detected() {
        let gzip = b"\x1F\x8B\x08\x04payload";
        let mut reader = PackageReader::new(Cursor::new(gzip)).unwrap();
        assert!(matches!(
            reader.info().header,
            PackageHeader::Userdata { .. }
        ));
        let mut copied = Vec::new();
        reader.copy_decoded_payload(&mut copied, false).unwrap();
        assert_eq!(copied, gzip);

        let zip = PackageReader::new(Cursor::new(b"PK\x03\x04zip")).unwrap();
        assert!(matches!(zip.info().header, PackageHeader::Android));

        let mut component = vec![0_u8; 4 + RECOVERY_HEADER_LEN];
        component[..4].copy_from_slice(b"CB01");
        let raw = &mut component[4..];
        raw[0..8].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
        raw[8..16].copy_from_slice(&0x1112_1314_1516_1718_u64.to_le_bytes());
        raw[16..80]
            .copy_from_slice(b"abababababababababababababababababababababababababababababababab");
        raw[80..84].copy_from_slice(&7_u32.to_le_bytes());
        raw[84..88].copy_from_slice(&12_u32.to_le_bytes());
        raw[88..92].copy_from_slice(&3_u32.to_le_bytes());
        raw[92..96].copy_from_slice(&2_u32.to_le_bytes());
        raw[96..98].copy_from_slice(&0x0E85_u16.to_le_bytes());
        raw[98..100].copy_from_slice(&0xFFFF_u16.to_le_bytes());
        let reader = PackageReader::new(Cursor::new(component)).unwrap();
        let PackageHeader::Component(header) = &reader.info().header else {
            panic!("expected component header");
        };
        assert_eq!(header.minimum_revision, 0x0102_0304_0506_0708);
        assert_eq!(header.devices, vec![DeviceCode(0x0E85), DeviceCode(0xFFFF)]);
    }

    #[test]
    fn all_truncated_ota_v2_header_prefixes_fail() {
        let payload = b"payload";
        let mut package = Vec::new();
        PackageWriter::new(&mut package)
            .write(
                &ota_v2_spec(BundleMagic::Fd04),
                &mut Cursor::new(payload),
                WriteOptions::default(),
            )
            .unwrap();
        let header_len = package.len() - payload.len();
        for length in 0..header_len {
            assert!(
                PackageReader::new(Cursor::new(&package[..length])).is_err(),
                "prefix length {length} unexpectedly parsed"
            );
        }
    }

    #[test]
    fn parser_limits_metadata_before_allocating_values() {
        let mut package = Vec::new();
        PackageWriter::new(&mut package)
            .write(
                &ota_v2_spec(BundleMagic::Fd04),
                &mut Cursor::new(b"payload"),
                WriteOptions::default(),
            )
            .unwrap();
        let metadata_count_offset = 4 + 18 + 4 + 34;
        package[metadata_count_offset..metadata_count_offset + 2]
            .copy_from_slice(&4097_u16.to_le_bytes());
        assert!(
            PackageReader::with_limits(
                Cursor::new(package),
                ParseLimits {
                    max_metadata_items: 4096,
                    ..ParseLimits::default()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn parser_limits_total_metadata_bytes_before_allocating_values() {
        let mut package = Vec::new();
        PackageWriter::new(&mut package)
            .write(
                &ota_v2_spec(BundleMagic::Fd04),
                &mut Cursor::new(b"payload"),
                WriteOptions::default(),
            )
            .unwrap();
        assert!(
            PackageReader::with_limits(
                Cursor::new(package),
                ParseLimits {
                    max_metadata_bytes: 8,
                    ..ParseLimits::default()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn nested_signature_envelopes_are_rejected() {
        let mut package = Vec::new();
        package.extend_from_slice(b"SP01");
        package.extend_from_slice(&[0_u8; 60 + 128]);
        package.extend_from_slice(b"SP01");
        assert!(PackageReader::new(Cursor::new(package)).is_err());
    }

    fn ota_v1_spec(
        kind: OtaV1Kind,
        minimum: u64,
        maximum: u64,
        device: DeviceCode,
        optional: u8,
    ) -> PackageSpec {
        PackageSpec::OtaV1(
            OtaV1Spec::new(kind, revision_range(minimum, maximum), device, optional).unwrap(),
        )
    }

    fn ota_v2_spec(magic: BundleMagic) -> PackageSpec {
        let kind = match magic {
            BundleMagic::Fc04 => OtaV2Kind::Ota,
            BundleMagic::Fd04 => OtaV2Kind::Versionless,
            BundleMagic::Fl01 => OtaV2Kind::Language,
            _ => panic!("not an OTA V2 magic"),
        };
        PackageSpec::OtaV2(
            OtaV2Spec::new(
                kind,
                revision_range(0x0102_0304_0506_0708, 0xF1F2_F3F4_F5F6_F7F8),
                vec![DeviceCode(0x201), DeviceCode(0xFFFF)],
                3,
                vec![b"PackageName=roundtrip".to_vec()],
            )
            .unwrap(),
        )
    }

    fn recovery_v1_spec(magic: BundleMagic, header_revision: u32) -> PackageSpec {
        if header_revision == 2 {
            PackageSpec::RecoveryV1(RecoveryV1Spec::revision2(
                FirmwareRevision::new(0x0102_0304_0506_0708),
                0x1122_3344,
                0x5566_7788,
                9,
                Platform(12),
                Board(5),
            ))
        } else {
            let kind = if magic == BundleMagic::Fb01 {
                RecoveryV1Kind::Fb01
            } else {
                RecoveryV1Kind::Fb02
            };
            PackageSpec::RecoveryV1(RecoveryV1Spec::legacy(
                kind,
                0x1122_3344,
                0x5566_7788,
                9,
                0x201,
            ))
        }
    }

    fn recovery_v2_spec() -> PackageSpec {
        PackageSpec::RecoveryV2(
            RecoveryV2Spec::new(
                FirmwareRevision::new(0x0102_0304_0506_0708),
                1,
                2,
                3,
                Platform(12),
                0,
                Board(0),
                vec![DeviceCode(0x0E75), DeviceCode(0xFFFF)],
            )
            .unwrap(),
        )
    }

    fn revision_range(minimum: u64, maximum: u64) -> FirmwareRange {
        FirmwareRange::new(
            FirmwareRevision::new(minimum),
            FirmwareRevision::new(maximum),
        )
        .unwrap()
    }
}
