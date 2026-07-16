use crate::codec::{copy_demangled, copy_mangled, demangle, mangle};
use crate::crypto::{SigningKey, md5_hex};
use crate::devices::DeviceCode;
use crate::model::{
    Board, BundleMagic, Certificate, ComponentHeader, OTA_V1_HEADER_LEN, OtaV1Header, OtaV2Header,
    PackageHeader, PackageInfo, PackageSpec, Platform, RECOVERY_HEADER_LEN, RecoveryV1Header,
    RecoveryV1Spec, RecoveryV2Header, SIGNATURE_HEADER_LEN, SignatureEnvelope,
};
use crate::{Error, Result};
use std::io::{self, Read, Seek, SeekFrom, Write};

const OTA_V2_FIXED_1: usize = 18;
const OTA_V2_FIXED_2: usize = 36;
const DEFAULT_MAX_METADATA_ITEMS: usize = 4096;
const DEFAULT_MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;

/// Limits used while parsing untrusted package headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseOptions {
    /// Maximum OTA V2 metadata item count accepted by the parser.
    pub max_metadata_items: usize,
    /// Maximum combined OTA V2 metadata value bytes accepted by the parser.
    pub max_metadata_bytes: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            max_metadata_items: DEFAULT_MAX_METADATA_ITEMS,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
        }
    }
}

/// Local signing configuration used by [`PackageWriter`].
#[derive(Clone, Copy, Debug)]
pub struct SigningConfiguration<'key> {
    /// RSA private key.
    pub key: &'key SigningKey,
    /// Kindle certificate selector written to SP01.
    pub certificate: Certificate,
}

/// Package encoding behavior.
#[derive(Clone, Copy, Debug, Default)]
pub struct WriteOptions<'key> {
    /// Leave payload bytes unmangled and do not implicitly add SP01.
    pub fake_sign: bool,
    /// Optional SP01 signing configuration.
    pub signing: Option<SigningConfiguration<'key>>,
}

/// Streaming Kindle package reader.
pub struct PackageReader<R> {
    reader: R,
    info: PackageInfo,
}

impl<R: Read> PackageReader<R> {
    /// Parse a package with default safety limits.
    pub fn new(reader: R) -> Result<Self> {
        Self::with_options(reader, ParseOptions::default())
    }

    /// Parse a package with explicit safety limits.
    pub fn with_options(mut reader: R, options: ParseOptions) -> Result<Self> {
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
            info: PackageInfo {
                header,
                envelope,
                raw_inner_header: encoded_inner_header,
            },
        })
    }

    /// Parsed package information.
    #[must_use]
    pub const fn info(&self) -> &PackageInfo {
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
        match self.info.header {
            PackageHeader::Android => Err(Error::Unsupported("Android ZIP conversion")),
            PackageHeader::Userdata { magic } => {
                writer.write_all(&magic)?;
                Ok(4 + io::copy(&mut self.reader, &mut writer)?)
            }
            _ if fake_sign => Ok(io::copy(&mut self.reader, &mut writer)?),
            _ => Ok(copy_demangled(&mut self.reader, &mut writer)?),
        }
    }

    /// Write the exact inner package, removing one outer SP01 envelope.
    pub fn copy_unwrapped<W: Write>(&mut self, mut writer: W) -> Result<u64> {
        if self.info.envelope.is_none() {
            return Err(Error::Unsupported("package is not wrapped in SP01"));
        }
        writer.write_all(&self.info.raw_inner_header)?;
        Ok(self.info.raw_inner_header.len() as u64 + io::copy(&mut self.reader, &mut writer)?)
    }

    /// Copy the outer payload signature if one exists.
    pub fn copy_signature<W: Write>(&self, mut writer: W) -> Result<usize> {
        let envelope = self
            .info
            .envelope
            .as_ref()
            .ok_or(Error::Unsupported("package has no SP01 signature"))?;
        writer.write_all(&envelope.signature)?;
        Ok(envelope.signature.len())
    }
}

/// Streaming Kindle package writer.
pub struct PackageWriter<W> {
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
            PackageSpec::SignedUserdata => {
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

    /// Return the wrapped output stream.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.writer
    }
}

fn parse_inner_header<R: Read>(
    reader: &mut R,
    magic: BundleMagic,
    options: ParseOptions,
) -> Result<(PackageHeader, Vec<u8>)> {
    match magic {
        BundleMagic::Fc02 | BundleMagic::Fd03 => {
            let raw = read_vec(reader, OTA_V1_HEADER_LEN, "OTA V1 header")?;
            Ok((parse_ota_v1(magic, &raw)?, raw))
        }
        BundleMagic::Fc04 | BundleMagic::Fd04 | BundleMagic::Fl01 => {
            let (header, raw) = parse_ota_v2(reader, magic, options)?;
            Ok((PackageHeader::OtaV2(header), raw))
        }
        BundleMagic::Fb01 | BundleMagic::Fb02 => {
            let raw = read_vec(reader, RECOVERY_HEADER_LEN, "recovery header")?;
            Ok((parse_recovery_v1(magic, &raw)?, raw))
        }
        BundleMagic::Fb03 => {
            let raw = read_vec(reader, RECOVERY_HEADER_LEN, "recovery V2 header")?;
            Ok((parse_recovery_v2(&raw)?, raw))
        }
        BundleMagic::Cb01 => {
            let raw = read_vec(reader, RECOVERY_HEADER_LEN, "component header")?;
            Ok((parse_component(&raw)?, raw))
        }
        BundleMagic::Gzip(bytes) => Ok((PackageHeader::Userdata { magic: bytes }, Vec::new())),
        BundleMagic::Zip => Ok((PackageHeader::Android, Vec::new())),
        BundleMagic::Sp01 => Err(Error::InvalidField {
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
    let md5 = decode_obfuscated_hex(cursor.take(32, "MD5")?, 32, "MD5")?;
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
    options: ParseOptions,
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
    let md5 = decode_obfuscated_hex(cursor.take(32, "MD5")?, 32, "MD5")?;
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
            md5: decode_obfuscated_hex(slice_at(raw, 12, 32, "MD5")?, 32, "MD5")?,
            magic_1: le_u32_at(raw, 44, "magic 1")?,
            magic_2: le_u32_at(raw, 48, "magic 2")?,
            minor: le_u32_at(raw, 52, "minor")?,
            device: None,
            platform: Some(Platform(le_u32_at(raw, 56, "platform")?)),
            header_revision,
            board: Some(Board(le_u32_at(raw, 64, "board")?)),
        }))
    } else {
        Ok(PackageHeader::RecoveryV1(RecoveryV1Header {
            magic,
            target_revision: None,
            md5: decode_obfuscated_hex(slice_at(raw, 12, 32, "MD5")?, 32, "MD5")?,
            magic_1: le_u32_at(raw, 44, "magic 1")?,
            magic_2: le_u32_at(raw, 48, "magic 2")?,
            minor: le_u32_at(raw, 52, "minor")?,
            device: Some(le_u32_at(raw, 56, "device")?),
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
        md5: decode_obfuscated_hex(slice_at(raw, 12, 32, "MD5")?, 32, "MD5")?,
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
        minimum_revision: le_u64_at(raw, 0, "minimum revision")?,
        target_revision: le_u64_at(raw, 8, "target revision")?,
        sha256: decode_clear_hex(slice_at(raw, 16, 64, "SHA-256")?, 64, "SHA-256")?,
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
            if !matches!(header.magic, BundleMagic::Fc02 | BundleMagic::Fd03) {
                return Err(invalid("bundle", "OTA V1 requires FC02 or FD03"));
            }
            let mut output = Vec::with_capacity(4 + OTA_V1_HEADER_LEN);
            output.extend_from_slice(&header.magic.as_bytes());
            output.extend_from_slice(&header.source_revision.to_le_bytes());
            output.extend_from_slice(&header.target_revision.to_le_bytes());
            output.extend_from_slice(&header.device.0.to_le_bytes());
            output.push(header.optional);
            output.push(0);
            output.extend_from_slice(&encoded_hash);
            output.resize(4 + OTA_V1_HEADER_LEN, 0);
            Ok(output)
        }
        PackageSpec::OtaV2(header) => encode_ota_v2(header, &encoded_hash),
        PackageSpec::RecoveryV1(header) => encode_recovery_v1(header, &encoded_hash),
        PackageSpec::RecoveryV2(header) => encode_recovery_v2(header, &encoded_hash),
        PackageSpec::SignedUserdata => Err(Error::Unsupported(
            "signed userdata does not have an inner Kindle header",
        )),
    }
}

fn encode_ota_v2(header: &OtaV2Header, encoded_hash: &[u8]) -> Result<Vec<u8>> {
    if !matches!(
        header.magic,
        BundleMagic::Fc04 | BundleMagic::Fd04 | BundleMagic::Fl01
    ) {
        return Err(invalid("bundle", "OTA V2 requires FC04, FD04, or FL01"));
    }
    let count = u16::try_from(header.devices.len())
        .map_err(|_| invalid("devices", "OTA V2 supports at most 65535 devices"))?;
    let metadata_count = u16::try_from(header.metadata.len())
        .map_err(|_| invalid("metadata", "OTA V2 supports at most 65535 entries"))?;
    let mut output = Vec::new();
    output.extend_from_slice(&header.magic.as_bytes());
    output.extend_from_slice(&header.source_revision.to_le_bytes());
    output.extend_from_slice(&header.target_revision.to_le_bytes());
    output.extend_from_slice(&count.to_le_bytes());
    for device in &header.devices {
        output.extend_from_slice(&device.0.to_le_bytes());
    }
    output.push(header.critical);
    output.push(header.padding);
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

fn encode_recovery_v1(spec: &RecoveryV1Spec, encoded_hash: &[u8]) -> Result<Vec<u8>> {
    let mut output = vec![0_u8; 4 + RECOVERY_HEADER_LEN];
    let magic = match spec {
        RecoveryV1Spec::Legacy { magic, .. } => {
            if !matches!(magic, BundleMagic::Fb01 | BundleMagic::Fb02) {
                return Err(invalid("bundle", "recovery V1 requires FB01 or FB02"));
            }
            *magic
        }
        RecoveryV1Spec::Revision2 { .. } => BundleMagic::Fb02,
    };
    output[0..4].copy_from_slice(&magic.as_bytes());
    let raw = &mut output[4..];
    match spec {
        RecoveryV1Spec::Legacy {
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
        RecoveryV1Spec::Revision2 {
            target_revision,
            magic_1,
            magic_2,
            minor,
            platform,
            board,
        } => {
            raw[4..12].copy_from_slice(&target_revision.to_le_bytes());
            raw[12..44].copy_from_slice(encoded_hash);
            raw[44..48].copy_from_slice(&magic_1.to_le_bytes());
            raw[48..52].copy_from_slice(&magic_2.to_le_bytes());
            raw[52..56].copy_from_slice(&minor.to_le_bytes());
            raw[56..60].copy_from_slice(&platform.0.to_le_bytes());
            raw[60..64].copy_from_slice(&2_u32.to_le_bytes());
            raw[64..68].copy_from_slice(&board.0.to_le_bytes());
        }
    }
    Ok(output)
}

fn encode_recovery_v2(header: &RecoveryV2Header, encoded_hash: &[u8]) -> Result<Vec<u8>> {
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
    raw[4..12].copy_from_slice(&header.target_revision.to_le_bytes());
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
    use super::{PackageReader, PackageWriter, ParseOptions, SigningConfiguration, WriteOptions};
    use crate::crypto::SigningKey;
    use crate::devices::DeviceCode;
    use crate::model::{
        Board, BundleMagic, Certificate, OtaV1Header, OtaV2Header, PackageHeader, PackageSpec,
        Platform, RECOVERY_HEADER_LEN, RecoveryV1Spec, RecoveryV2Header,
    };
    use std::io::Cursor;

    #[test]
    fn ota_v2_round_trip() {
        let spec = PackageSpec::OtaV2(OtaV2Header {
            magic: BundleMagic::Fd04,
            source_revision: 0,
            target_revision: u64::MAX,
            devices: vec![DeviceCode(0x201), DeviceCode(0xC6)],
            critical: 0,
            padding: 0,
            md5: String::new(),
            metadata: vec![b"PackageName=test".to_vec()],
        });
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
                PackageSpec::OtaV1(OtaV1Header {
                    magic: BundleMagic::Fc02,
                    source_revision: 0x0102_0304,
                    target_revision: 0xF1F2_F3F4,
                    device: DeviceCode(0x201),
                    optional: 7,
                    md5: String::new(),
                }),
                BundleMagic::Fc02,
            ),
            (
                PackageSpec::OtaV1(OtaV1Header {
                    magic: BundleMagic::Fd03,
                    source_revision: 1,
                    target_revision: 2,
                    device: DeviceCode(0xFFFF),
                    optional: 0,
                    md5: String::new(),
                }),
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
                &PackageSpec::SignedUserdata,
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
            PackageReader::with_options(
                Cursor::new(package),
                ParseOptions {
                    max_metadata_items: 4096,
                    ..ParseOptions::default()
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
            PackageReader::with_options(
                Cursor::new(package),
                ParseOptions {
                    max_metadata_bytes: 8,
                    ..ParseOptions::default()
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

    fn ota_v2_spec(magic: BundleMagic) -> PackageSpec {
        PackageSpec::OtaV2(OtaV2Header {
            magic,
            source_revision: 0x0102_0304_0506_0708,
            target_revision: 0xF1F2_F3F4_F5F6_F7F8,
            devices: vec![DeviceCode(0x201), DeviceCode(0xFFFF)],
            critical: 3,
            padding: 0xA5,
            md5: String::new(),
            metadata: vec![b"PackageName=roundtrip".to_vec()],
        })
    }

    fn recovery_v1_spec(magic: BundleMagic, header_revision: u32) -> PackageSpec {
        if header_revision == 2 {
            PackageSpec::RecoveryV1(RecoveryV1Spec::Revision2 {
                target_revision: 0x0102_0304_0506_0708,
                magic_1: 0x1122_3344,
                magic_2: 0x5566_7788,
                minor: 9,
                platform: Platform(12),
                board: Board(5),
            })
        } else {
            PackageSpec::RecoveryV1(RecoveryV1Spec::Legacy {
                magic,
                magic_1: 0x1122_3344,
                magic_2: 0x5566_7788,
                minor: 9,
                device: 0x201,
            })
        }
    }

    fn recovery_v2_spec() -> PackageSpec {
        PackageSpec::RecoveryV2(RecoveryV2Header {
            target_revision: 0x0102_0304_0506_0708,
            md5: String::new(),
            magic_1: 1,
            magic_2: 2,
            minor: 3,
            platform: Platform(12),
            header_revision: 0,
            board: Board(0),
            devices: vec![DeviceCode(0x0E75), DeviceCode(0xFFFF)],
        })
    }
}
