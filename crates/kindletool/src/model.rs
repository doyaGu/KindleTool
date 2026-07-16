use crate::devices::DeviceCode;
use crate::format::{ArchiveKind, PackageFormat};
use crate::values::{FirmwareRange, FirmwareRevision, Md5Digest, Sha256Digest};
use crate::{Error, Result};
use std::fmt;
use std::str::FromStr;

/// Size of Kindle package magic values.
pub const MAGIC_LEN: usize = 4;
/// Size of OTA V1 headers after the magic.
pub const OTA_V1_HEADER_LEN: usize = 60;
/// Size of fixed recovery and component headers after the magic.
pub const RECOVERY_HEADER_LEN: usize = 131_068;
/// Size of an SP01 envelope header after the magic.
pub const SIGNATURE_HEADER_LEN: usize = 60;

/// Recognized on-disk Kindle bundle magic.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BundleMagic {
    /// FB01 recovery bundle.
    Fb01,
    /// FB02 recovery bundle.
    Fb02,
    /// FB03 recovery V2 bundle.
    Fb03,
    /// FC02 OTA V1 bundle.
    Fc02,
    /// FC04 OTA V2 bundle.
    Fc04,
    /// FD03 versionless OTA V1 bundle.
    Fd03,
    /// FD04 versionless OTA V2 bundle.
    Fd04,
    /// FL01 language OTA V2 bundle.
    Fl01,
    /// SP01 RSA signing envelope.
    Sp01,
    /// CB01 component bundle.
    Cb01,
    /// A gzip userdata archive.
    Gzip([u8; 4]),
    /// An Android ZIP update.
    Zip,
}

impl BundleMagic {
    /// All fixed magic values and their descriptions in catalog order.
    #[must_use]
    pub fn known() -> impl ExactSizeIterator<Item = (Self, &'static str)> {
        crate::format::fixed_records().map(|record| (record.magic, record.description))
    }

    /// Decode a four-byte magic value.
    pub fn from_bytes(bytes: [u8; 4]) -> Result<Self> {
        if matches!(bytes, [0x1F, 0x8B, 0x08, _]) {
            return Ok(Self::Gzip(bytes));
        }
        crate::format::by_bytes(bytes)
            .map(|record| record.magic)
            .ok_or(Error::UnknownMagic(bytes))
    }

    /// Return the exact four bytes written to disk.
    #[must_use]
    pub fn as_bytes(self) -> [u8; 4] {
        if let Self::Gzip(bytes) = self {
            bytes
        } else {
            crate::format::record(self)
                .expect("static magic has a catalog entry")
                .bytes
        }
    }

    /// Human-readable legacy description.
    #[must_use]
    pub fn description(self) -> &'static str {
        if matches!(self, Self::Gzip(_)) {
            "(Userdata tarball)"
        } else {
            crate::format::record(self)
                .expect("static magic has a catalog entry")
                .description
        }
    }

    /// Data-driven format metadata for this magic.
    #[must_use]
    pub fn profile(self) -> &'static crate::format::FormatProfile {
        crate::format::magic_profile(self)
    }
}

impl fmt::Display for BundleMagic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gzip(_) => formatter.write_str("GZIP"),
            Self::Zip => formatter.write_str("ZIP"),
            value => formatter.write_str(std::str::from_utf8(&value.as_bytes()).unwrap_or("????")),
        }
    }
}

impl FromStr for BundleMagic {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let bytes: [u8; 4] = value
            .to_ascii_uppercase()
            .as_bytes()
            .try_into()
            .map_err(|_| Error::InvalidField {
                field: "bundle",
                message: format!("magic must contain exactly four bytes: {value}"),
            })?;
        Self::from_bytes(bytes)
    }
}

/// Certificate selector stored by SP01.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Certificate {
    /// Developer certificate, 1024-bit signature.
    Developer,
    /// First production certificate, 1024-bit signature.
    Production1K,
    /// Second production certificate, 2048-bit signature.
    Production2K,
}

struct CertificateRecord {
    certificate: Certificate,
    raw: u32,
    signature_len: usize,
    label: &'static str,
}

const CERTIFICATE_CATALOG: &[CertificateRecord] = &[
    CertificateRecord {
        certificate: Certificate::Developer,
        raw: 0,
        signature_len: 128,
        label: "pubdevkey01.pem (Developer)",
    },
    CertificateRecord {
        certificate: Certificate::Production1K,
        raw: 1,
        signature_len: 128,
        label: "pubprodkey01.pem (Official 1K)",
    },
    CertificateRecord {
        certificate: Certificate::Production2K,
        raw: 2,
        signature_len: 256,
        label: "pubprodkey02.pem (Official 2K)",
    },
];

impl Certificate {
    /// All supported certificate selectors in numeric order.
    #[must_use]
    pub fn known() -> impl ExactSizeIterator<Item = Self> {
        CERTIFICATE_CATALOG.iter().map(|record| record.certificate)
    }

    /// Decode a numeric certificate selector.
    pub fn from_raw(value: u32) -> Result<Self> {
        CERTIFICATE_CATALOG
            .iter()
            .find(|record| record.raw == value)
            .map(|record| record.certificate)
            .ok_or_else(|| Error::InvalidField {
                field: "certificate",
                message: format!("unknown certificate number {value}"),
            })
    }

    /// Numeric value stored in the header.
    #[must_use]
    pub fn raw(self) -> u32 {
        self.record().raw
    }

    /// Required signature length.
    #[must_use]
    pub fn signature_len(self) -> usize {
        self.record().signature_len
    }

    /// Certificate filename and legacy label.
    #[must_use]
    pub fn label(self) -> &'static str {
        self.record().label
    }

    fn record(self) -> &'static CertificateRecord {
        CERTIFICATE_CATALOG
            .iter()
            .find(|record| record.certificate == self)
            .expect("certificate has a catalog entry")
    }
}

impl TryFrom<u16> for Certificate {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        Self::from_raw(u32::from(value))
    }
}

/// Kindle hardware platform stored in recovery/component headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Platform(pub(crate) u32);

struct NamedCode {
    code: u32,
    cli_name: &'static str,
    display_name: &'static str,
}

const PLATFORM_CATALOG: &[NamedCode] = &[
    NamedCode {
        code: 0,
        cli_name: "unspecified",
        display_name: "Unspecified",
    },
    NamedCode {
        code: 1,
        cli_name: "mario",
        display_name: "Mario (Deprecated)",
    },
    NamedCode {
        code: 2,
        cli_name: "luigi",
        display_name: "Luigi",
    },
    NamedCode {
        code: 3,
        cli_name: "banjo",
        display_name: "Banjo",
    },
    NamedCode {
        code: 4,
        cli_name: "yoshi",
        display_name: "Yoshi",
    },
    NamedCode {
        code: 5,
        cli_name: "yoshime-p",
        display_name: "Yoshime (Prototype)",
    },
    NamedCode {
        code: 6,
        cli_name: "yoshime",
        display_name: "Yoshime (Yoshime3)",
    },
    NamedCode {
        code: 7,
        cli_name: "wario",
        display_name: "Wario",
    },
    NamedCode {
        code: 8,
        cli_name: "duet",
        display_name: "Duet",
    },
    NamedCode {
        code: 9,
        cli_name: "heisenberg",
        display_name: "Heisenberg",
    },
    NamedCode {
        code: 10,
        cli_name: "zelda",
        display_name: "Zelda",
    },
    NamedCode {
        code: 11,
        cli_name: "rex",
        display_name: "Rex",
    },
    NamedCode {
        code: 12,
        cli_name: "bellatrix",
        display_name: "Bellatrix",
    },
    NamedCode {
        code: 13,
        cli_name: "bellatrix3",
        display_name: "Bellatrix3",
    },
    NamedCode {
        code: 14,
        cli_name: "bellatrix4",
        display_name: "Bellatrix4",
    },
    NamedCode {
        code: 15,
        cli_name: "platpa6",
        display_name: "Platpa6",
    },
    NamedCode {
        code: 16,
        cli_name: "platcs8",
        display_name: "Platcs8",
    },
];

const BOARD_CATALOG: &[NamedCode] = &[
    NamedCode {
        code: 0,
        cli_name: "unspecified",
        display_name: "Unspecified",
    },
    NamedCode {
        code: 3,
        cli_name: "tequila",
        display_name: "Tequila",
    },
    NamedCode {
        code: 5,
        cli_name: "whitney",
        display_name: "Whitney",
    },
];

impl Platform {
    /// Preserve a raw platform selector, including unknown values.
    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Raw on-disk selector.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
    /// All documented platform names and numeric values.
    #[must_use]
    pub fn known() -> impl ExactSizeIterator<Item = (Self, &'static str, &'static str)> {
        PLATFORM_CATALOG
            .iter()
            .map(|record| (Self(record.code), record.cli_name, record.display_name))
    }

    /// Parse a documented CLI platform name.
    pub fn from_name(name: &str) -> Result<Self> {
        PLATFORM_CATALOG
            .iter()
            .find(|record| record.cli_name.eq_ignore_ascii_case(name))
            .map(|record| Self(record.code))
            .ok_or_else(|| Error::InvalidField {
                field: "platform",
                message: format!("unknown platform {name}"),
            })
    }

    /// Human-readable name, preserving unknown numeric values.
    #[must_use]
    pub fn name(self) -> &'static str {
        PLATFORM_CATALOG
            .iter()
            .find(|record| record.code == self.0)
            .map_or("Unknown", |record| record.display_name)
    }
}

/// Kindle board selector stored in recovery headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Board(pub(crate) u32);

impl Board {
    /// Preserve a raw board selector, including unknown values.
    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Raw on-disk selector.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
    /// All documented board names and numeric values.
    #[must_use]
    pub fn known() -> impl ExactSizeIterator<Item = (Self, &'static str, &'static str)> {
        BOARD_CATALOG
            .iter()
            .map(|record| (Self(record.code), record.cli_name, record.display_name))
    }

    /// Parse a documented CLI board name.
    pub fn from_name(name: &str) -> Result<Self> {
        BOARD_CATALOG
            .iter()
            .find(|record| record.cli_name.eq_ignore_ascii_case(name))
            .map(|record| Self(record.code))
            .ok_or_else(|| Error::InvalidField {
                field: "board",
                message: format!("unknown board {name}"),
            })
    }

    /// Human-readable board name.
    #[must_use]
    pub fn name(self) -> &'static str {
        BOARD_CATALOG
            .iter()
            .find(|record| record.code == self.0)
            .map_or("Unknown", |record| record.display_name)
    }
}

/// Parsed OTA V1 header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtaV1Header {
    /// FC02 or FD03.
    pub(crate) magic: BundleMagic,
    /// Minimum source firmware revision.
    pub(crate) source_revision: u32,
    /// Maximum target firmware revision.
    pub(crate) target_revision: u32,
    /// Target device.
    pub(crate) device: DeviceCode,
    /// Optional one-byte policy value.
    pub(crate) optional: u8,
    /// Stored payload MD5 in lowercase hexadecimal.
    pub(crate) md5: Md5Digest,
}

impl OtaV1Header {
    /// Inclusive firmware range encoded by the header.
    #[must_use]
    pub fn firmware_range(&self) -> FirmwareRange {
        FirmwareRange::new(self.source_revision.into(), self.target_revision.into())
            .expect("a parsed OTA V1 range is ordered")
    }

    /// Target device.
    #[must_use]
    pub const fn device(&self) -> DeviceCode {
        self.device
    }

    /// Optional policy byte.
    #[must_use]
    pub const fn optional(&self) -> u8 {
        self.optional
    }

    /// Stored decoded-payload digest.
    #[must_use]
    pub const fn payload_digest(&self) -> Md5Digest {
        self.md5
    }
}

/// Parsed OTA V2 header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtaV2Header {
    /// FC04, FD04, or FL01.
    pub(crate) magic: BundleMagic,
    /// Minimum source firmware revision.
    pub(crate) source_revision: u64,
    /// Maximum target firmware revision.
    pub(crate) target_revision: u64,
    /// Target devices in package order.
    pub(crate) devices: Vec<DeviceCode>,
    /// Critical update byte.
    pub(crate) critical: u8,
    /// Header padding byte retained for diagnostics.
    pub(crate) padding: u8,
    /// Stored payload MD5 in lowercase hexadecimal.
    pub(crate) md5: Md5Digest,
    /// Raw metadata strings, preserved even if they are not UTF-8.
    pub(crate) metadata: Vec<Vec<u8>>,
}

impl OtaV2Header {
    /// Inclusive firmware range encoded by the header.
    #[must_use]
    pub fn firmware_range(&self) -> FirmwareRange {
        FirmwareRange::new(self.source_revision.into(), self.target_revision.into())
            .expect("a parsed OTA V2 range is ordered")
    }

    /// Target devices in encoded order.
    #[must_use]
    pub fn devices(&self) -> &[DeviceCode] {
        &self.devices
    }

    /// Critical-update policy byte.
    #[must_use]
    pub const fn critical(&self) -> u8 {
        self.critical
    }

    /// Reserved padding byte retained from the wire.
    #[must_use]
    pub const fn padding(&self) -> u8 {
        self.padding
    }

    /// Stored decoded-payload digest.
    #[must_use]
    pub const fn payload_digest(&self) -> Md5Digest {
        self.md5
    }

    /// Raw metadata entries in encoded order.
    #[must_use]
    pub fn metadata(&self) -> &[Vec<u8>] {
        &self.metadata
    }
}

/// OTA V1 wire variant selected for package creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtaV1Kind {
    /// FC02 standard OTA package.
    Ota,
    /// FD03 versionless OTA package.
    Versionless,
}

impl OtaV1Kind {
    pub(crate) const fn magic(self) -> BundleMagic {
        match self {
            Self::Ota => BundleMagic::Fc02,
            Self::Versionless => BundleMagic::Fd03,
        }
    }
}

/// Validated OTA V1 creation specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtaV1Spec {
    pub(crate) kind: OtaV1Kind,
    pub(crate) revisions: FirmwareRange,
    pub(crate) device: DeviceCode,
    pub(crate) optional: u8,
}

impl OtaV1Spec {
    /// Construct an OTA V1 specification.
    pub fn new(
        kind: OtaV1Kind,
        revisions: FirmwareRange,
        device: DeviceCode,
        optional: u8,
    ) -> Result<Self> {
        if revisions.maximum().get() > u64::from(u32::MAX) {
            return Err(Error::InvalidField {
                field: "firmware range",
                message: "OTA V1 revisions must fit in 32 bits".to_owned(),
            });
        }
        Ok(Self {
            kind,
            revisions,
            device,
            optional,
        })
    }

    /// Selected OTA V1 wire variant.
    #[must_use]
    pub const fn kind(&self) -> OtaV1Kind {
        self.kind
    }

    /// Inclusive supported firmware range.
    #[must_use]
    pub const fn revisions(&self) -> FirmwareRange {
        self.revisions
    }

    /// Target device.
    #[must_use]
    pub const fn device(&self) -> DeviceCode {
        self.device
    }

    /// Optional policy byte.
    #[must_use]
    pub const fn optional(&self) -> u8 {
        self.optional
    }
}

/// OTA V2 wire variant selected for package creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtaV2Kind {
    /// FC04 standard OTA package.
    Ota,
    /// FD04 versionless OTA package.
    Versionless,
    /// FL01 language package.
    Language,
}

impl OtaV2Kind {
    pub(crate) const fn magic(self) -> BundleMagic {
        match self {
            Self::Ota => BundleMagic::Fc04,
            Self::Versionless => BundleMagic::Fd04,
            Self::Language => BundleMagic::Fl01,
        }
    }
}

/// Validated OTA V2 creation specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtaV2Spec {
    pub(crate) kind: OtaV2Kind,
    pub(crate) revisions: FirmwareRange,
    pub(crate) devices: Vec<DeviceCode>,
    pub(crate) critical: u8,
    pub(crate) metadata: Vec<Vec<u8>>,
}

impl OtaV2Spec {
    /// Construct an OTA V2 specification.
    pub fn new(
        kind: OtaV2Kind,
        revisions: FirmwareRange,
        devices: Vec<DeviceCode>,
        critical: u8,
        metadata: Vec<Vec<u8>>,
    ) -> Result<Self> {
        u16::try_from(devices.len()).map_err(|_| Error::InvalidField {
            field: "devices",
            message: "OTA V2 supports at most 65535 devices".to_owned(),
        })?;
        u16::try_from(metadata.len()).map_err(|_| Error::InvalidField {
            field: "metadata",
            message: "OTA V2 supports at most 65535 entries".to_owned(),
        })?;
        if metadata
            .iter()
            .any(|entry| entry.len() > usize::from(u16::MAX))
        {
            return Err(Error::InvalidField {
                field: "metadata",
                message: "entry exceeds 65535 bytes".to_owned(),
            });
        }
        Ok(Self {
            kind,
            revisions,
            devices,
            critical,
            metadata,
        })
    }

    /// Selected OTA V2 wire variant.
    #[must_use]
    pub const fn kind(&self) -> OtaV2Kind {
        self.kind
    }

    /// Inclusive supported firmware range.
    #[must_use]
    pub const fn revisions(&self) -> FirmwareRange {
        self.revisions
    }

    /// Target devices in encoded order.
    #[must_use]
    pub fn devices(&self) -> &[DeviceCode] {
        &self.devices
    }

    /// Critical-update policy byte.
    #[must_use]
    pub const fn critical(&self) -> u8 {
        self.critical
    }

    /// Raw metadata strings in encoded order.
    #[must_use]
    pub fn metadata(&self) -> &[Vec<u8>] {
        &self.metadata
    }
}

/// Parsed recovery V1/FB02 header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryV1Header {
    /// FB01 or FB02.
    pub(crate) magic: BundleMagic,
    /// Optional target revision used by header revision 2.
    pub(crate) target_revision: Option<u64>,
    /// Stored payload MD5 in lowercase hexadecimal.
    pub(crate) md5: Md5Digest,
    /// Recovery magic value 1.
    pub(crate) magic_1: u32,
    /// Recovery magic value 2.
    pub(crate) magic_2: u32,
    /// Recovery minor value.
    pub(crate) minor: u32,
    /// Legacy target device for header revisions before 2.
    pub(crate) device: Option<u32>,
    /// Legacy selector normalized for the common target query when representable.
    pub(crate) device_code: Option<DeviceCode>,
    /// Platform used by header revision 2.
    pub(crate) platform: Option<Platform>,
    /// Header revision.
    pub(crate) header_revision: u32,
    /// Board used by header revision 2.
    pub(crate) board: Option<Board>,
}

impl RecoveryV1Header {
    /// Exact target firmware revision used by revision-2 headers.
    #[must_use]
    pub const fn target_revision(&self) -> Option<FirmwareRevision> {
        match self.target_revision {
            Some(value) => Some(FirmwareRevision::new(value)),
            None => None,
        }
    }

    /// Stored decoded-payload digest.
    #[must_use]
    pub const fn payload_digest(&self) -> Md5Digest {
        self.md5
    }

    /// Legacy numeric device selector.
    #[must_use]
    pub const fn legacy_device(&self) -> Option<u32> {
        self.device
    }

    /// Platform selector used by revision-2 headers.
    #[must_use]
    pub const fn platform(&self) -> Option<Platform> {
        self.platform
    }

    /// Board selector used by revision-2 headers.
    #[must_use]
    pub const fn board(&self) -> Option<Board> {
        self.board
    }

    /// Header revision.
    #[must_use]
    pub const fn header_revision(&self) -> u32 {
        self.header_revision
    }
}

/// Legacy recovery wire variant selected for package creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryV1Kind {
    /// FB01 recovery package.
    Fb01,
    /// FB02 recovery package.
    Fb02,
}

impl RecoveryV1Kind {
    pub(crate) const fn magic(self) -> BundleMagic {
        match self {
            Self::Fb01 => BundleMagic::Fb01,
            Self::Fb02 => BundleMagic::Fb02,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryV1Layout {
    Legacy {
        kind: RecoveryV1Kind,
        magic_1: u32,
        magic_2: u32,
        minor: u32,
        device: u32,
    },
    Revision2 {
        target_revision: FirmwareRevision,
        magic_1: u32,
        magic_2: u32,
        minor: u32,
        platform: Platform,
        board: Board,
    },
}

/// Validated recovery V1 creation specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryV1Spec(pub(crate) RecoveryV1Layout);

impl RecoveryV1Spec {
    /// Construct a legacy FB01/FB02 recovery specification.
    #[must_use]
    pub const fn legacy(
        kind: RecoveryV1Kind,
        magic_1: u32,
        magic_2: u32,
        minor: u32,
        device: u32,
    ) -> Self {
        Self(RecoveryV1Layout::Legacy {
            kind,
            magic_1,
            magic_2,
            minor,
            device,
        })
    }

    /// Construct an FB02 revision-2 recovery specification.
    #[must_use]
    pub const fn revision2(
        target_revision: FirmwareRevision,
        magic_1: u32,
        magic_2: u32,
        minor: u32,
        platform: Platform,
        board: Board,
    ) -> Self {
        Self(RecoveryV1Layout::Revision2 {
            target_revision,
            magic_1,
            magic_2,
            minor,
            platform,
            board,
        })
    }

    pub(crate) const fn layout(&self) -> &RecoveryV1Layout {
        &self.0
    }

    /// Whether this specification uses the FB02 revision-2 layout.
    #[must_use]
    pub const fn is_revision2(&self) -> bool {
        matches!(self.0, RecoveryV1Layout::Revision2 { .. })
    }
}

/// Parsed recovery V2 header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryV2Header {
    /// Target firmware revision.
    pub(crate) target_revision: u64,
    /// Stored payload MD5 in lowercase hexadecimal.
    pub(crate) md5: Md5Digest,
    /// Recovery magic value 1.
    pub(crate) magic_1: u32,
    /// Recovery magic value 2.
    pub(crate) magic_2: u32,
    /// Recovery minor value.
    pub(crate) minor: u32,
    /// Hardware platform.
    pub(crate) platform: Platform,
    /// Header revision.
    pub(crate) header_revision: u32,
    /// Hardware board.
    pub(crate) board: Board,
    /// Target devices in package order.
    pub(crate) devices: Vec<DeviceCode>,
}

impl RecoveryV2Header {
    /// Exact target firmware revision.
    #[must_use]
    pub const fn target_revision(&self) -> FirmwareRevision {
        FirmwareRevision::new(self.target_revision)
    }

    /// Stored decoded-payload digest.
    #[must_use]
    pub const fn payload_digest(&self) -> Md5Digest {
        self.md5
    }

    /// Hardware platform.
    #[must_use]
    pub const fn platform(&self) -> Platform {
        self.platform
    }

    /// Hardware board.
    #[must_use]
    pub const fn board(&self) -> Board {
        self.board
    }

    /// Target devices in encoded order.
    #[must_use]
    pub fn devices(&self) -> &[DeviceCode] {
        &self.devices
    }
}

/// Validated recovery V2 creation specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryV2Spec {
    pub(crate) target_revision: FirmwareRevision,
    pub(crate) magic_1: u32,
    pub(crate) magic_2: u32,
    pub(crate) minor: u32,
    pub(crate) platform: Platform,
    pub(crate) header_revision: u32,
    pub(crate) board: Board,
    pub(crate) devices: Vec<DeviceCode>,
}

impl RecoveryV2Spec {
    /// Construct a recovery V2 specification.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_revision: FirmwareRevision,
        magic_1: u32,
        magic_2: u32,
        minor: u32,
        platform: Platform,
        header_revision: u32,
        board: Board,
        devices: Vec<DeviceCode>,
    ) -> Result<Self> {
        u8::try_from(devices.len()).map_err(|_| Error::InvalidField {
            field: "devices",
            message: "recovery V2 supports at most 255 devices".to_owned(),
        })?;
        Ok(Self {
            target_revision,
            magic_1,
            magic_2,
            minor,
            platform,
            header_revision,
            board,
            devices,
        })
    }

    /// Target firmware revision.
    #[must_use]
    pub const fn target_revision(&self) -> FirmwareRevision {
        self.target_revision
    }

    /// Target devices in encoded order.
    #[must_use]
    pub fn devices(&self) -> &[DeviceCode] {
        &self.devices
    }
}

/// Standalone gzip userdata creation specification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserdataSpec;

/// Parsed component update header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentHeader {
    /// Minimum firmware revision.
    pub(crate) minimum_revision: u64,
    /// Target firmware revision.
    pub(crate) target_revision: u64,
    /// Cleartext component SHA-256.
    pub(crate) sha256: Sha256Digest,
    /// Component identifier.
    pub(crate) component: u32,
    /// Hardware platform.
    pub(crate) platform: Platform,
    /// Header revision.
    pub(crate) header_revision: u32,
    /// Target devices.
    pub(crate) devices: Vec<DeviceCode>,
}

impl ComponentHeader {
    /// Inclusive firmware range encoded by the header.
    #[must_use]
    pub fn firmware_range(&self) -> FirmwareRange {
        FirmwareRange::new(self.minimum_revision.into(), self.target_revision.into())
            .expect("a parsed component range is ordered")
    }

    /// Clear component-content digest.
    #[must_use]
    pub const fn content_digest(&self) -> Sha256Digest {
        self.sha256
    }

    /// Component identifier.
    #[must_use]
    pub const fn component(&self) -> u32 {
        self.component
    }

    /// Hardware platform.
    #[must_use]
    pub const fn platform(&self) -> Platform {
        self.platform
    }

    /// Target devices in encoded order.
    #[must_use]
    pub fn devices(&self) -> &[DeviceCode] {
        &self.devices
    }
}

/// Typed package header.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PackageHeader {
    /// OTA V1.
    OtaV1(OtaV1Header),
    /// OTA V2.
    OtaV2(OtaV2Header),
    /// Recovery V1 or FB02 header revision 2.
    RecoveryV1(RecoveryV1Header),
    /// Recovery V2.
    RecoveryV2(RecoveryV2Header),
    /// Component update.
    Component(ComponentHeader),
    /// Plain gzip userdata archive.
    Userdata {
        /// Exact four-byte gzip prefix retained from the input.
        magic: [u8; 4],
    },
    /// Android ZIP update.
    Android,
}

impl PackageHeader {
    /// Bundle magic represented by this header.
    #[must_use]
    pub const fn magic(&self) -> BundleMagic {
        match self {
            Self::OtaV1(header) => header.magic,
            Self::OtaV2(header) => header.magic,
            Self::RecoveryV1(header) => header.magic,
            Self::RecoveryV2(_) => BundleMagic::Fb03,
            Self::Component(_) => BundleMagic::Cb01,
            Self::Userdata { magic } => BundleMagic::Gzip(*magic),
            Self::Android => BundleMagic::Zip,
        }
    }

    /// Payload hash stored by the header, if the format defines one.
    #[must_use]
    pub const fn payload_digest(&self) -> Option<Md5Digest> {
        match self {
            Self::OtaV1(header) => Some(header.md5),
            Self::OtaV2(header) => Some(header.md5),
            Self::RecoveryV1(header) => Some(header.md5),
            Self::RecoveryV2(header) => Some(header.md5),
            Self::Component(_) | Self::Userdata { .. } | Self::Android => None,
        }
    }

    /// Content hash stored by component bundles, which is not a hash of the tar payload.
    #[must_use]
    pub const fn component_sha256(&self) -> Option<Sha256Digest> {
        match self {
            Self::Component(header) => Some(header.sha256),
            _ => None,
        }
    }
}

/// Parsed SP01 signing envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureEnvelope {
    /// Selected Kindle certificate.
    pub(crate) certificate: Certificate,
    /// The 56 reserved SP01 header bytes, retained without interpretation.
    pub(crate) reserved: Vec<u8>,
    /// Raw RSA signature bytes.
    pub(crate) signature: Vec<u8>,
}

impl SignatureEnvelope {
    /// Certificate selector declared by SP01.
    #[must_use]
    pub const fn certificate(&self) -> Certificate {
        self.certificate
    }

    /// Uninterpreted reserved bytes.
    #[must_use]
    pub fn reserved(&self) -> &[u8] {
        &self.reserved
    }

    /// Raw big-endian RSA signature.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Digest declared by a parsed package header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PayloadDigest {
    /// MD5 of the decoded payload.
    Md5(Md5Digest),
    /// SHA-256 of component content inside a CB01 archive.
    ComponentSha256(Sha256Digest),
}

/// Package metadata plus an optional outer signature envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageDescriptor {
    /// Decoded inner header.
    pub(crate) header: PackageHeader,
    /// SP01 envelope, when present.
    pub(crate) envelope: Option<SignatureEnvelope>,
    /// Exact inner magic and encoded header bytes, including unknown/reserved fields.
    pub(crate) raw_inner_header: Vec<u8>,
}

impl PackageDescriptor {
    /// Exact inner package magic.
    #[must_use]
    pub const fn magic(&self) -> BundleMagic {
        self.header.magic()
    }

    /// High-level package format.
    #[must_use]
    pub fn format(&self) -> PackageFormat {
        self.magic().profile().format()
    }

    /// Parsed SP01 envelope, if present.
    #[must_use]
    pub const fn envelope(&self) -> Option<&SignatureEnvelope> {
        self.envelope.as_ref()
    }

    /// Header-declared payload or component digest.
    #[must_use]
    pub const fn payload_digest(&self) -> Option<PayloadDigest> {
        match self.header.payload_digest() {
            Some(digest) => Some(PayloadDigest::Md5(digest)),
            None => match self.header.component_sha256() {
                Some(digest) => Some(PayloadDigest::ComponentSha256(digest)),
                None => None,
            },
        }
    }

    /// Devices explicitly targeted by the package.
    #[must_use]
    pub fn target_devices(&self) -> &[DeviceCode] {
        match &self.header {
            PackageHeader::OtaV1(header) => std::slice::from_ref(&header.device),
            PackageHeader::OtaV2(header) => &header.devices,
            PackageHeader::RecoveryV1(header) => header.device_code.as_slice(),
            PackageHeader::RecoveryV2(header) => &header.devices,
            PackageHeader::Component(header) => &header.devices,
            _ => &[],
        }
    }

    /// Firmware range declared by the package.
    #[must_use]
    pub fn firmware_range(&self) -> Option<FirmwareRange> {
        match &self.header {
            PackageHeader::OtaV1(header) => Some(header.firmware_range()),
            PackageHeader::OtaV2(header) => Some(header.firmware_range()),
            PackageHeader::RecoveryV1(header) => header.target_revision().map(FirmwareRange::exact),
            PackageHeader::RecoveryV2(header) => {
                Some(FirmwareRange::exact(header.target_revision()))
            }
            PackageHeader::Component(header) => Some(header.firmware_range()),
            _ => None,
        }
    }

    /// Hardware platform selector, if present.
    #[must_use]
    pub const fn platform(&self) -> Option<Platform> {
        match &self.header {
            PackageHeader::RecoveryV1(header) => header.platform,
            PackageHeader::RecoveryV2(header) => Some(header.platform),
            PackageHeader::Component(header) => Some(header.platform),
            _ => None,
        }
    }

    /// Hardware board selector, if present.
    #[must_use]
    pub const fn board(&self) -> Option<Board> {
        match &self.header {
            PackageHeader::RecoveryV1(header) => header.board,
            PackageHeader::RecoveryV2(header) => Some(header.board),
            _ => None,
        }
    }

    /// Archive conventions associated with the decoded payload.
    #[must_use]
    pub fn archive_kind(&self) -> Option<ArchiveKind> {
        self.magic().profile().archive_kind()
    }

    /// Concrete parsed header for format-specific callers.
    #[must_use]
    pub const fn header(&self) -> &PackageHeader {
        &self.header
    }

    /// Exact inner magic and header bytes as stored on disk.
    #[must_use]
    pub fn raw_header(&self) -> &[u8] {
        &self.raw_inner_header
    }
}

/// Strongly typed package creation specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageSpec {
    /// Create OTA V1.
    OtaV1(OtaV1Spec),
    /// Create OTA V2.
    OtaV2(OtaV2Spec),
    /// Create recovery V1 or FB02 revision 2.
    RecoveryV1(RecoveryV1Spec),
    /// Create recovery V2.
    RecoveryV2(RecoveryV2Spec),
    /// Encode a standalone gzip userdata archive.
    Userdata(UserdataSpec),
}

impl PackageSpec {
    pub(crate) const fn magic(&self) -> BundleMagic {
        match self {
            Self::OtaV1(spec) => spec.kind.magic(),
            Self::OtaV2(spec) => spec.kind.magic(),
            Self::RecoveryV1(spec) => match spec.layout() {
                RecoveryV1Layout::Legacy { kind, .. } => kind.magic(),
                RecoveryV1Layout::Revision2 { .. } => BundleMagic::Fb02,
            },
            Self::RecoveryV2(_) => BundleMagic::Fb03,
            Self::Userdata(_) => BundleMagic::Gzip([0x1F, 0x8B, 0x08, 0]),
        }
    }

    /// Whether the static format catalog recommends an SP01 envelope.
    #[must_use]
    pub fn default_envelope(&self) -> bool {
        if matches!(self, Self::RecoveryV1(spec) if spec.is_revision2()) {
            return true;
        }
        matches!(
            self.magic().profile().default_envelope,
            crate::format::DefaultEnvelope::Signed
        )
    }
}
