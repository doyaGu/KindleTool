use crate::devices::DeviceCode;
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

struct MagicRecord {
    magic: BundleMagic,
    bytes: [u8; 4],
    description: &'static str,
}

const MAGIC_CATALOG: &[MagicRecord] = &[
    MagicRecord {
        magic: BundleMagic::Fb01,
        bytes: *b"FB01",
        description: "(Fullbin)",
    },
    MagicRecord {
        magic: BundleMagic::Fb02,
        bytes: *b"FB02",
        description: "(Fullbin [signed?])",
    },
    MagicRecord {
        magic: BundleMagic::Fb03,
        bytes: *b"FB03",
        description: "(Fullbin [OTA?, fwo?])",
    },
    MagicRecord {
        magic: BundleMagic::Fc02,
        bytes: *b"FC02",
        description: "(OTA [ota])",
    },
    MagicRecord {
        magic: BundleMagic::Fc04,
        bytes: *b"FC04",
        description: "(OTA [ota])",
    },
    MagicRecord {
        magic: BundleMagic::Fd03,
        bytes: *b"FD03",
        description: "(Versionless [vls])",
    },
    MagicRecord {
        magic: BundleMagic::Fd04,
        bytes: *b"FD04",
        description: "(Versionless [vls])",
    },
    MagicRecord {
        magic: BundleMagic::Fl01,
        bytes: *b"FL01",
        description: "(Language [lang])",
    },
    MagicRecord {
        magic: BundleMagic::Sp01,
        bytes: *b"SP01",
        description: "(Signing Envelope)",
    },
    MagicRecord {
        magic: BundleMagic::Cb01,
        bytes: *b"CB01",
        description: "(Component [OTA?])",
    },
    MagicRecord {
        magic: BundleMagic::Zip,
        bytes: [0x50, 0x4B, 0x03, 0x04],
        description: "(Android update)",
    },
];

impl BundleMagic {
    /// All fixed magic values and their descriptions in catalog order.
    #[must_use]
    pub fn known() -> impl ExactSizeIterator<Item = (Self, &'static str)> {
        MAGIC_CATALOG
            .iter()
            .map(|record| (record.magic, record.description))
    }

    /// Decode a four-byte magic value.
    pub fn from_bytes(bytes: [u8; 4]) -> Result<Self> {
        if matches!(bytes, [0x1F, 0x8B, 0x08, _]) {
            return Ok(Self::Gzip(bytes));
        }
        MAGIC_CATALOG
            .iter()
            .find(|record| record.bytes == bytes)
            .map(|record| record.magic)
            .ok_or(Error::UnknownMagic(bytes))
    }

    /// Return the exact four bytes written to disk.
    #[must_use]
    pub fn as_bytes(self) -> [u8; 4] {
        if let Self::Gzip(bytes) = self {
            bytes
        } else {
            self.record()
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
            self.record()
                .expect("static magic has a catalog entry")
                .description
        }
    }

    fn record(self) -> Option<&'static MagicRecord> {
        MAGIC_CATALOG.iter().find(|record| record.magic == self)
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
pub struct Platform(pub u32);

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
pub struct Board(pub u32);

impl Board {
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
    pub magic: BundleMagic,
    /// Minimum source firmware revision.
    pub source_revision: u32,
    /// Maximum target firmware revision.
    pub target_revision: u32,
    /// Target device.
    pub device: DeviceCode,
    /// Optional one-byte policy value.
    pub optional: u8,
    /// Stored payload MD5 in lowercase hexadecimal.
    pub md5: String,
}

/// Parsed OTA V2 header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtaV2Header {
    /// FC04, FD04, or FL01.
    pub magic: BundleMagic,
    /// Minimum source firmware revision.
    pub source_revision: u64,
    /// Maximum target firmware revision.
    pub target_revision: u64,
    /// Target devices in package order.
    pub devices: Vec<DeviceCode>,
    /// Critical update byte.
    pub critical: u8,
    /// Header padding byte retained for diagnostics.
    pub padding: u8,
    /// Stored payload MD5 in lowercase hexadecimal.
    pub md5: String,
    /// Raw metadata strings, preserved even if they are not UTF-8.
    pub metadata: Vec<Vec<u8>>,
}

/// Parsed recovery V1/FB02 header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryV1Header {
    /// FB01 or FB02.
    pub magic: BundleMagic,
    /// Optional target revision used by header revision 2.
    pub target_revision: Option<u64>,
    /// Stored payload MD5 in lowercase hexadecimal.
    pub md5: String,
    /// Recovery magic value 1.
    pub magic_1: u32,
    /// Recovery magic value 2.
    pub magic_2: u32,
    /// Recovery minor value.
    pub minor: u32,
    /// Legacy target device for header revisions before 2.
    pub device: Option<u32>,
    /// Platform used by header revision 2.
    pub platform: Option<Platform>,
    /// Header revision.
    pub header_revision: u32,
    /// Board used by header revision 2.
    pub board: Option<Board>,
}

/// Valid creation-time configurations for FB01/FB02 recovery packages.
///
/// Keeping the legacy and revision-2 layouts in separate variants makes it impossible to omit a
/// required device, platform, board, or target revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryV1Spec {
    /// Legacy FB01/FB02 recovery header containing one 32-bit device code.
    Legacy {
        /// FB01 or FB02.
        magic: BundleMagic,
        /// Recovery magic value 1.
        magic_1: u32,
        /// Recovery magic value 2.
        magic_2: u32,
        /// Recovery minor value.
        minor: u32,
        /// Legacy 32-bit device code.
        device: u32,
    },
    /// FB02 header revision 2 containing target, platform, and board fields.
    Revision2 {
        /// Target firmware revision.
        target_revision: u64,
        /// Recovery magic value 1.
        magic_1: u32,
        /// Recovery magic value 2.
        magic_2: u32,
        /// Recovery minor value.
        minor: u32,
        /// Hardware platform.
        platform: Platform,
        /// Hardware board.
        board: Board,
    },
}

/// Parsed recovery V2 header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryV2Header {
    /// Target firmware revision.
    pub target_revision: u64,
    /// Stored payload MD5 in lowercase hexadecimal.
    pub md5: String,
    /// Recovery magic value 1.
    pub magic_1: u32,
    /// Recovery magic value 2.
    pub magic_2: u32,
    /// Recovery minor value.
    pub minor: u32,
    /// Hardware platform.
    pub platform: Platform,
    /// Header revision.
    pub header_revision: u32,
    /// Hardware board.
    pub board: Board,
    /// Target devices in package order.
    pub devices: Vec<DeviceCode>,
}

/// Parsed component update header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentHeader {
    /// Minimum firmware revision.
    pub minimum_revision: u64,
    /// Target firmware revision.
    pub target_revision: u64,
    /// Cleartext component SHA-256.
    pub sha256: String,
    /// Component identifier.
    pub component: u32,
    /// Hardware platform.
    pub platform: Platform,
    /// Header revision.
    pub header_revision: u32,
    /// Target devices.
    pub devices: Vec<DeviceCode>,
}

/// Typed package header.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub fn payload_hash(&self) -> Option<&str> {
        match self {
            Self::OtaV1(header) => Some(&header.md5),
            Self::OtaV2(header) => Some(&header.md5),
            Self::RecoveryV1(header) => Some(&header.md5),
            Self::RecoveryV2(header) => Some(&header.md5),
            Self::Component(_) | Self::Userdata { .. } | Self::Android => None,
        }
    }

    /// Content hash stored by component bundles, which is not a hash of the tar payload.
    #[must_use]
    pub fn component_sha256(&self) -> Option<&str> {
        match self {
            Self::Component(header) => Some(&header.sha256),
            _ => None,
        }
    }
}

/// Parsed SP01 signing envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureEnvelope {
    /// Selected Kindle certificate.
    pub certificate: Certificate,
    /// The 56 reserved SP01 header bytes, retained without interpretation.
    pub reserved: Vec<u8>,
    /// Raw RSA signature bytes.
    pub signature: Vec<u8>,
}

/// Package metadata plus an optional outer signature envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageInfo {
    /// Decoded inner header.
    pub header: PackageHeader,
    /// SP01 envelope, when present.
    pub envelope: Option<SignatureEnvelope>,
    /// Exact inner magic and encoded header bytes, including unknown/reserved fields.
    pub raw_inner_header: Vec<u8>,
}

/// Strongly typed package creation specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageSpec {
    /// Create OTA V1.
    OtaV1(OtaV1Header),
    /// Create OTA V2.
    OtaV2(OtaV2Header),
    /// Create recovery V1 or FB02 revision 2.
    RecoveryV1(RecoveryV1Spec),
    /// Create recovery V2.
    RecoveryV2(RecoveryV2Header),
    /// Wrap a gzip archive directly in SP01.
    SignedUserdata,
}
