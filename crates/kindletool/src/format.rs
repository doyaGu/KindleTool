//! Data-driven Kindle package format metadata.

use crate::model::BundleMagic;

/// High-level package format independent of its exact on-disk magic.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PackageFormat {
    /// FB01 or FB02 recovery package.
    RecoveryV1,
    /// FB03 recovery package.
    RecoveryV2,
    /// FC02 or FD03 OTA package.
    OtaV1,
    /// FC04, FD04, or FL01 OTA package.
    OtaV2,
    /// SP01 signing envelope.
    SignatureEnvelope,
    /// CB01 component package.
    Component,
    /// Plain gzip userdata archive.
    Userdata,
    /// Android ZIP update.
    Android,
}

/// Archive conventions associated with a package format.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ArchiveKind {
    /// OTA archive using 64-byte file-list blocks.
    Ota,
    /// Recovery archive using 128-KiB file-list blocks.
    Recovery,
    /// Component archive whose header names one content digest.
    Component,
    /// Standalone userdata archive.
    Userdata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeaderLayout {
    OtaV1,
    OtaV2,
    RecoveryV1,
    RecoveryV2,
    Component,
    Raw,
    Envelope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PayloadStorage {
    Mangled,
    Raw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DigestKind {
    Md5,
    ComponentSha256,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DefaultEnvelope {
    Signed,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TargetMetadata {
    Device,
    Devices,
    RecoveryLayout,
    PlatformDevices,
    PlatformBoardDevices,
    None,
}

/// Immutable metadata describing one Kindle package magic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatProfile {
    format: PackageFormat,
    archive_kind: Option<ArchiveKind>,
    writable: bool,
    pub(crate) layout: HeaderLayout,
    pub(crate) payload_storage: PayloadStorage,
    pub(crate) digest: DigestKind,
    pub(crate) default_envelope: DefaultEnvelope,
    pub(crate) target_metadata: TargetMetadata,
}

impl FormatProfile {
    /// High-level format represented by the magic.
    #[must_use]
    pub const fn format(self) -> PackageFormat {
        self.format
    }

    /// Archive convention used by decoded payloads, when known.
    #[must_use]
    pub const fn archive_kind(self) -> Option<ArchiveKind> {
        self.archive_kind
    }

    /// Whether `KindleTool` can encode this format.
    #[must_use]
    pub const fn writable(self) -> bool {
        self.writable
    }

    /// Manifest block size used by this format, when applicable.
    #[must_use]
    pub const fn archive_block_size(self) -> Option<u64> {
        match self.archive_kind {
            Some(ArchiveKind::Ota | ArchiveKind::Component) => Some(64),
            Some(ArchiveKind::Recovery) => Some(131_072),
            Some(ArchiveKind::Userdata) | None => None,
        }
    }
}

pub(crate) struct FormatRecord {
    pub magic: BundleMagic,
    pub bytes: [u8; 4],
    pub description: &'static str,
    pub profile: FormatProfile,
}

const fn profile(
    format: PackageFormat,
    archive_kind: Option<ArchiveKind>,
    writable: bool,
    layout: HeaderLayout,
    payload_storage: PayloadStorage,
    digest: DigestKind,
) -> FormatProfile {
    let default_envelope = match format {
        PackageFormat::SignatureEnvelope | PackageFormat::Android => DefaultEnvelope::None,
        _ => DefaultEnvelope::Signed,
    };
    let target_metadata = match layout {
        HeaderLayout::OtaV1 => TargetMetadata::Device,
        HeaderLayout::OtaV2 => TargetMetadata::Devices,
        HeaderLayout::RecoveryV2 => TargetMetadata::PlatformBoardDevices,
        HeaderLayout::RecoveryV1 => TargetMetadata::RecoveryLayout,
        HeaderLayout::Component => TargetMetadata::PlatformDevices,
        HeaderLayout::Raw | HeaderLayout::Envelope => TargetMetadata::None,
    };
    FormatProfile {
        format,
        archive_kind,
        writable,
        layout,
        payload_storage,
        digest,
        default_envelope,
        target_metadata,
    }
}

pub(crate) const FORMAT_CATALOG: &[FormatRecord] = &[
    FormatRecord {
        magic: BundleMagic::Fb01,
        bytes: *b"FB01",
        description: "(Fullbin)",
        profile: profile(
            PackageFormat::RecoveryV1,
            Some(ArchiveKind::Recovery),
            true,
            HeaderLayout::RecoveryV1,
            PayloadStorage::Mangled,
            DigestKind::Md5,
        ),
    },
    FormatRecord {
        magic: BundleMagic::Fb02,
        bytes: *b"FB02",
        description: "(Fullbin [signed?])",
        profile: profile(
            PackageFormat::RecoveryV1,
            Some(ArchiveKind::Recovery),
            true,
            HeaderLayout::RecoveryV1,
            PayloadStorage::Mangled,
            DigestKind::Md5,
        ),
    },
    FormatRecord {
        magic: BundleMagic::Fb03,
        bytes: *b"FB03",
        description: "(Fullbin [OTA?, fwo?])",
        profile: profile(
            PackageFormat::RecoveryV2,
            Some(ArchiveKind::Recovery),
            true,
            HeaderLayout::RecoveryV2,
            PayloadStorage::Mangled,
            DigestKind::Md5,
        ),
    },
    FormatRecord {
        magic: BundleMagic::Fc02,
        bytes: *b"FC02",
        description: "(OTA [ota])",
        profile: profile(
            PackageFormat::OtaV1,
            Some(ArchiveKind::Ota),
            true,
            HeaderLayout::OtaV1,
            PayloadStorage::Mangled,
            DigestKind::Md5,
        ),
    },
    FormatRecord {
        magic: BundleMagic::Fc04,
        bytes: *b"FC04",
        description: "(OTA [ota])",
        profile: profile(
            PackageFormat::OtaV2,
            Some(ArchiveKind::Ota),
            true,
            HeaderLayout::OtaV2,
            PayloadStorage::Mangled,
            DigestKind::Md5,
        ),
    },
    FormatRecord {
        magic: BundleMagic::Fd03,
        bytes: *b"FD03",
        description: "(Versionless [vls])",
        profile: profile(
            PackageFormat::OtaV1,
            Some(ArchiveKind::Ota),
            true,
            HeaderLayout::OtaV1,
            PayloadStorage::Mangled,
            DigestKind::Md5,
        ),
    },
    FormatRecord {
        magic: BundleMagic::Fd04,
        bytes: *b"FD04",
        description: "(Versionless [vls])",
        profile: profile(
            PackageFormat::OtaV2,
            Some(ArchiveKind::Ota),
            true,
            HeaderLayout::OtaV2,
            PayloadStorage::Mangled,
            DigestKind::Md5,
        ),
    },
    FormatRecord {
        magic: BundleMagic::Fl01,
        bytes: *b"FL01",
        description: "(Language [lang])",
        profile: profile(
            PackageFormat::OtaV2,
            Some(ArchiveKind::Ota),
            true,
            HeaderLayout::OtaV2,
            PayloadStorage::Mangled,
            DigestKind::Md5,
        ),
    },
    FormatRecord {
        magic: BundleMagic::Sp01,
        bytes: *b"SP01",
        description: "(Signing Envelope)",
        profile: profile(
            PackageFormat::SignatureEnvelope,
            None,
            false,
            HeaderLayout::Envelope,
            PayloadStorage::Raw,
            DigestKind::None,
        ),
    },
    FormatRecord {
        magic: BundleMagic::Cb01,
        bytes: *b"CB01",
        description: "(Component [OTA?])",
        profile: profile(
            PackageFormat::Component,
            Some(ArchiveKind::Component),
            false,
            HeaderLayout::Component,
            PayloadStorage::Mangled,
            DigestKind::ComponentSha256,
        ),
    },
    FormatRecord {
        magic: BundleMagic::Zip,
        bytes: [0x50, 0x4B, 0x03, 0x04],
        description: "(Android update)",
        profile: profile(
            PackageFormat::Android,
            None,
            false,
            HeaderLayout::Raw,
            PayloadStorage::Raw,
            DigestKind::None,
        ),
    },
];

const GZIP_PROFILE: FormatProfile = profile(
    PackageFormat::Userdata,
    Some(ArchiveKind::Userdata),
    true,
    HeaderLayout::Raw,
    PayloadStorage::Raw,
    DigestKind::None,
);

pub(crate) fn fixed_records() -> impl ExactSizeIterator<Item = &'static FormatRecord> {
    FORMAT_CATALOG.iter()
}

pub(crate) fn by_bytes(bytes: [u8; 4]) -> Option<&'static FormatRecord> {
    FORMAT_CATALOG.iter().find(|record| record.bytes == bytes)
}

pub(crate) fn record(magic: BundleMagic) -> Option<&'static FormatRecord> {
    FORMAT_CATALOG.iter().find(|record| record.magic == magic)
}

pub(crate) fn magic_profile(magic: BundleMagic) -> &'static FormatProfile {
    let profile = if matches!(magic, BundleMagic::Gzip(_)) {
        &GZIP_PROFILE
    } else {
        &record(magic)
            .expect("fixed magic has a catalog record")
            .profile
    };
    debug_assert!(profile_is_consistent(*profile));
    profile
}

const fn profile_is_consistent(profile: FormatProfile) -> bool {
    let raw_has_no_target = !matches!(profile.layout, HeaderLayout::Raw | HeaderLayout::Envelope)
        || matches!(profile.target_metadata, TargetMetadata::None);
    let envelope_is_not_wrapped = !matches!(profile.layout, HeaderLayout::Envelope)
        || matches!(profile.default_envelope, DefaultEnvelope::None);
    let digest_matches_storage = !matches!(profile.digest, DigestKind::Md5)
        || matches!(profile.payload_storage, PayloadStorage::Mangled);
    raw_has_no_target && envelope_is_not_wrapped && digest_matches_storage
}
