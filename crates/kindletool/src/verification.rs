//! Fixed package verification policies and typed verdicts.

use crate::crypto::VerificationKey;
use crate::model::{Board, Certificate, PackageDescriptor, PackageHeader, Platform};
use crate::{DeviceCode, FirmwareRevision, Md5Digest, Sha256Digest};

/// One of the two supported verification policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    authentic: bool,
}

impl VerificationPolicy {
    /// Require structural integrity; an unavailable signing key remains unverified.
    #[must_use]
    pub const fn structural() -> Self {
        Self { authentic: false }
    }

    /// Require structural integrity and every applicable signature.
    #[must_use]
    pub const fn authentic() -> Self {
        Self { authentic: true }
    }

    pub(crate) const fn requires_authenticity(self) -> bool {
        self.authentic
    }
}

/// Resource limits applied while verifying untrusted content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[allow(clippy::struct_field_names)]
pub struct VerificationLimits {
    /// Maximum uncompressed archive bytes inspected.
    pub(crate) max_uncompressed_bytes: u64,
    /// Maximum archive entries inspected.
    pub(crate) max_archive_entries: usize,
    /// Maximum UTF-8 archive path length.
    pub(crate) max_path_bytes: usize,
    /// Maximum manifest bytes retained.
    pub(crate) max_manifest_bytes: usize,
}

impl VerificationLimits {
    /// Construct explicit non-zero verification limits.
    pub fn new(
        max_uncompressed_bytes: u64,
        max_archive_entries: usize,
        max_path_bytes: usize,
        max_manifest_bytes: usize,
    ) -> crate::Result<Self> {
        if max_uncompressed_bytes == 0
            || max_archive_entries == 0
            || max_path_bytes == 0
            || max_manifest_bytes == 0
        {
            return Err(crate::Error::InvalidField {
                field: "verification limits",
                message: "all limits must be greater than zero".to_owned(),
            });
        }
        Ok(Self {
            max_uncompressed_bytes,
            max_archive_entries,
            max_path_bytes,
            max_manifest_bytes,
        })
    }
}

impl Default for VerificationLimits {
    fn default() -> Self {
        Self {
            max_uncompressed_bytes: 2 * 1024 * 1024 * 1024,
            max_archive_entries: 100_000,
            max_path_bytes: 4096,
            max_manifest_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Keys, optional target identity, and limits used for package verification.
#[derive(Debug, Default)]
pub struct VerificationContext {
    package_keys: Vec<(Certificate, VerificationKey)>,
    archive_key: Option<VerificationKey>,
    target_device: Option<DeviceCode>,
    target_firmware: Option<FirmwareRevision>,
    target_platform: Option<Platform>,
    target_board: Option<Board>,
    limits: VerificationLimits,
}

impl VerificationContext {
    /// Construct an empty context with conservative resource limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a public key for one SP01 certificate selector.
    #[must_use]
    pub fn with_package_key(mut self, certificate: Certificate, key: VerificationKey) -> Self {
        self.package_keys
            .retain(|(candidate, _)| *candidate != certificate);
        self.package_keys.push((certificate, key));
        self
    }

    /// Set the public key used for archive index and per-file signatures.
    #[must_use]
    pub fn with_archive_key(mut self, key: VerificationKey) -> Self {
        self.archive_key = Some(key);
        self
    }

    /// Set the device against which targeting metadata is checked.
    #[must_use]
    pub const fn with_target_device(mut self, device: DeviceCode) -> Self {
        self.target_device = Some(device);
        self
    }

    /// Set the firmware revision against which targeting metadata is checked.
    #[must_use]
    pub const fn with_target_firmware(mut self, revision: FirmwareRevision) -> Self {
        self.target_firmware = Some(revision);
        self
    }

    /// Set the platform against which targeting metadata is checked.
    #[must_use]
    pub const fn with_target_platform(mut self, platform: Platform) -> Self {
        self.target_platform = Some(platform);
        self
    }

    /// Set the board against which targeting metadata is checked.
    #[must_use]
    pub const fn with_target_board(mut self, board: Board) -> Self {
        self.target_board = Some(board);
        self
    }

    /// Replace verification resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: VerificationLimits) -> Self {
        self.limits = limits;
        self
    }

    pub(crate) fn package_key(&self, certificate: Certificate) -> Option<&VerificationKey> {
        self.package_keys
            .iter()
            .find_map(|(candidate, key)| (*candidate == certificate).then_some(key))
    }
    pub(crate) const fn archive_key(&self) -> Option<&VerificationKey> {
        self.archive_key.as_ref()
    }
    pub(crate) const fn target_device(&self) -> Option<DeviceCode> {
        self.target_device
    }
    pub(crate) const fn target_firmware(&self) -> Option<FirmwareRevision> {
        self.target_firmware
    }
    pub(crate) const fn target_platform(&self) -> Option<Platform> {
        self.target_platform
    }
    pub(crate) const fn target_board(&self) -> Option<Board> {
        self.target_board
    }
    pub(crate) const fn limits(&self) -> VerificationLimits {
        self.limits
    }
}

/// SP01 signature check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureCheck {
    /// No SP01 envelope is present.
    Unsigned,
    /// No key is registered for the declared certificate.
    MissingKey {
        /// Certificate declared by SP01.
        certificate: Certificate,
    },
    /// The registered key length does not match the certificate selector.
    KeyMismatch {
        /// Certificate declared by SP01.
        certificate: Certificate,
    },
    /// Signature is valid.
    Valid {
        /// Certificate declared by SP01.
        certificate: Certificate,
    },
    /// Signature is invalid.
    Invalid {
        /// Certificate declared by SP01.
        certificate: Certificate,
    },
}

/// Header payload-integrity check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PayloadIntegrityCheck {
    /// Decoded payload MD5 is valid.
    Valid {
        /// Calculated and expected digest.
        digest: Md5Digest,
    },
    /// Decoded payload MD5 differs from the header.
    Invalid {
        /// Digest declared by the header.
        expected: Md5Digest,
        /// Digest calculated from decoded payload bytes.
        actual: Md5Digest,
    },
    /// The format has no directly checkable payload digest.
    NotPresent,
    /// Integrity exists but its scope requires archive inspection.
    UnsupportedScope,
    /// CB01 single component content matches its header digest.
    ComponentValid {
        /// Calculated and expected content digest.
        digest: Sha256Digest,
    },
    /// CB01 component content differs from its header digest.
    ComponentInvalid {
        /// Digest declared by CB01.
        expected: Sha256Digest,
        /// Digest calculated from the unique content candidate.
        actual: Sha256Digest,
    },
    /// CB01 archive does not contain exactly one content candidate.
    ComponentAmbiguous {
        /// Number of ordinary regular-file candidates found.
        candidates: usize,
    },
}

/// Archive-level verification status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArchiveCheck {
    /// Archive inspection was not requested or implemented for this payload.
    NotChecked,
    /// The package does not contain an archive.
    NotArchive,
    /// Archive paths, manifest, hashes, and required signatures are valid.
    Valid,
    /// Archive validation found one or more mismatches.
    Invalid,
}

/// Result of checking one optional targeting dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TargetFieldCheck {
    /// Caller did not supply this target field.
    NotChecked,
    /// Package metadata matches the supplied target.
    Match,
    /// Package metadata excludes the supplied target.
    Mismatch,
    /// Package does not constrain this target field.
    NotSpecified,
}

/// Independent target checks; this deliberately does not claim global compatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TargetCheck {
    device: TargetFieldCheck,
    firmware: TargetFieldCheck,
    platform: TargetFieldCheck,
    board: TargetFieldCheck,
}

impl TargetCheck {
    /// Device targeting result.
    #[must_use]
    pub const fn device(&self) -> TargetFieldCheck {
        self.device
    }
    /// Firmware targeting result.
    #[must_use]
    pub const fn firmware(&self) -> TargetFieldCheck {
        self.firmware
    }
    /// Platform targeting result.
    #[must_use]
    pub const fn platform(&self) -> TargetFieldCheck {
        self.platform
    }
    /// Board targeting result.
    #[must_use]
    pub const fn board(&self) -> TargetFieldCheck {
        self.board
    }
}

/// Fixed verification report for one package.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VerificationReport {
    signature: SignatureCheck,
    payload: PayloadIntegrityCheck,
    archive: ArchiveCheck,
    target: TargetCheck,
}

impl VerificationReport {
    /// SP01 signature result.
    #[must_use]
    pub const fn signature(&self) -> SignatureCheck {
        self.signature
    }
    /// Payload-integrity result.
    #[must_use]
    pub const fn payload(&self) -> PayloadIntegrityCheck {
        self.payload
    }
    /// Archive result.
    #[must_use]
    pub const fn archive(&self) -> ArchiveCheck {
        self.archive
    }
    /// Targeting results.
    #[must_use]
    pub const fn target(&self) -> &TargetCheck {
        &self.target
    }

    pub(crate) const fn new(
        signature: SignatureCheck,
        payload: PayloadIntegrityCheck,
        archive: ArchiveCheck,
        target: TargetCheck,
    ) -> Self {
        Self {
            signature,
            payload,
            archive,
            target,
        }
    }
}

/// Policy decision separated from verification execution errors.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidationOutcome {
    /// All requirements of the selected policy were met.
    Accepted(VerificationReport),
    /// Verification completed but one or more policy requirements failed.
    Rejected(VerificationReport),
}

impl ValidationOutcome {
    /// Borrow the complete report regardless of verdict.
    #[must_use]
    pub const fn report(&self) -> &VerificationReport {
        match self {
            Self::Accepted(report) | Self::Rejected(report) => report,
        }
    }

    /// Whether the selected policy accepted the package.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }
}

pub(crate) fn target_check(
    descriptor: &PackageDescriptor,
    context: &VerificationContext,
) -> TargetCheck {
    let device = check_optional(context.target_device(), |target| {
        if let PackageHeader::RecoveryV1(header) = descriptor.header() {
            if let Some(device) = header.legacy_device() {
                return Some(device == u32::from(target.0));
            }
        }
        let devices = descriptor.target_devices();
        (!devices.is_empty()).then(|| devices.contains(&target))
    });
    let firmware = check_optional(context.target_firmware(), |target| {
        descriptor
            .firmware_range()
            .map(|range| range.contains(target))
    });
    let platform = check_optional(context.target_platform(), |target| {
        descriptor.platform().map(|value| value == target)
    });
    let board = check_optional(context.target_board(), |target| {
        descriptor.board().map(|value| value == target)
    });
    TargetCheck {
        device,
        firmware,
        platform,
        board,
    }
}

fn check_optional<T: Copy>(
    target: Option<T>,
    check: impl FnOnce(T) -> Option<bool>,
) -> TargetFieldCheck {
    let Some(target) = target else {
        return TargetFieldCheck::NotChecked;
    };
    match check(target) {
        Some(true) => TargetFieldCheck::Match,
        Some(false) => TargetFieldCheck::Mismatch,
        None => TargetFieldCheck::NotSpecified,
    }
}

pub(crate) const fn accepts(policy: VerificationPolicy, report: &VerificationReport) -> bool {
    let structural = !matches!(
        report.signature,
        SignatureCheck::Invalid { .. } | SignatureCheck::KeyMismatch { .. }
    ) && matches!(
        report.payload,
        PayloadIntegrityCheck::Valid { .. }
            | PayloadIntegrityCheck::ComponentValid { .. }
            | PayloadIntegrityCheck::NotPresent
    ) && !matches!(report.archive, ArchiveCheck::Invalid)
        && !matches!(report.target.device, TargetFieldCheck::Mismatch)
        && !matches!(report.target.firmware, TargetFieldCheck::Mismatch)
        && !matches!(report.target.platform, TargetFieldCheck::Mismatch)
        && !matches!(report.target.board, TargetFieldCheck::Mismatch);
    structural
        && (!policy.requires_authenticity()
            || matches!(report.signature, SignatureCheck::Valid { .. }))
}
