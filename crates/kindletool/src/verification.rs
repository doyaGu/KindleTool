//! Typed package verification policies and results.

use crate::crypto::VerificationKey;
use crate::devices::DeviceCode;
use crate::model::{Certificate, PackageHeader};

/// Outcome of cryptographically checking an SP01 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureStatus {
    /// The signature matches the complete inner package and supplied public key.
    Valid,
    /// The signature does not match the complete inner package and supplied public key.
    Invalid,
    /// The package has no SP01 envelope.
    Unsigned,
    /// The package is signed, but no public key was supplied.
    KeyMissing,
    /// The public key modulus length does not match the SP01 certificate selector.
    KeyMismatch,
}

/// SP01 signature verification result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SignatureVerification {
    /// Cryptographic result.
    pub status: SignatureStatus,
    /// Certificate selector declared by the SP01 envelope.
    pub certificate: Option<Certificate>,
}

/// Result of comparing a decoded payload with the digest stored in its package header.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PayloadIntegrityStatus {
    /// The decoded payload matches the stored digest.
    Valid,
    /// The decoded payload does not match the stored digest.
    Invalid {
        /// Digest stored in the package header.
        expected: String,
        /// Digest calculated from the decoded payload.
        actual: String,
    },
    /// This package format does not store a directly verifiable payload digest.
    NotAvailable,
}

/// Result of comparing a requested Kindle device with package targeting metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DeviceCompatibilityStatus {
    /// No target device was requested.
    NotChecked,
    /// The requested device is explicitly targeted.
    Compatible,
    /// The package explicitly targets other devices.
    Incompatible,
    /// This package header does not identify a concrete device.
    NotSpecified,
}

/// Inputs controlling package verification.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct VerificationOptions<'key> {
    /// Public key used for SP01 verification, or `None` to report [`SignatureStatus::KeyMissing`].
    pub signature_key: Option<&'key VerificationKey>,
    /// Device code to compare with package targeting metadata.
    pub target_device: Option<DeviceCode>,
}

/// Cryptographic and payload-integrity results for one package.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VerificationReport {
    /// SP01 signature result.
    pub signature: SignatureVerification,
    /// Decoded payload digest result.
    pub payload_integrity: PayloadIntegrityStatus,
    /// Requested-device compatibility result.
    pub device_compatibility: DeviceCompatibilityStatus,
}

pub(crate) fn device_compatibility(
    header: &PackageHeader,
    target: Option<DeviceCode>,
) -> DeviceCompatibilityStatus {
    let Some(target) = target else {
        return DeviceCompatibilityStatus::NotChecked;
    };
    let matches = match header {
        PackageHeader::OtaV1(header) => Some(header.device == target),
        PackageHeader::OtaV2(header) => device_list_matches(&header.devices, target),
        PackageHeader::RecoveryV1(header) => {
            header.device.map(|device| u32::from(target.0) == device)
        }
        PackageHeader::RecoveryV2(header) => device_list_matches(&header.devices, target),
        PackageHeader::Component(header) => device_list_matches(&header.devices, target),
        PackageHeader::Userdata { .. } | PackageHeader::Android => None,
    };
    match matches {
        Some(true) => DeviceCompatibilityStatus::Compatible,
        Some(false) => DeviceCompatibilityStatus::Incompatible,
        None => DeviceCompatibilityStatus::NotSpecified,
    }
}

fn device_list_matches(devices: &[DeviceCode], target: DeviceCode) -> Option<bool> {
    (!devices.is_empty()).then(|| devices.contains(&target))
}
