//! Safe, typed support for Kindle update packages.
//!
//! The library deliberately keeps command-line parsing and environment variables out of the
//! package model. Callers choose parsing, conversion, archive, and signing policies explicitly.
//!
//! # Example
//!
//! ```no_run
//! use kindletool::{Package, Result};
//! use std::fs::File;
//!
//! fn main() -> Result<()> {
//!     let package = Package::parse(File::open("Update_example.bin")?)?;
//!     println!("{}", package.descriptor().magic());
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]

/// Kindle-compatible GNU tar/gzip archive creation and safe extraction.
pub mod archive;
/// Amazon byte obfuscation codecs.
pub mod codec;
/// Hashing and RSA signing and verification.
pub mod crypto;
/// Kindle device catalog and serial-number encoding.
pub mod devices;
mod error;
/// Data-driven Kindle package format metadata.
pub mod format;
/// Typed on-disk package models.
pub mod model;
/// Streaming package parsing and encoding.
pub mod package;
/// Human-readable and shell-friendly package reports.
pub mod report;
/// Kindle serial-number model and password derivation.
pub mod serial;
/// Validated values stored in Kindle package headers.
pub mod values;
/// Typed package verification policies and results.
pub mod verification;

pub use archive::{
    ArchiveBuildReport, ArchiveExtractReport, ArchiveInput, ArchiveIssue, ArchiveOptions,
    ArchiveVerificationReport, ComponentContentCheck, SafeExtractionOutcome, SafeExtractor,
    UpdateArchiveBuilder, UpdateArchiveVerifier, extract_archive,
};
pub use codec::{DemangleReader, DemangleWriter, MangleReader, MangleWriter};
pub use crypto::{SigningKey, VerificationKey};
pub use devices::{DeviceCatalog, DeviceCode, DeviceFamily, DeviceRecord};
pub use error::{Error, Result};
pub use format::{ArchiveKind, FormatProfile, PackageFormat};
pub use model::{
    Board, BundleMagic, Certificate, ComponentHeader, OtaV1Header, OtaV1Kind, OtaV1Spec,
    OtaV2Header, OtaV2Kind, OtaV2Spec, PackageDescriptor, PackageHeader, PackageSpec,
    PayloadDigest, Platform, RecoveryV1Header, RecoveryV1Kind, RecoveryV1Spec, RecoveryV2Header,
    RecoveryV2Spec, SignatureEnvelope, UserdataSpec,
};
pub use package::{
    EncodeOptions, EncodeReport, Package, PackageEncoder, ParseLimits, PayloadSource, PayloadView,
};
pub use values::{ArchivePath, FirmwareRange, FirmwareRevision, Md5Digest, Sha256Digest};
pub use verification::{
    ArchiveCheck, PayloadIntegrityCheck, SignatureCheck, TargetCheck, TargetFieldCheck,
    ValidationOutcome, VerificationContext, VerificationLimits, VerificationPolicy,
    VerificationReport,
};
