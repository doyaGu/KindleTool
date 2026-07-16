//! Safe, typed support for Kindle update packages.
//!
//! The library deliberately keeps command-line parsing and environment variables out of the
//! package model. Callers choose parsing, conversion, archive, and signing policies explicitly.
//!
//! # Example
//!
//! ```no_run
//! use kindletool::{PackageReader, Result};
//! use std::fs::File;
//!
//! fn main() -> Result<()> {
//!     let package = PackageReader::new(File::open("Update_example.bin")?)?;
//!     println!("{}", package.info().header.magic());
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
/// Typed on-disk package models.
pub mod model;
/// Streaming package parsing and encoding.
pub mod package;
/// Human-readable and shell-friendly package reports.
pub mod report;
/// Kindle serial-number model and password derivation.
pub mod serial;
/// Typed package verification policies and results.
pub mod verification;

pub use archive::{
    ArchiveBuildReport, ArchiveExtractReport, ArchiveOptions, UpdateArchiveBuilder, extract_archive,
};
pub use codec::{DemangleReader, DemangleWriter, MangleReader, MangleWriter};
pub use crypto::{SigningKey, VerificationKey};
pub use devices::{DeviceCatalog, DeviceCode, DeviceFamily, DeviceRecord};
pub use error::{Error, Result};
pub use model::{
    Board, BundleMagic, Certificate, ComponentHeader, OtaV1Header, OtaV2Header, PackageHeader,
    PackageInfo, PackageSpec, Platform, RecoveryV1Header, RecoveryV1Spec, RecoveryV2Header,
    SignatureEnvelope,
};
pub use package::{PackageReader, PackageWriter, ParseOptions, SigningConfiguration, WriteOptions};
pub use verification::{
    DeviceCompatibilityStatus, PayloadIntegrityStatus, SignatureStatus, SignatureVerification,
    VerificationOptions, VerificationReport,
};
