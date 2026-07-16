//! Validated values stored in Kindle package headers.

use crate::{Error, Result};
use std::fmt;
use std::str::FromStr;

/// A validated 128-bit MD5 digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Md5Digest([u8; 16]);

/// A validated 256-bit SHA-256 digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha256Digest([u8; 32]);

/// A Kindle firmware revision number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FirmwareRevision(u64);

/// An inclusive range of Kindle firmware revisions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FirmwareRange {
    minimum: FirmwareRevision,
    maximum: FirmwareRevision,
}

/// A normalized UTF-8 path stored inside a Kindle update archive.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArchivePath(String);

impl Md5Digest {
    /// Construct a digest from its raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl FromStr for Md5Digest {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Ok(Self(parse_hex::<16>(value, "MD5")?))
    }
}

impl fmt::Display for Md5Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

impl Sha256Digest {
    /// Construct a digest from its raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl FromStr for Sha256Digest {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Ok(Self(parse_hex::<32>(value, "SHA-256")?))
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

impl FirmwareRevision {
    /// Construct a firmware revision.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw revision number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for FirmwareRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<u32> for FirmwareRevision {
    fn from(value: u32) -> Self {
        Self(u64::from(value))
    }
}

impl From<u64> for FirmwareRevision {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl FirmwareRange {
    /// Construct a range containing exactly one revision.
    #[must_use]
    pub const fn exact(revision: FirmwareRevision) -> Self {
        Self {
            minimum: revision,
            maximum: revision,
        }
    }

    /// Construct an inclusive range, rejecting an inverted interval.
    pub fn new(minimum: FirmwareRevision, maximum: FirmwareRevision) -> Result<Self> {
        if minimum > maximum {
            return Err(Error::InvalidField {
                field: "firmware range",
                message: format!("minimum {minimum} exceeds maximum {maximum}"),
            });
        }
        Ok(Self { minimum, maximum })
    }

    /// Inclusive lower bound.
    #[must_use]
    pub const fn minimum(self) -> FirmwareRevision {
        self.minimum
    }

    /// Inclusive upper bound.
    #[must_use]
    pub const fn maximum(self) -> FirmwareRevision {
        self.maximum
    }

    /// Whether a revision is inside this inclusive range.
    #[must_use]
    pub const fn contains(self, revision: FirmwareRevision) -> bool {
        revision.0 >= self.minimum.0 && revision.0 <= self.maximum.0
    }
}

impl ArchivePath {
    /// Validate a normalized, relative archive path using `/` separators.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let bytes = value.as_bytes();
        let windows_drive_prefix =
            bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
        let valid = !value.is_empty()
            && !value.starts_with('/')
            && !value.contains('\\')
            && !windows_drive_prefix
            && !value.chars().any(char::is_control)
            && value
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..");
        if !valid {
            return Err(Error::UnsafeArchivePath(value.into()));
        }
        Ok(Self(value))
    }

    /// Return the normalized path text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArchivePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn parse_hex<const N: usize>(value: &str, field: &'static str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(invalid_hex(field, N));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0]).ok_or_else(|| invalid_hex(field, N))?;
        let low = hex_digit(pair[1]).ok_or_else(|| invalid_hex(field, N))?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn invalid_hex(field: &'static str, bytes: usize) -> Error {
    Error::InvalidField {
        field,
        message: format!("expected {} hexadecimal characters", bytes * 2),
    }
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
