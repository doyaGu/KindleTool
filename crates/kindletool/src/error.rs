use std::io;
use std::path::PathBuf;

/// Error type returned by the `KindleTool` library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An underlying I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// The input ended before a complete value could be read.
    #[error("truncated {context}: need {needed} bytes, only {remaining} remain")]
    Truncated {
        /// Name of the value being decoded.
        context: &'static str,
        /// Required byte count.
        needed: usize,
        /// Available byte count.
        remaining: usize,
    },
    /// The bundle magic is not recognized.
    #[error("unknown update bundle magic {0:02X?}")]
    UnknownMagic([u8; 4]),
    /// A decoded field is invalid for its bundle type.
    #[error("invalid {field}: {message}")]
    InvalidField {
        /// Field name.
        field: &'static str,
        /// Human-readable explanation.
        message: String,
    },
    /// A requested operation is unsupported for this bundle.
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
    /// Archive content attempted to escape its extraction root.
    #[error("unsafe archive path: {0}")]
    UnsafeArchivePath(PathBuf),
    /// A source path could not be represented in a Kindle update archive.
    #[error("unsupported filesystem entry: {0}")]
    UnsupportedEntry(PathBuf),
    /// The payload digest does not match the header.
    #[error("integrity check failed: header {expected}, payload {actual}")]
    Integrity {
        /// Digest stored in the package header.
        expected: String,
        /// Digest calculated from the decoded payload.
        actual: String,
    },
    /// RSA key parsing, validation, signing, or verification setup failed.
    #[error("RSA error: {0}")]
    Rsa(String),
}

/// Library result alias.
pub type Result<T> = std::result::Result<T, Error>;
