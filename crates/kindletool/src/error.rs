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
    /// A requested operation is unsupported for the encountered format.
    #[error("unsupported format operation {operation}")]
    UnsupportedFormat {
        /// Stable operation identifier.
        operation: &'static str,
    },
    /// Archive content attempted to escape its extraction root.
    #[error("unsafe archive path: {0}")]
    UnsafeArchivePath(PathBuf),
    /// Archive content disagrees with its manifest or expected structure.
    #[error("archive mismatch at {path:?}: expected {expected}, found {actual}")]
    ArchiveMismatch {
        /// Associated path, when the mismatch belongs to one entry.
        path: Option<PathBuf>,
        /// Stable expected condition.
        expected: String,
        /// Observed condition.
        actual: String,
    },
    /// RSA key parsing, validation, signing, or verification setup failed.
    #[error("invalid RSA key: {message}")]
    InvalidKey {
        /// Parser or validation detail.
        message: String,
    },
}

/// Library result alias.
pub type Result<T> = std::result::Result<T, Error>;
