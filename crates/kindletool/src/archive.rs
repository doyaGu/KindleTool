use crate::crypto::{SigningKey, VerificationKey, md5_hex, md5_hex_reader, sha256_hex_reader};
use crate::{
    ArchiveKind, ArchivePath, Error, Result, Sha256Digest, VerificationLimits, VerificationPolicy,
};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::UNIX_EPOCH;
use tar::{Builder, EntryType, Header};
use walkdir::WalkDir;

/// Filename of the Kindle per-file bundle index.
pub const INDEX_FILE_NAME: &str = "update-filelist.dat";
/// OTA bundle block size.
pub const OTA_BLOCK_SIZE: u64 = 64;
/// Recovery bundle block size.
pub const RECOVERY_BLOCK_SIZE: u64 = 131_072;

/// Archive path and block-size behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveOptions {
    /// Store directory contents relative to each explicitly passed directory.
    pub(crate) legacy_paths: bool,
    /// Block size written to `update-filelist.dat`.
    pub(crate) block_size: u64,
}

impl ArchiveOptions {
    /// Construct archive options with an explicit block size.
    pub fn new(legacy_paths: bool, block_size: u64) -> Result<Self> {
        if !matches!(block_size, OTA_BLOCK_SIZE | RECOVERY_BLOCK_SIZE) {
            return Err(Error::InvalidField {
                field: "block size",
                message: format!(
                    "must be {OTA_BLOCK_SIZE} for OTA or {RECOVERY_BLOCK_SIZE} for recovery"
                ),
            });
        }
        Ok(Self {
            legacy_paths,
            block_size,
        })
    }

    /// Whether directory contents use legacy root-relative paths.
    #[must_use]
    pub const fn legacy_paths(&self) -> bool {
        self.legacy_paths
    }

    /// File-list block size.
    #[must_use]
    pub const fn block_size(&self) -> u64 {
        self.block_size
    }

    const fn archive_kind(self) -> ArchiveKind {
        if self.block_size == RECOVERY_BLOCK_SIZE {
            ArchiveKind::Recovery
        } else {
            ArchiveKind::Ota
        }
    }
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            legacy_paths: false,
            block_size: OTA_BLOCK_SIZE,
        }
    }
}

/// Summary returned after building an update archive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ArchiveBuildReport {
    /// Number of source entries added, excluding generated signatures and the index.
    source_entries: usize,
    /// Number of regular source files signed.
    signed_files: usize,
    /// Whether at least one `.sh` or `.ffs` script was found.
    has_script: bool,
}

impl ArchiveBuildReport {
    /// Number of source entries added.
    #[must_use]
    pub const fn source_entries(&self) -> usize {
        self.source_entries
    }
    /// Number of regular files signed.
    #[must_use]
    pub const fn signed_files(&self) -> usize {
        self.signed_files
    }
    /// Whether the archive contains an executable script.
    #[must_use]
    pub const fn has_script(&self) -> bool {
        self.has_script
    }
}

/// Summary returned after extracting an update archive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ArchiveExtractReport {
    /// Number of archive entries extracted.
    entries: usize,
}

impl ArchiveExtractReport {
    /// Number of entries committed.
    #[must_use]
    pub const fn entries(&self) -> usize {
        self.entries
    }
}

/// Explicit source-to-archive path mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveInput {
    source: PathBuf,
    destination: ArchivePath,
}

impl ArchiveInput {
    /// Construct an explicit source-to-destination mapping.
    #[must_use]
    pub const fn new(source: PathBuf, destination: ArchivePath) -> Self {
        Self {
            source,
            destination,
        }
    }

    /// Map a source to its final path component.
    pub fn from_source(source: PathBuf) -> Result<Self> {
        let destination =
            source
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or_else(|| Error::InvalidField {
                    field: "archive input",
                    message: format!("{} has no UTF-8 final path component", source.display()),
                })?;
        let destination = ArchivePath::new(destination)?;
        Ok(Self {
            source,
            destination,
        })
    }

    /// Filesystem source.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Normalized archive destination.
    #[must_use]
    pub const fn destination(&self) -> &ArchivePath {
        &self.destination
    }
}

/// A concrete archive mismatch found during verification.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArchiveIssue {
    /// A path is unsafe, duplicated, non-UTF-8, or exceeds configured limits.
    UnsafePath(String),
    /// The archive contains an unsupported entry type.
    UnsupportedEntry(String),
    /// A required manifest or signature entry is absent or duplicated.
    MissingEntry(String),
    /// A regular entry is not represented consistently by the manifest.
    ManifestMismatch(String),
    /// A file digest differs from the manifest.
    DigestMismatch(String),
    /// A required archive signature is absent, invalid, or cannot be checked.
    SignatureMismatch(String),
    /// A configured resource limit was exceeded.
    LimitExceeded(&'static str),
}

/// Result of checking one update archive.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ArchiveVerificationReport {
    entries: usize,
    issues: Vec<ArchiveIssue>,
    component_content: ComponentContentCheck,
}

impl ArchiveVerificationReport {
    /// Number of archive entries inspected.
    #[must_use]
    pub const fn entries(&self) -> usize {
        self.entries
    }

    /// All concrete mismatches found.
    #[must_use]
    pub fn issues(&self) -> &[ArchiveIssue] {
        &self.issues
    }

    /// Whether every check required by the selected policy passed.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }

    /// CB01 content candidate result.
    #[must_use]
    pub const fn component_content(&self) -> ComponentContentCheck {
        self.component_content
    }
}

/// Result of identifying the single content file covered by a CB01 header digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ComponentContentCheck {
    /// Archive kind is not component.
    NotApplicable,
    /// Exactly one ordinary regular file was found.
    Unique(Sha256Digest),
    /// Zero or multiple content candidates were found.
    Ambiguous {
        /// Number of ordinary regular-file candidates found.
        candidates: usize,
    },
}

/// Streaming safety, manifest, digest, and signature verifier for update archives.
pub struct UpdateArchiveVerifier<'key> {
    kind: ArchiveKind,
    policy: VerificationPolicy,
    key: Option<&'key VerificationKey>,
    limits: VerificationLimits,
}

/// Result of verification-gated extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SafeExtractionOutcome {
    /// Verification passed and the staging directory was committed.
    Extracted(ArchiveExtractReport),
    /// Verification completed but rejected the archive; nothing was extracted.
    Rejected(ArchiveVerificationReport),
}

/// Verification-gated, staging-based archive extractor.
pub struct SafeExtractor<'key> {
    verifier: UpdateArchiveVerifier<'key>,
}

impl<'key> SafeExtractor<'key> {
    /// Construct an extractor with explicit archive verification settings.
    #[must_use]
    pub const fn new(
        kind: ArchiveKind,
        policy: VerificationPolicy,
        key: Option<&'key VerificationKey>,
        limits: VerificationLimits,
    ) -> Self {
        Self {
            verifier: UpdateArchiveVerifier::new(kind, policy, key, limits),
        }
    }

    /// Verify into a seekable spool, then atomically extract only an accepted archive.
    pub fn extract<R: Read>(
        &self,
        mut reader: R,
        destination: &Path,
    ) -> Result<SafeExtractionOutcome> {
        let mut spool = tempfile::tempfile()?;
        std::io::copy(&mut reader, &mut spool)?;
        spool.seek(std::io::SeekFrom::Start(0))?;
        let report = self.verifier.verify(&mut spool)?;
        if !report.is_valid() {
            return Ok(SafeExtractionOutcome::Rejected(report));
        }
        spool.seek(std::io::SeekFrom::Start(0))?;
        Ok(SafeExtractionOutcome::Extracted(extract_archive(
            spool,
            destination,
        )?))
    }
}

impl<'key> UpdateArchiveVerifier<'key> {
    /// Construct a verifier with explicit policy and optional archive key.
    #[must_use]
    pub const fn new(
        kind: ArchiveKind,
        policy: VerificationPolicy,
        key: Option<&'key VerificationKey>,
        limits: VerificationLimits,
    ) -> Self {
        Self {
            kind,
            policy,
            key,
            limits,
        }
    }

    /// Verify a gzip-compressed GNU tar stream without extracting it.
    pub fn verify<R: Read>(&self, reader: R) -> Result<ArchiveVerificationReport> {
        verify_update_archive(reader, self.kind, self.policy, self.key, self.limits)
    }
}

#[derive(Debug)]
struct ManifestRecord {
    file_type: u32,
    md5: String,
    path: String,
    blocks: u64,
}

#[derive(Clone, Copy, Debug)]
struct StoredFile {
    offset: u64,
    length: u64,
}

fn verify_update_archive<R: Read>(
    reader: R,
    kind: ArchiveKind,
    policy: VerificationPolicy,
    key: Option<&VerificationKey>,
    limits: VerificationLimits,
) -> Result<ArchiveVerificationReport> {
    let decoder = GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let mut seen = HashSet::new();
    let mut files = HashMap::<String, StoredFile>::new();
    let mut spool = tempfile::tempfile()?;
    let mut issues = Vec::new();
    let mut entries = 0_usize;
    let mut total = 0_u64;

    for item in archive.entries()? {
        entries = entries.saturating_add(1);
        if entries > limits.max_archive_entries {
            issues.push(ArchiveIssue::LimitExceeded("archive entries"));
            break;
        }
        let mut entry = item?;
        let entry_type = entry.header().entry_type();
        let path = match entry.path()?.to_str() {
            Some(value) if entry_type.is_dir() => {
                value.replace('\\', "/").trim_end_matches('/').to_owned()
            }
            Some(value) => value.replace('\\', "/"),
            None => {
                issues.push(ArchiveIssue::UnsafePath("non-UTF-8 path".to_owned()));
                continue;
            }
        };
        if path.len() > limits.max_path_bytes || crate::ArchivePath::new(path.clone()).is_err() {
            issues.push(ArchiveIssue::UnsafePath(path));
            continue;
        }
        if !seen.insert(path.clone()) {
            issues.push(ArchiveIssue::UnsafePath(format!("duplicate path {path}")));
            continue;
        }
        if entry_type.is_dir() {
            continue;
        }
        if matches!(entry_type, EntryType::Symlink | EntryType::Link) {
            if validate_link_target(&entry, Path::new(&path)).is_err() {
                issues.push(ArchiveIssue::UnsafePath(path));
            }
            continue;
        }
        if !entry_type.is_file() {
            issues.push(ArchiveIssue::UnsupportedEntry(path));
            continue;
        }
        let declared = entry.size();
        total = total.saturating_add(declared);
        if total > limits.max_uncompressed_bytes {
            issues.push(ArchiveIssue::LimitExceeded("uncompressed bytes"));
            break;
        }
        if path == INDEX_FILE_NAME && declared > limits.max_manifest_bytes as u64 {
            issues.push(ArchiveIssue::LimitExceeded("manifest bytes"));
            continue;
        }
        let offset = spool.stream_position()?;
        let length = std::io::copy(&mut entry, &mut spool)?;
        if length != declared {
            issues.push(ArchiveIssue::ManifestMismatch(format!(
                "declared size for {path}"
            )));
        }
        files.insert(path, StoredFile { offset, length });
    }

    if kind == ArchiveKind::Userdata {
        return Ok(ArchiveVerificationReport {
            entries,
            issues,
            component_content: ComponentContentCheck::NotApplicable,
        });
    }

    let component_content = if kind == ArchiveKind::Component {
        let candidates = files
            .iter()
            .filter(|(path, _)| path.as_str() != INDEX_FILE_NAME && !is_signature_path(path))
            .collect::<Vec<_>>();
        if let [(_, file)] = candidates.as_slice() {
            ComponentContentCheck::Unique(spooled_sha256(&mut spool, file)?)
        } else {
            ComponentContentCheck::Ambiguous {
                candidates: candidates.len(),
            }
        }
    } else {
        ComponentContentCheck::NotApplicable
    };

    let Some(index_file) = files.get(INDEX_FILE_NAME) else {
        issues.push(ArchiveIssue::MissingEntry(INDEX_FILE_NAME.to_owned()));
        return Ok(ArchiveVerificationReport {
            entries,
            issues,
            component_content,
        });
    };
    let index = read_spooled_file(&mut spool, index_file)?;
    let records = parse_manifest(&index, &mut issues);
    let block_size = kind.block_size();
    let mut listed = HashSet::new();
    for record in records {
        if !listed.insert(record.path.clone()) {
            issues.push(ArchiveIssue::ManifestMismatch(format!(
                "duplicate manifest path {}",
                record.path
            )));
            continue;
        }
        let Some(data) = files.get(&record.path) else {
            issues.push(ArchiveIssue::MissingEntry(record.path));
            continue;
        };
        if spooled_md5(&mut spool, data)? != record.md5.to_ascii_lowercase() {
            issues.push(ArchiveIssue::DigestMismatch(record.path.clone()));
        }
        if data.length / block_size != record.blocks {
            issues.push(ArchiveIssue::ManifestMismatch(format!(
                "block count for {}",
                record.path
            )));
        }
        let expected_type = if kind == ArchiveKind::Recovery && is_kernel(Path::new(&record.path)) {
            1
        } else if is_script(Path::new(&record.path)) {
            129
        } else {
            128
        };
        if record.file_type != expected_type {
            issues.push(ArchiveIssue::ManifestMismatch(format!(
                "file type for {}",
                record.path
            )));
        }
        verify_archive_signature(
            key,
            policy,
            &mut spool,
            data,
            files.get(&format!("{}.sig", record.path)),
            &record.path,
            &mut issues,
        )?;
    }

    for path in files.keys() {
        if path == INDEX_FILE_NAME || path == "update-filelist.dat.sig" || is_signature_path(path) {
            continue;
        }
        if !listed.contains(path) {
            issues.push(ArchiveIssue::ManifestMismatch(format!(
                "unlisted file {path}"
            )));
        }
    }
    for path in files
        .keys()
        .filter(|path| is_signature_path(path) && path.as_str() != "update-filelist.dat.sig")
    {
        let source = &path[..path.len() - 4];
        if !listed.contains(source) {
            issues.push(ArchiveIssue::ManifestMismatch(format!(
                "orphan signature {path}"
            )));
        }
    }
    verify_archive_signature(
        key,
        policy,
        &mut spool,
        index_file,
        files.get("update-filelist.dat.sig"),
        INDEX_FILE_NAME,
        &mut issues,
    )?;
    Ok(ArchiveVerificationReport {
        entries,
        issues,
        component_content,
    })
}

fn parse_manifest(index: &[u8], issues: &mut Vec<ArchiveIssue>) -> Vec<ManifestRecord> {
    let Ok(text) = std::str::from_utf8(index) else {
        issues.push(ArchiveIssue::ManifestMismatch(
            "manifest is not UTF-8".to_owned(),
        ));
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 5 {
                issues.push(ArchiveIssue::ManifestMismatch(format!(
                    "malformed line: {line}"
                )));
                return None;
            }
            let Ok(file_type) = fields[0].parse() else {
                issues.push(ArchiveIssue::ManifestMismatch(format!("file type: {line}")));
                return None;
            };
            if fields[1].len() != 32 || !fields[1].bytes().all(|byte| byte.is_ascii_hexdigit()) {
                issues.push(ArchiveIssue::ManifestMismatch(format!("MD5: {line}")));
                return None;
            }
            let Ok(blocks) = fields[fields.len() - 2].parse() else {
                issues.push(ArchiveIssue::ManifestMismatch(format!(
                    "block count: {line}"
                )));
                return None;
            };
            let path = fields[2..fields.len() - 2].join(" ");
            if crate::ArchivePath::new(path.clone()).is_err() {
                issues.push(ArchiveIssue::UnsafePath(path));
                return None;
            }
            Some(ManifestRecord {
                file_type,
                md5: fields[1].to_owned(),
                path,
                blocks,
            })
        })
        .collect()
}

fn verify_archive_signature(
    key: Option<&VerificationKey>,
    policy: VerificationPolicy,
    spool: &mut File,
    data: &StoredFile,
    signature: Option<&StoredFile>,
    path: &str,
    issues: &mut Vec<ArchiveIssue>,
) -> Result<()> {
    let Some(signature) = signature else {
        issues.push(ArchiveIssue::MissingEntry(format!("{path}.sig")));
        return Ok(());
    };
    let Some(key) = key else {
        if policy == VerificationPolicy::authentic() {
            issues.push(ArchiveIssue::SignatureMismatch(format!(
                "missing key for {path}"
            )));
        }
        return Ok(());
    };
    if signature.length != key.size() as u64 {
        issues.push(ArchiveIssue::SignatureMismatch(path.to_owned()));
        return Ok(());
    }
    let signature = read_spooled_file(spool, signature)?;
    spool.seek(SeekFrom::Start(data.offset))?;
    if !key.verify_reader((&mut *spool).take(data.length), &signature)? {
        issues.push(ArchiveIssue::SignatureMismatch(path.to_owned()));
    }
    Ok(())
}

fn read_spooled_file(spool: &mut File, file: &StoredFile) -> Result<Vec<u8>> {
    let length = usize::try_from(file.length).map_err(|_| Error::InvalidField {
        field: "archive entry size",
        message: format!("{} bytes cannot be retained on this platform", file.length),
    })?;
    let mut data = vec![0_u8; length];
    spool.seek(SeekFrom::Start(file.offset))?;
    spool.read_exact(&mut data)?;
    Ok(data)
}

fn spooled_md5(spool: &mut File, file: &StoredFile) -> Result<String> {
    spool.seek(SeekFrom::Start(file.offset))?;
    md5_hex_reader((&mut *spool).take(file.length))
}

fn spooled_sha256(spool: &mut File, file: &StoredFile) -> Result<Sha256Digest> {
    spool.seek(SeekFrom::Start(file.offset))?;
    Sha256Digest::from_str(&sha256_hex_reader((&mut *spool).take(file.length))?)
}

fn is_signature_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("sig"))
}

/// Builds Kindle-compatible GNU tar/gzip archives and their per-file signatures.
pub struct UpdateArchiveBuilder<'key> {
    key: &'key SigningKey,
    options: ArchiveOptions,
}

impl<'key> UpdateArchiveBuilder<'key> {
    /// Create an archive builder with OTA defaults.
    #[must_use]
    pub const fn new(key: &'key SigningKey) -> Self {
        Self {
            key,
            options: ArchiveOptions {
                legacy_paths: false,
                block_size: OTA_BLOCK_SIZE,
            },
        }
    }

    /// Replace archive behavior options.
    #[must_use]
    pub const fn options(mut self, options: ArchiveOptions) -> Self {
        self.options = options;
        self
    }

    /// Build a complete intermediate archive from input files and directories.
    pub fn build<W: Write>(
        &self,
        inputs: &[ArchiveInput],
        mut writer: W,
    ) -> Result<ArchiveBuildReport> {
        if inputs.is_empty() {
            return Err(Error::InvalidField {
                field: "archive inputs",
                message: "at least one file or directory is required".to_owned(),
            });
        }
        let entries = collect_entries(inputs, self.options.legacy_paths)?;
        let mut spool = tempfile::tempfile()?;
        let mut report = ArchiveBuildReport::default();
        {
            let encoder = GzEncoder::new(&mut spool, Compression::default());
            let mut tar = Builder::new(encoder);
            tar.mode(tar::HeaderMode::Complete);
            tar.preserve_absolute(true);

            let mut regular_files = Vec::new();
            for entry in &entries {
                append_source_entry(&mut tar, entry)?;
                report.source_entries += 1;
                if entry.metadata.file_type().is_file() {
                    report.has_script |= is_script(&entry.archive_path);
                    regular_files.push(entry);
                }
            }

            let mut index = Vec::new();
            for entry in regular_files {
                let mut source = File::open(&entry.source)?;
                let md5 = md5_hex(&mut source)?;
                let signature = self.key.sign(&mut source)?;
                let signature_path = append_extension(&entry.archive_path, ".sig");
                append_generated(&mut tar, &signature_path, &signature)?;
                report.signed_files += 1;

                let file_type = if self.options.block_size == RECOVERY_BLOCK_SIZE
                    && is_kernel(&entry.archive_path)
                {
                    1
                } else if is_script(&entry.archive_path) {
                    129
                } else {
                    128
                };
                let display_name = entry
                    .source
                    .file_name()
                    .and_then(OsStr::to_str)
                    .unwrap_or("file");
                writeln!(
                    index,
                    "{file_type} {md5} {} {} {display_name}_ktool_file",
                    archive_path_text(&entry.archive_path),
                    entry.metadata.len() / self.options.block_size,
                )?;
            }

            let index_signature = self.key.sign(&mut Cursor::new(&index))?;
            append_generated(
                &mut tar,
                Path::new("update-filelist.dat.sig"),
                &index_signature,
            )?;
            append_generated(&mut tar, Path::new(INDEX_FILE_NAME), &index)?;
            tar.finish()?;
            let encoder = tar.into_inner()?;
            encoder.finish()?;
        }

        spool.seek(SeekFrom::Start(0))?;
        let verification_key = self.key.verification_key();
        let verification = UpdateArchiveVerifier::new(
            self.options.archive_kind(),
            VerificationPolicy::authentic(),
            Some(&verification_key),
            VerificationLimits::default(),
        )
        .verify(&mut spool)?;
        if !verification.is_valid() {
            return Err(Error::ArchiveMismatch {
                path: None,
                expected: "self-verified update archive".to_owned(),
                actual: format!("{:?}", verification.issues()),
            });
        }
        spool.seek(SeekFrom::Start(0))?;
        std::io::copy(&mut spool, &mut writer)?;
        Ok(report)
    }
}

/// Extract a gzip-compressed tar archive beneath a destination directory.
///
/// Extraction is completed inside a private sibling directory and committed with a same-filesystem
/// rename. An existing destination must be empty; non-empty directories are never merged or
/// overwritten.
pub fn extract_archive<R: Read>(reader: R, destination: &Path) -> Result<ArchiveExtractReport> {
    let file_name = destination.file_name().ok_or_else(|| Error::InvalidField {
        field: "extraction destination",
        message: "must name a directory below its parent".to_owned(),
    })?;
    let requested_parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(requested_parent)?;
    let parent = requested_parent.canonicalize()?;
    let destination = parent.join(file_name);
    ensure_empty_destination(&destination)?;

    let staging = tempfile::Builder::new()
        .prefix(".kindletool-extract-")
        .tempdir_in(&parent)?;
    let staged_destination = staging.path().join("payload");
    fs::create_dir(&staged_destination)?;
    let report = extract_archive_into(reader, &staged_destination)?;

    ensure_empty_destination(&destination)?;
    let removed_empty_destination = destination.try_exists()?;
    if removed_empty_destination {
        fs::remove_dir(&destination)?;
    }
    if let Err(error) = fs::rename(&staged_destination, &destination) {
        if removed_empty_destination {
            let _ = fs::create_dir(&destination);
        }
        return Err(error.into());
    }
    Ok(report)
}

fn extract_archive_into<R: Read>(reader: R, destination: &Path) -> Result<ArchiveExtractReport> {
    let destination = destination.canonicalize()?;
    let decoder = GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);

    let mut report = ArchiveExtractReport::default();
    for item in archive.entries()? {
        let mut entry = item?;
        let path = entry.path()?.into_owned();
        validate_archive_path(&path)?;
        validate_link_target(&entry, &path)?;
        ensure_no_symlink_ancestors(&destination, &path)?;
        if !entry.unpack_in(&destination)? {
            return Err(Error::UnsafeArchivePath(path));
        }
        report.entries += 1;
    }
    Ok(report)
}

fn ensure_empty_destination(destination: &Path) -> Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::InvalidField {
            field: "extraction destination",
            message: format!("{} is a symbolic link", destination.display()),
        }),
        Ok(metadata) if !metadata.is_dir() => Err(Error::InvalidField {
            field: "extraction destination",
            message: format!("{} is not a directory", destination.display()),
        }),
        Ok(_) if fs::read_dir(destination)?.next().transpose()?.is_some() => {
            Err(Error::InvalidField {
                field: "extraction destination",
                message: format!("{} is not empty", destination.display()),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug)]
struct SourceEntry {
    source: PathBuf,
    archive_path: PathBuf,
    metadata: Metadata,
}

fn collect_entries(inputs: &[ArchiveInput], legacy: bool) -> Result<Vec<SourceEntry>> {
    let mut output = Vec::new();
    for mapping in inputs {
        let input = &mapping.source;
        let root_metadata = fs::symlink_metadata(input)?;
        let archive_root = PathBuf::from(mapping.destination.as_str());
        if root_metadata.is_dir() {
            for item in WalkDir::new(input).follow_links(false).sort_by_file_name() {
                let item = item.map_err(|error| {
                    Error::Io(error.into_io_error().unwrap_or_else(|| {
                        std::io::Error::other("failed to traverse archive input")
                    }))
                })?;
                if legacy && item.depth() == 0 {
                    continue;
                }
                let source = item.path().to_path_buf();
                let metadata = fs::symlink_metadata(&source)?;
                if should_exclude(&source, &metadata) {
                    continue;
                }
                let relative = source
                    .strip_prefix(input)
                    .map_err(|_| Error::ArchiveMismatch {
                        path: Some(source.clone()),
                        expected: "path below archive input".to_owned(),
                        actual: "path outside archive input".to_owned(),
                    })?;
                let archive_path = if legacy {
                    relative.to_path_buf()
                } else {
                    archive_root.join(relative)
                };
                output.push(SourceEntry {
                    source,
                    archive_path,
                    metadata,
                });
            }
        } else if !should_exclude(input, &root_metadata) {
            output.push(SourceEntry {
                source: input.clone(),
                archive_path: archive_root,
                metadata: root_metadata,
            });
        }
    }
    Ok(output)
}

fn append_source_entry<W: Write>(tar: &mut Builder<W>, entry: &SourceEntry) -> Result<()> {
    let file_type = entry.metadata.file_type();
    let mut header = source_header(&entry.metadata, &entry.archive_path)?;
    if file_type.is_file() {
        let mut source = File::open(&entry.source)?;
        append_with_path(tar, &mut header, &entry.archive_path, &mut source)?;
    } else if file_type.is_dir() {
        append_with_path(tar, &mut header, &entry.archive_path, std::io::empty())?;
    } else if file_type.is_symlink() {
        let target = fs::read_link(&entry.source)?;
        header.set_link_name(&target)?;
        append_with_path(tar, &mut header, &entry.archive_path, std::io::empty())?;
    } else {
        return Err(Error::ArchiveMismatch {
            path: Some(entry.source.clone()),
            expected: "regular file, directory, or symlink".to_owned(),
            actual: "unsupported filesystem entry".to_owned(),
        });
    }
    Ok(())
}

fn append_generated<W: Write>(tar: &mut Builder<W>, path: &Path, data: &[u8]) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_uid(0);
    header.set_gid(0);
    header.set_username("root")?;
    header.set_groupname("root")?;
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_size(data.len() as u64);
    header.set_cksum();
    append_with_path(tar, &mut header, path, data)?;
    Ok(())
}

fn source_header(metadata: &Metadata, path: &Path) -> Result<Header> {
    let mut header = Header::new_gnu();
    header.set_uid(0);
    header.set_gid(0);
    header.set_username("root")?;
    header.set_groupname("root")?;
    header.set_mtime(
        metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs()),
    );
    let file_type = metadata.file_type();
    if file_type.is_file() {
        header.set_entry_type(EntryType::Regular);
        header.set_size(metadata.len());
        header.set_mode(if is_script(path) { 0o755 } else { 0o644 });
    } else if file_type.is_dir() {
        header.set_entry_type(EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
    } else if file_type.is_symlink() {
        header.set_entry_type(EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o644);
    }
    header.set_cksum();
    Ok(header)
}

fn append_with_path<W: Write, R: Read>(
    tar: &mut Builder<W>,
    header: &mut Header,
    path: &Path,
    data: R,
) -> Result<()> {
    validate_source_archive_path(path)?;
    tar.append_data(header, path, data)?;
    Ok(())
}

fn should_exclude(path: &Path, metadata: &Metadata) -> bool {
    if !metadata.file_type().is_file() {
        return false;
    }
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|value| value.eq_ignore_ascii_case("sig") || value.eq_ignore_ascii_case("dat"))
}

fn is_script(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|value| value.eq_ignore_ascii_case("sh") || value.eq_ignore_ascii_case("ffs"))
}

fn is_kernel(path: &Path) -> bool {
    archive_path_text(path).ends_with("uImage")
}

fn append_extension(path: &Path, extension: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(extension);
    PathBuf::from(value)
}

fn archive_path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn validate_archive_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Error::UnsafeArchivePath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_source_archive_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::UnsafeArchivePath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_link_target<R: Read>(entry: &tar::Entry<'_, R>, path: &Path) -> Result<()> {
    if !matches!(
        entry.header().entry_type(),
        EntryType::Symlink | EntryType::Link
    ) {
        return Ok(());
    }
    let Some(target) = entry.link_name()? else {
        return Err(Error::UnsafeArchivePath(path.to_path_buf()));
    };
    if target.is_absolute() {
        return Err(Error::UnsafeArchivePath(target.into_owned()));
    }
    let base = if entry.header().entry_type() == EntryType::Symlink {
        path.parent().unwrap_or_else(|| Path::new(""))
    } else {
        Path::new("")
    };
    normalize_link_target(base, &target)
        .ok_or_else(|| Error::UnsafeArchivePath(target.into_owned()))?;
    Ok(())
}

fn normalize_link_target(base: &Path, target: &Path) -> Option<PathBuf> {
    let mut components = base
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => None,
        })
        .collect::<Vec<_>>();
    for component in target.components() {
        match component {
            Component::Normal(value) => components.push(value.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                components.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(components.into_iter().collect())
}

fn ensure_no_symlink_ancestors(root: &Path, relative: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        current.push(name);
        if current == root.join(relative) {
            break;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::UnsafeArchivePath(relative.to_path_buf()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ArchiveInput, ArchiveOptions, UpdateArchiveBuilder, extract_archive, normalize_link_target,
    };
    use crate::ArchivePath;
    use crate::crypto::SigningKey;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use tar::{Builder, Header};

    #[test]
    fn archive_build_and_extract_round_trip() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("install.sh"), b"#!/bin/sh\n").unwrap();
        fs::write(source.path().join("asset.txt"), b"asset").unwrap();
        let key = SigningKey::default_jailbreak().unwrap();
        let mut archive = Vec::new();
        let report = UpdateArchiveBuilder::new(&key)
            .options(ArchiveOptions {
                legacy_paths: true,
                ..ArchiveOptions::default()
            })
            .build(
                &[ArchiveInput::from_source(source.path().to_path_buf()).unwrap()],
                &mut archive,
            )
            .unwrap();
        assert!(report.has_script);
        assert_eq!(report.signed_files, 2);

        let output = tempfile::tempdir().unwrap();
        extract_archive(Cursor::new(archive), output.path()).unwrap();
        assert_eq!(fs::read(output.path().join("asset.txt")).unwrap(), b"asset");
        assert!(output.path().join("asset.txt.sig").exists());
        assert!(output.path().join("update-filelist.dat").exists());
    }

    #[test]
    fn absolute_source_paths_use_the_explicit_safe_destination() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("asset.txt"), b"asset").unwrap();
        let key = SigningKey::default_jailbreak().unwrap();
        let mut archive = Vec::new();
        UpdateArchiveBuilder::new(&key)
            .build(
                &[ArchiveInput::from_source(source.path().to_path_buf()).unwrap()],
                &mut archive,
            )
            .unwrap();

        let decoder = flate2::read::GzDecoder::new(Cursor::new(archive));
        let mut archive = tar::Archive::new(decoder);
        let paths = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect::<Vec<_>>();
        let root = source.path().file_name().unwrap();
        assert!(paths.contains(&PathBuf::from(root).join("asset.txt")));
    }

    #[test]
    fn archive_options_reject_unknown_block_sizes() {
        assert!(ArchiveOptions::new(false, 1).is_err());
        assert!(ArchiveOptions::new(false, super::OTA_BLOCK_SIZE).is_ok());
        assert!(ArchiveOptions::new(false, super::RECOVERY_BLOCK_SIZE).is_ok());
    }

    #[test]
    fn builder_rejects_duplicate_archive_destinations_without_writing_output() {
        let source = tempfile::tempdir().unwrap();
        let first = source.path().join("first");
        let second = source.path().join("second");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let destination = ArchivePath::new("duplicate").unwrap();
        let inputs = [
            ArchiveInput::new(first, destination.clone()),
            ArchiveInput::new(second, destination),
        ];
        let key = SigningKey::default_jailbreak().unwrap();
        let mut output = Vec::new();

        assert!(
            UpdateArchiveBuilder::new(&key)
                .build(&inputs, &mut output)
                .is_err()
        );
        assert!(output.is_empty());
    }

    #[test]
    fn extraction_rejects_parent_paths() {
        let mut data = Vec::new();
        {
            let encoder = GzEncoder::new(&mut data, Compression::default());
            let mut builder = Builder::new(encoder);
            let mut header = Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            header.as_mut_bytes()[..7].copy_from_slice(b"../x\0\0\0");
            header.set_cksum();
            builder.append(&header, &b"x"[..]).unwrap();
            let encoder = builder.into_inner().unwrap();
            encoder.finish().unwrap();
        }
        let output = tempfile::tempdir().unwrap();
        assert!(extract_archive(Cursor::new(data), output.path()).is_err());
    }

    #[test]
    fn extraction_rejects_links_that_escape_the_destination() {
        let mut data = Vec::new();
        {
            let encoder = GzEncoder::new(&mut data, Compression::default());
            let mut builder = Builder::new(encoder);
            let mut header = Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_path("dir/link").unwrap();
            header.set_link_name("../../escape").unwrap();
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            let encoder = builder.into_inner().unwrap();
            encoder.finish().unwrap();
        }
        let output = tempfile::tempdir().unwrap();
        assert!(extract_archive(Cursor::new(data), output.path()).is_err());
    }

    #[test]
    fn parent_relative_symlink_is_allowed_when_it_stays_inside_the_root() {
        assert_eq!(
            normalize_link_target(Path::new("dir"), Path::new("../target")),
            Some(PathBuf::from("target"))
        );
        assert_eq!(
            normalize_link_target(Path::new("dir"), Path::new("../../escape")),
            None
        );
    }

    #[test]
    fn extraction_never_overwrites_a_nonempty_destination() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("output");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("sentinel"), b"keep me").unwrap();

        assert!(extract_archive(Cursor::new(Vec::new()), &destination).is_err());
        assert_eq!(fs::read(destination.join("sentinel")).unwrap(), b"keep me");
    }

    #[test]
    fn failed_extraction_does_not_leave_a_partial_destination() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("output");
        assert!(extract_archive(Cursor::new(b"not gzip"), &destination).is_err());
        assert!(!destination.exists());
    }
}
