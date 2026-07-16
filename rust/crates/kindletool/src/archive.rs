use crate::crypto::{SigningKey, md5_hex};
use crate::{Error, Result};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
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
    pub legacy_paths: bool,
    /// Block size written to `update-filelist.dat`.
    pub block_size: u64,
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
pub struct ArchiveBuildReport {
    /// Number of source entries added, excluding generated signatures and the index.
    pub source_entries: usize,
    /// Number of regular source files signed.
    pub signed_files: usize,
    /// Whether at least one `.sh` or `.ffs` script was found.
    pub has_script: bool,
}

/// Summary returned after extracting an update archive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArchiveExtractReport {
    /// Number of archive entries extracted.
    pub entries: usize,
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
    pub fn build<W: Write>(&self, inputs: &[PathBuf], writer: W) -> Result<ArchiveBuildReport> {
        if inputs.is_empty() {
            return Err(Error::InvalidField {
                field: "archive inputs",
                message: "at least one file or directory is required".to_owned(),
            });
        }
        if self.options.block_size == 0 {
            return Err(Error::InvalidField {
                field: "block size",
                message: "must be greater than zero".to_owned(),
            });
        }

        let entries = collect_entries(inputs, self.options.legacy_paths)?;
        let encoder = GzEncoder::new(writer, Compression::default());
        let mut tar = Builder::new(encoder);
        tar.mode(tar::HeaderMode::Complete);
        tar.preserve_absolute(true);

        let mut report = ArchiveBuildReport::default();
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

fn collect_entries(inputs: &[PathBuf], legacy: bool) -> Result<Vec<SourceEntry>> {
    let mut output = Vec::new();
    for input in inputs {
        let root_metadata = fs::symlink_metadata(input)?;
        let archive_root = safe_input_path(input)?;
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
                    .map_err(|_| Error::UnsupportedEntry(source.clone()))?;
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

fn safe_input_path(input: &Path) -> Result<PathBuf> {
    let path = input
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect::<PathBuf>();
    validate_source_archive_path(&path)?;
    Ok(path)
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
        return Err(Error::UnsupportedEntry(entry.source.clone()));
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
    use super::{ArchiveOptions, UpdateArchiveBuilder, extract_archive, normalize_link_target};
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
            .build(&[source.path().to_path_buf()], &mut archive)
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
    fn absolute_source_paths_preserve_the_legacy_archive_path() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("asset.txt"), b"asset").unwrap();
        let key = SigningKey::default_jailbreak().unwrap();
        let mut archive = Vec::new();
        UpdateArchiveBuilder::new(&key)
            .build(&[source.path().to_path_buf()], &mut archive)
            .unwrap();

        let decoder = flate2::read::GzDecoder::new(Cursor::new(archive));
        let mut archive = tar::Archive::new(decoder);
        let paths = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect::<Vec<_>>();
        assert!(paths.contains(&source.path().join("asset.txt")));
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
