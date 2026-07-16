//! Adversarial update-archive verification through the public API.

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use kindletool::{
    ArchiveInput, ArchiveIssue, ArchiveKind, ArchiveOptions, SafeExtractionOutcome, SafeExtractor,
    SigningKey, UpdateArchiveBuilder, UpdateArchiveVerifier, VerificationLimits,
    VerificationPolicy,
};
use std::fs;
use std::io::{Cursor, Read};
use tar::{Builder, Header};

const INDEX: &str = "update-filelist.dat";
const RECOVERY_INDEX: &str = "update-payload.dat";

#[derive(Clone)]
struct StoredEntry {
    path: String,
    data: Vec<u8>,
}

#[test]
fn structural_rejects_a_manifest_digest_mismatch() {
    let key = SigningKey::default_jailbreak().unwrap();
    let archive = valid_archive(&key);
    let archive = rewrite_manifest(&archive, |manifest| {
        manifest.replacen(
            manifest.split_whitespace().nth(1).unwrap(),
            "00000000000000000000000000000000",
            1,
        )
    });

    let report = structural_verifier().verify(Cursor::new(archive)).unwrap();

    assert!(!report.is_valid());
    assert!(
        report.issues().iter().any(
            |issue| matches!(issue, ArchiveIssue::DigestMismatch(path) if path == "payload.bin")
        ),
        "{:?}",
        report.issues()
    );
}

#[test]
fn structural_rejects_a_manifest_block_count_mismatch() {
    let key = SigningKey::default_jailbreak().unwrap();
    let archive = valid_archive(&key);
    let archive = rewrite_manifest(&archive, |manifest| {
        let mut fields = manifest.split_whitespace().collect::<Vec<_>>();
        let block_index = fields.len() - 2;
        fields[block_index] = "1";
        format!("{}\n", fields.join(" "))
    });

    let report = structural_verifier().verify(Cursor::new(archive)).unwrap();

    assert!(!report.is_valid());
    assert!(report.issues().iter().any(
        |issue| matches!(issue, ArchiveIssue::ManifestMismatch(message) if message == "block count for payload.bin")
    ));
}

#[test]
fn structural_rejects_a_missing_manifest() {
    let key = SigningKey::default_jailbreak().unwrap();
    let mut entries = read_entries(&valid_archive(&key));
    entries.retain(|entry| entry.path != INDEX);

    let report = structural_verifier()
        .verify(Cursor::new(write_entries(&entries)))
        .unwrap();

    assert!(!report.is_valid());
    assert!(
        report
            .issues()
            .iter()
            .any(|issue| matches!(issue, ArchiveIssue::MissingEntry(path) if path == INDEX))
    );
}

#[test]
fn structural_rejects_a_missing_per_file_signature() {
    let key = SigningKey::default_jailbreak().unwrap();
    let mut entries = read_entries(&valid_archive(&key));
    entries.retain(|entry| entry.path != "payload.bin.sig");

    let report = structural_verifier()
        .verify(Cursor::new(write_entries(&entries)))
        .unwrap();

    assert!(!report.is_valid());
    assert!(report.issues().iter().any(
        |issue| matches!(issue, ArchiveIssue::MissingEntry(path) if path == "payload.bin.sig")
    ));
}

#[test]
fn structural_rejects_an_unlisted_regular_file() {
    let key = SigningKey::default_jailbreak().unwrap();
    let mut entries = read_entries(&valid_archive(&key));
    entries.push(StoredEntry {
        path: "unlisted.bin".to_owned(),
        data: b"unlisted".to_vec(),
    });

    let report = structural_verifier()
        .verify(Cursor::new(write_entries(&entries)))
        .unwrap();

    assert!(!report.is_valid());
    assert!(report.issues().iter().any(
        |issue| matches!(issue, ArchiveIssue::ManifestMismatch(message) if message == "unlisted file unlisted.bin")
    ));
}

#[test]
fn structural_rejects_an_orphan_signature() {
    let key = SigningKey::default_jailbreak().unwrap();
    let mut entries = read_entries(&valid_archive(&key));
    entries.push(StoredEntry {
        path: "orphan.bin.sig".to_owned(),
        data: vec![0; key.size()],
    });

    let report = structural_verifier()
        .verify(Cursor::new(write_entries(&entries)))
        .unwrap();

    assert!(!report.is_valid());
    assert!(report.issues().iter().any(
        |issue| matches!(issue, ArchiveIssue::ManifestMismatch(message) if message == "orphan signature orphan.bin.sig")
    ));
}

#[test]
fn structural_rejects_a_duplicate_archive_path() {
    let key = SigningKey::default_jailbreak().unwrap();
    let mut entries = read_entries(&valid_archive(&key));
    let duplicate = entries
        .iter()
        .find(|entry| entry.path == "payload.bin")
        .unwrap()
        .clone();
    entries.push(duplicate);

    let report = structural_verifier()
        .verify(Cursor::new(write_entries(&entries)))
        .unwrap();

    assert!(!report.is_valid());
    assert!(report.issues().iter().any(
        |issue| matches!(issue, ArchiveIssue::UnsafePath(message) if message == "duplicate path payload.bin")
    ));
}

#[test]
fn authentic_rejects_tampered_index_and_file_signatures() {
    let key = SigningKey::default_jailbreak().unwrap();
    let verification_key = key.verification_key();
    for (signature_path, signed_path) in [
        ("payload.bin.sig", "payload.bin"),
        ("update-filelist.dat.sig", INDEX),
    ] {
        let mut entries = read_entries(&valid_archive(&key));
        let signature = entries
            .iter_mut()
            .find(|entry| entry.path == signature_path)
            .unwrap();
        signature.data[0] ^= 0xff;
        let verifier = UpdateArchiveVerifier::new(
            ArchiveKind::Ota,
            VerificationPolicy::authentic(),
            Some(&verification_key),
            VerificationLimits::default(),
        );

        let report = verifier
            .verify(Cursor::new(write_entries(&entries)))
            .unwrap();

        assert!(!report.is_valid());
        assert!(report.issues().iter().any(
            |issue| matches!(issue, ArchiveIssue::SignatureMismatch(path) if path == signed_path)
        ));
    }
}

#[test]
fn authentic_rejects_an_archive_without_a_verification_key() {
    let key = SigningKey::default_jailbreak().unwrap();
    let verifier = UpdateArchiveVerifier::new(
        ArchiveKind::Ota,
        VerificationPolicy::authentic(),
        None,
        VerificationLimits::default(),
    );

    let report = verifier.verify(Cursor::new(valid_archive(&key))).unwrap();

    assert!(!report.is_valid());
    assert!(report.issues().iter().any(
        |issue| matches!(issue, ArchiveIssue::SignatureMismatch(message) if message == "missing key for payload.bin")
    ));
    assert!(report.issues().iter().any(
        |issue| matches!(issue, ArchiveIssue::SignatureMismatch(message) if message == "missing key for update-filelist.dat")
    ));
}

#[test]
fn verification_limits_bound_entries_content_paths_and_manifest_bytes() {
    let key = SigningKey::default_jailbreak().unwrap();
    let archive = valid_archive(&key);
    let cases = [
        (
            VerificationLimits::new(u64::MAX, 1, usize::MAX, usize::MAX).unwrap(),
            "archive entries",
        ),
        (
            VerificationLimits::new(1, usize::MAX, usize::MAX, usize::MAX).unwrap(),
            "uncompressed bytes",
        ),
        (
            VerificationLimits::new(u64::MAX, usize::MAX, usize::MAX, 1).unwrap(),
            "manifest bytes",
        ),
    ];
    for (limits, expected) in cases {
        let verifier = UpdateArchiveVerifier::new(
            ArchiveKind::Ota,
            VerificationPolicy::structural(),
            None,
            limits,
        );
        let report = verifier.verify(Cursor::new(&archive)).unwrap();
        assert!(
            report.issues().iter().any(
                |issue| matches!(issue, ArchiveIssue::LimitExceeded(name) if *name == expected)
            )
        );
    }

    let verifier = UpdateArchiveVerifier::new(
        ArchiveKind::Ota,
        VerificationPolicy::structural(),
        None,
        VerificationLimits::new(u64::MAX, usize::MAX, 4, usize::MAX).unwrap(),
    );
    let report = verifier.verify(Cursor::new(archive)).unwrap();
    assert!(
        report
            .issues()
            .iter()
            .any(|issue| matches!(issue, ArchiveIssue::UnsafePath(_)))
    );
}

#[test]
fn structural_rejects_a_link_that_escapes_the_archive_root() {
    let key = SigningKey::default_jailbreak().unwrap();
    let entries = read_entries(&valid_archive(&key));
    let archive = write_entries_with(&entries, |archive| {
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_path("dir/link").unwrap();
        header.set_link_name("../../escape").unwrap();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        archive.append(&header, std::io::empty()).unwrap();
    });

    let report = structural_verifier().verify(Cursor::new(archive)).unwrap();

    assert!(!report.is_valid());
    assert!(
        report
            .issues()
            .iter()
            .any(|issue| matches!(issue, ArchiveIssue::UnsafePath(path) if path == "dir/link"))
    );
}

#[test]
fn structural_rejects_an_unsupported_archive_entry_type() {
    let key = SigningKey::default_jailbreak().unwrap();
    let entries = read_entries(&valid_archive(&key));
    let archive = write_entries_with(&entries, |archive| {
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char);
        header.set_path("device").unwrap();
        header.set_size(0);
        header.set_mode(0o600);
        header.set_cksum();
        archive.append(&header, std::io::empty()).unwrap();
    });

    let report = structural_verifier().verify(Cursor::new(archive)).unwrap();

    assert!(!report.is_valid());
    assert!(
        report
            .issues()
            .iter()
            .any(|issue| matches!(issue, ArchiveIssue::UnsupportedEntry(path) if path == "device"))
    );
}

#[test]
fn safe_extractor_leaves_no_destination_when_verification_rejects() {
    let key = SigningKey::default_jailbreak().unwrap();
    let archive = rewrite_manifest(&valid_archive(&key), |manifest| {
        manifest.replacen(
            manifest.split_whitespace().nth(1).unwrap(),
            "00000000000000000000000000000000",
            1,
        )
    });
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("output");
    let extractor = SafeExtractor::new(
        ArchiveKind::Ota,
        VerificationPolicy::structural(),
        None,
        VerificationLimits::default(),
    );

    let outcome = extractor
        .extract(Cursor::new(archive), &destination)
        .unwrap();

    assert!(matches!(outcome, SafeExtractionOutcome::Rejected(_)));
    assert!(!destination.exists());
}

#[test]
fn recovery_accepts_the_modern_update_payload_manifest() {
    let key = SigningKey::default_jailbreak().unwrap();
    let mut entries = read_entries(&valid_archive(&key));
    for entry in &mut entries {
        if entry.path == INDEX {
            entry.path = RECOVERY_INDEX.to_owned();
        } else if entry.path == format!("{INDEX}.sig") {
            entry.path = format!("{RECOVERY_INDEX}.sig");
        }
    }
    let verifier = UpdateArchiveVerifier::new(
        ArchiveKind::Recovery,
        VerificationPolicy::structural(),
        None,
        VerificationLimits::default(),
    );

    let report = verifier
        .verify(Cursor::new(write_entries(&entries)))
        .unwrap();

    assert!(report.is_valid(), "{:?}", report.issues());
}

#[test]
fn recovery_rejects_multiple_manifest_conventions_in_one_archive() {
    let key = SigningKey::default_jailbreak().unwrap();
    let mut entries = read_entries(&valid_archive(&key));
    let mut modern = entries
        .iter()
        .filter(|entry| entry.path == INDEX || entry.path == format!("{INDEX}.sig"))
        .cloned()
        .collect::<Vec<_>>();
    for entry in &mut modern {
        entry.path = entry.path.replacen(INDEX, RECOVERY_INDEX, 1);
    }
    entries.extend(modern);
    let verifier = UpdateArchiveVerifier::new(
        ArchiveKind::Recovery,
        VerificationPolicy::structural(),
        None,
        VerificationLimits::default(),
    );

    let report = verifier
        .verify(Cursor::new(write_entries(&entries)))
        .unwrap();

    assert!(!report.is_valid());
    assert!(report.issues().iter().any(
        |issue| matches!(issue, ArchiveIssue::ManifestMismatch(message) if message.starts_with("multiple manifests:"))
    ));
}

fn valid_archive(key: &SigningKey) -> Vec<u8> {
    let source = tempfile::tempdir().unwrap();
    let input = source.path().join("payload.bin");
    fs::write(&input, b"payload contents").unwrap();
    let mut archive = Vec::new();
    UpdateArchiveBuilder::new(key)
        .options(ArchiveOptions::new(false, 64).unwrap())
        .build(&[ArchiveInput::from_source(input).unwrap()], &mut archive)
        .unwrap();
    archive
}

fn structural_verifier() -> UpdateArchiveVerifier<'static> {
    UpdateArchiveVerifier::new(
        ArchiveKind::Ota,
        VerificationPolicy::structural(),
        None,
        VerificationLimits::default(),
    )
}

fn rewrite_manifest(archive: &[u8], rewrite: impl FnOnce(&str) -> String) -> Vec<u8> {
    let mut entries = read_entries(archive);
    let manifest = entries
        .iter_mut()
        .find(|entry| entry.path == INDEX)
        .expect("valid fixture contains a manifest");
    let text = std::str::from_utf8(&manifest.data).unwrap();
    manifest.data = rewrite(text).into_bytes();
    write_entries(&entries)
}

fn read_entries(archive: &[u8]) -> Vec<StoredEntry> {
    let decoder = GzDecoder::new(Cursor::new(archive));
    let mut archive = tar::Archive::new(decoder);
    archive
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            assert!(entry.header().entry_type().is_file());
            let path = entry.path().unwrap().to_string_lossy().replace('\\', "/");
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            StoredEntry { path, data }
        })
        .collect()
}

fn write_entries(entries: &[StoredEntry]) -> Vec<u8> {
    write_entries_with(entries, |_| {})
}

fn write_entries_with(
    entries: &[StoredEntry],
    append: impl FnOnce(&mut Builder<GzEncoder<&mut Vec<u8>>>),
) -> Vec<u8> {
    let mut output = Vec::new();
    let encoder = GzEncoder::new(&mut output, Compression::default());
    let mut archive = Builder::new(encoder);
    for entry in entries {
        let mut header = Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_size(entry.data.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, &entry.path, Cursor::new(&entry.data))
            .unwrap();
    }
    append(&mut archive);
    archive.finish().unwrap();
    let encoder = archive.into_inner().unwrap();
    encoder.finish().unwrap();
    output
}
