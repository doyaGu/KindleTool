//! Optional read-only verification of local, non-redistributable package corpora.

use kindletool::{
    Package, PayloadView, UpdateArchiveVerifier, VerificationContext, VerificationLimits,
    VerificationPolicy,
};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom};

#[test]
fn configured_packages_pass_structural_verification_without_mutating_sources() {
    let Some(paths) = std::env::var_os("KINDLETOOL_CORPUS") else {
        eprintln!("KINDLETOOL_CORPUS is unset; skipping local corpus verification");
        return;
    };
    let paths = std::env::split_paths(&paths).collect::<Vec<_>>();
    assert!(!paths.is_empty(), "KINDLETOOL_CORPUS contains no paths");

    for source in paths {
        let before = fs::metadata(&source).unwrap();
        assert!(before.is_file(), "{} is not a file", source.display());
        let temporary = tempfile::tempdir().unwrap();
        let copy = temporary.path().join(
            source
                .file_name()
                .expect("corpus package has a final path component"),
        );
        fs::copy(&source, &copy).unwrap();

        let mut package = Package::parse(File::open(&copy).unwrap()).unwrap();
        let archive_kind = package.descriptor().archive_kind();
        let outcome = package
            .verify(
                &VerificationContext::new(),
                VerificationPolicy::structural(),
            )
            .unwrap();
        if !outcome.is_accepted() {
            let archive_issues = archive_kind.map(|kind| {
                let mut decoded = tempfile::tempfile().unwrap();
                package
                    .copy_payload(PayloadView::Decoded, &mut decoded)
                    .unwrap();
                decoded.seek(SeekFrom::Start(0)).unwrap();
                UpdateArchiveVerifier::new(
                    kind,
                    VerificationPolicy::structural(),
                    None,
                    VerificationLimits::default(),
                )
                .verify(decoded)
                .unwrap()
                .issues()
                .to_vec()
            });
            panic!(
                "{}: {:?}; archive issues: {:?}",
                source.display(),
                outcome.report(),
                archive_issues
            );
        }

        let after = fs::metadata(&source).unwrap();
        assert_eq!(
            after.len(),
            before.len(),
            "{} changed size",
            source.display()
        );
        assert_eq!(
            after.modified().unwrap(),
            before.modified().unwrap(),
            "{} changed modification time",
            source.display()
        );
        eprintln!("verified {}", source.display());
    }
}
