//! Optional read-only verification of local, non-redistributable package corpora.

use kindletool::{ArchiveIssue, Package, VerificationContext, VerificationPolicy};
use std::fs::{self, File};

#[derive(Clone, Copy)]
enum ExpectedOutcome {
    Accepted,
    DigestMismatch,
}

#[test]
fn configured_packages_pass_structural_verification_without_mutating_sources() {
    let accepted = corpus_paths("KINDLETOOL_CORPUS");
    let digest_mismatches = corpus_paths("KINDLETOOL_CORPUS_DIGEST_MISMATCH");
    if accepted.is_empty() && digest_mismatches.is_empty() {
        eprintln!("KindleTool corpus variables are unset; skipping local corpus verification");
        return;
    }
    for source in accepted {
        verify_source(&source, ExpectedOutcome::Accepted);
    }
    for source in digest_mismatches {
        verify_source(&source, ExpectedOutcome::DigestMismatch);
    }
}

fn corpus_paths(variable: &str) -> Vec<std::path::PathBuf> {
    std::env::var_os(variable)
        .map(|paths| std::env::split_paths(&paths).collect())
        .unwrap_or_default()
}

fn verify_source(source: &std::path::Path, expected: ExpectedOutcome) {
    let before = fs::metadata(source).unwrap();
    assert!(before.is_file(), "{} is not a file", source.display());
    let temporary = tempfile::tempdir().unwrap();
    let copy = temporary.path().join(
        source
            .file_name()
            .expect("corpus package has a final path component"),
    );
    fs::copy(source, &copy).unwrap();

    let mut package = Package::parse(File::open(&copy).unwrap()).unwrap();
    let outcome = package
        .verify(
            &VerificationContext::new(),
            VerificationPolicy::structural(),
        )
        .unwrap();
    match expected {
        ExpectedOutcome::Accepted => {
            assert!(outcome.is_accepted(), "{}: {outcome:?}", source.display());
        }
        ExpectedOutcome::DigestMismatch => {
            assert!(!outcome.is_accepted(), "{} was accepted", source.display());
            let issues = outcome
                .report()
                .archive_report()
                .expect("digest mismatch belongs to an archive")
                .issues();
            assert!(
                !issues.is_empty(),
                "{} has no archive issue",
                source.display()
            );
            assert!(
                issues
                    .iter()
                    .all(|issue| matches!(issue, ArchiveIssue::DigestMismatch(_))),
                "{}: {issues:?}",
                source.display()
            );
        }
    }

    let after = fs::metadata(source).unwrap();
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
