//! Public v2 package verification behavior.

use kindletool::{
    ArchiveInput, ArchiveOptions, Certificate, DeviceCode, EncodeOptions, FirmwareRange,
    FirmwareRevision, OtaV1Kind, OtaV1Spec, Package, PackageEncoder, PackageSpec,
    PayloadIntegrityCheck, PayloadSource, PayloadView, SignatureCheck, SigningKey,
    TargetFieldCheck, UpdateArchiveBuilder, ValidationOutcome, VerificationContext,
    VerificationLimits, VerificationPolicy,
};
use std::fs;
use std::io::Cursor;

#[test]
fn authentic_package_verification_checks_every_layer_and_preserves_payload_position() {
    let key = SigningKey::default_jailbreak().unwrap();
    let archive = test_archive(&key);
    let archive_report = kindletool::archive::UpdateArchiveVerifier::new(
        kindletool::ArchiveKind::Ota,
        VerificationPolicy::authentic(),
        Some(&key.verification_key()),
        VerificationLimits::default(),
    )
    .verify(Cursor::new(&archive))
    .unwrap();
    assert!(archive_report.is_valid(), "{:?}", archive_report.issues());
    let spec = ota_v1_spec();
    let mut encoded = Vec::new();
    PackageEncoder::encode(
        &spec,
        Cursor::new(&archive),
        &mut encoded,
        EncodeOptions::signed(PayloadSource::Decoded, &key, Certificate::Developer).unwrap(),
    )
    .unwrap();

    let context = VerificationContext::new()
        .with_package_key(Certificate::Developer, key.verification_key())
        .with_archive_key(key.verification_key())
        .with_target_device(DeviceCode(0x201));
    let mut package = Package::parse(Cursor::new(encoded)).unwrap();
    let outcome = package
        .verify(&context, VerificationPolicy::authentic())
        .unwrap();

    assert!(outcome.is_accepted(), "{outcome:?}");
    assert!(matches!(
        outcome.report().signature(),
        SignatureCheck::Valid { .. }
    ));
    assert!(matches!(
        outcome.report().payload(),
        PayloadIntegrityCheck::Valid { .. }
    ));
    assert_eq!(outcome.report().target().device(), TargetFieldCheck::Match);
    let mut decoded = Vec::new();
    package
        .copy_payload(PayloadView::Decoded, &mut decoded)
        .unwrap();
    assert_eq!(decoded, archive);
}

#[test]
fn structural_allows_missing_package_key_but_authentic_rejects_it() {
    let key = SigningKey::default_jailbreak().unwrap();
    let archive = test_archive(&key);
    let mut encoded = Vec::new();
    PackageEncoder::encode(
        &ota_v1_spec(),
        Cursor::new(archive),
        &mut encoded,
        EncodeOptions::signed(PayloadSource::Decoded, &key, Certificate::Developer).unwrap(),
    )
    .unwrap();
    let context = VerificationContext::new().with_archive_key(key.verification_key());

    let mut structural = Package::parse(Cursor::new(encoded.clone())).unwrap();
    let structural_outcome = structural
        .verify(&context, VerificationPolicy::structural())
        .unwrap();
    assert!(structural_outcome.is_accepted(), "{structural_outcome:?}");
    let mut authentic = Package::parse(Cursor::new(encoded)).unwrap();
    let outcome = authentic
        .verify(&context, VerificationPolicy::authentic())
        .unwrap();
    assert!(matches!(outcome, ValidationOutcome::Rejected(_)));
    assert!(matches!(
        outcome.report().signature(),
        SignatureCheck::MissingKey { .. }
    ));
}

#[test]
fn tampered_payload_is_a_rejected_verdict_not_an_execution_error() {
    let key = SigningKey::default_jailbreak().unwrap();
    let archive = test_archive(&key);
    let mut encoded = Vec::new();
    PackageEncoder::encode(
        &ota_v1_spec(),
        Cursor::new(archive),
        &mut encoded,
        EncodeOptions::unsigned(PayloadSource::Decoded),
    )
    .unwrap();
    *encoded.last_mut().unwrap() ^= 1;
    let mut package = Package::parse(Cursor::new(encoded)).unwrap();
    let outcome = package
        .verify(
            &VerificationContext::new(),
            VerificationPolicy::structural(),
        )
        .unwrap();
    assert!(matches!(outcome, ValidationOutcome::Rejected(_)));
    assert!(matches!(
        outcome.report().payload(),
        PayloadIntegrityCheck::Invalid { .. }
    ));
}

fn test_archive(key: &SigningKey) -> Vec<u8> {
    let source = tempfile::tempdir().unwrap();
    let input = source.path().join("install.sh");
    fs::write(&input, b"#!/bin/sh\nexit 0\n").unwrap();
    let mut archive = Vec::new();
    UpdateArchiveBuilder::new(key)
        .options(ArchiveOptions::new(true, 64).unwrap())
        .build(
            &[ArchiveInput::from_source(source.path().to_path_buf()).unwrap()],
            &mut archive,
        )
        .unwrap();
    archive
}

fn ota_v1_spec() -> PackageSpec {
    PackageSpec::OtaV1(
        OtaV1Spec::new(
            OtaV1Kind::Ota,
            FirmwareRange::new(FirmwareRevision::new(1), FirmwareRevision::new(2)).unwrap(),
            DeviceCode(0x201),
            0,
        )
        .unwrap(),
    )
}
