//! CB01 content and target verification through the public package API.

use kindletool::crypto::sha256_hex;
use kindletool::{
    ArchiveInput, ArchiveOptions, Board, DeviceCode, FirmwareRevision, MangleReader, Package,
    PayloadIntegrityCheck, Platform, SigningKey, TargetFieldCheck, UpdateArchiveBuilder,
    VerificationContext, VerificationPolicy,
};
use std::fs;
use std::io::Cursor;

const COMPONENT: &[u8] = b"component payload";

#[test]
fn structural_accepts_a_component_with_one_matching_content_file() {
    let archive = component_archive(&[("component.bin", COMPONENT)]);
    let encoded = component_package(&archive, &digest(COMPONENT), &[DeviceCode(0x201)]);
    let mut package = Package::parse(Cursor::new(encoded)).unwrap();

    let outcome = package
        .verify(
            &VerificationContext::new(),
            VerificationPolicy::structural(),
        )
        .unwrap();

    assert!(outcome.is_accepted(), "{outcome:?}");
    assert!(matches!(
        outcome.report().payload(),
        PayloadIntegrityCheck::ComponentValid { .. }
    ));
}

#[test]
fn structural_rejects_a_component_header_digest_mismatch() {
    let archive = component_archive(&[("component.bin", COMPONENT)]);
    let encoded = component_package(
        &archive,
        &digest(b"different content"),
        &[DeviceCode(0x201)],
    );
    let mut package = Package::parse(Cursor::new(encoded)).unwrap();

    let outcome = package
        .verify(
            &VerificationContext::new(),
            VerificationPolicy::structural(),
        )
        .unwrap();

    assert!(!outcome.is_accepted());
    assert!(matches!(
        outcome.report().payload(),
        PayloadIntegrityCheck::ComponentInvalid { .. }
    ));
}

#[test]
fn structural_rejects_an_ambiguous_component_archive() {
    let archive = component_archive(&[
        ("component.bin", COMPONENT),
        ("second.bin", b"second component"),
    ]);
    let encoded = component_package(&archive, &digest(COMPONENT), &[DeviceCode(0x201)]);
    let mut package = Package::parse(Cursor::new(encoded)).unwrap();

    let outcome = package
        .verify(
            &VerificationContext::new(),
            VerificationPolicy::structural(),
        )
        .unwrap();

    assert!(!outcome.is_accepted());
    assert!(matches!(
        outcome.report().payload(),
        PayloadIntegrityCheck::ComponentAmbiguous { candidates: 2 }
    ));
}

#[test]
fn component_targets_are_reported_independently() {
    let archive = component_archive(&[("component.bin", COMPONENT)]);
    let encoded = component_package(&archive, &digest(COMPONENT), &[DeviceCode(0x201)]);
    let context = VerificationContext::new()
        .with_target_device(DeviceCode(0x202))
        .with_target_firmware(FirmwareRevision::new(11))
        .with_target_platform(Platform::from_raw(13))
        .with_target_board(Board::from_raw(3));
    let mut package = Package::parse(Cursor::new(encoded)).unwrap();

    let outcome = package
        .verify(&context, VerificationPolicy::structural())
        .unwrap();

    assert!(!outcome.is_accepted());
    assert_eq!(
        outcome.report().target().device(),
        TargetFieldCheck::Mismatch
    );
    assert_eq!(
        outcome.report().target().firmware(),
        TargetFieldCheck::Mismatch
    );
    assert_eq!(
        outcome.report().target().platform(),
        TargetFieldCheck::Mismatch
    );
    assert_eq!(
        outcome.report().target().board(),
        TargetFieldCheck::NotSpecified
    );
}

fn component_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let source = tempfile::tempdir().unwrap();
    let inputs = files
        .iter()
        .map(|(name, data)| {
            let path = source.path().join(name);
            fs::write(&path, data).unwrap();
            ArchiveInput::from_source(path).unwrap()
        })
        .collect::<Vec<_>>();
    let key = SigningKey::default_jailbreak().unwrap();
    let mut archive = Vec::new();
    UpdateArchiveBuilder::new(&key)
        .options(ArchiveOptions::new(false, 64).unwrap())
        .build(&inputs, &mut archive)
        .unwrap();
    archive
}

fn component_package(archive: &[u8], sha256: &str, devices: &[DeviceCode]) -> Vec<u8> {
    let mut encoded =
        Vec::with_capacity(4 + kindletool::model::RECOVERY_HEADER_LEN + archive.len());
    encoded.extend_from_slice(b"CB01");
    let mut header = vec![0_u8; kindletool::model::RECOVERY_HEADER_LEN];
    header[0..8].copy_from_slice(&1_u64.to_le_bytes());
    header[8..16].copy_from_slice(&10_u64.to_le_bytes());
    header[16..80].copy_from_slice(sha256.as_bytes());
    header[80..84].copy_from_slice(&7_u32.to_le_bytes());
    header[84..88].copy_from_slice(&12_u32.to_le_bytes());
    header[88..92].copy_from_slice(&1_u32.to_le_bytes());
    header[92..96].copy_from_slice(&u32::try_from(devices.len()).unwrap().to_le_bytes());
    for (index, device) in devices.iter().enumerate() {
        let offset = 96 + index * 2;
        header[offset..offset + 2].copy_from_slice(&device.0.to_le_bytes());
    }
    encoded.extend_from_slice(&header);
    std::io::copy(&mut MangleReader::new(Cursor::new(archive)), &mut encoded).unwrap();
    encoded
}

fn digest(data: &[u8]) -> String {
    sha256_hex(&mut Cursor::new(data)).unwrap()
}
