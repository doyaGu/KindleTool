//! Public format-catalog behavior.

use kindletool::{
    ArchiveKind, Board, BundleMagic, DeviceCode, FirmwareRange, FirmwareRevision, OtaV1Kind,
    OtaV1Spec, OtaV2Kind, OtaV2Spec, PackageFormat, PackageSpec, Platform, RecoveryV1Spec,
};

#[test]
fn every_known_magic_has_one_consistent_format_profile() {
    let profiles = BundleMagic::known()
        .map(|(magic, _)| (magic, magic.profile()))
        .collect::<Vec<_>>();

    assert_eq!(profiles.len(), 11);
    assert_eq!(BundleMagic::Fc02.profile().format(), PackageFormat::OtaV1);
    assert_eq!(BundleMagic::Fd03.profile().format(), PackageFormat::OtaV1);
    assert_eq!(BundleMagic::Fc04.profile().format(), PackageFormat::OtaV2);
    assert_eq!(
        BundleMagic::Fb03.profile().archive_kind(),
        Some(ArchiveKind::Recovery)
    );
    assert_eq!(
        BundleMagic::Cb01.profile().format(),
        PackageFormat::Component
    );
    assert!(!BundleMagic::Cb01.profile().writable());
    assert!(!BundleMagic::Zip.profile().writable());
}

#[test]
fn specs_derive_default_envelopes_from_format_metadata() {
    let range = FirmwareRange::new(FirmwareRevision::new(0), FirmwareRevision::new(1)).unwrap();
    let ota_v1 =
        PackageSpec::OtaV1(OtaV1Spec::new(OtaV1Kind::Ota, range, DeviceCode(1), 0).unwrap());
    let ota_v2 =
        PackageSpec::OtaV2(OtaV2Spec::new(OtaV2Kind::Ota, range, vec![], 0, vec![]).unwrap());
    let recovery_revision2 = PackageSpec::RecoveryV1(RecoveryV1Spec::revision2(
        FirmwareRevision::new(1),
        0,
        0,
        0,
        Platform::from_raw(0),
        Board::from_raw(0),
    ));

    assert!(!ota_v1.default_envelope());
    assert!(ota_v2.default_envelope());
    assert!(recovery_revision2.default_envelope());
}
