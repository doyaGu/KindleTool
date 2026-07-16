//! Public format-catalog behavior.

use kindletool::{ArchiveKind, BundleMagic, PackageFormat};

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
