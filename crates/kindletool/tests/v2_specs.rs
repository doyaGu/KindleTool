//! Public package-specification behavior.

use kindletool::{
    DeviceCode, FirmwareRange, FirmwareRevision, OtaV1Kind, OtaV1Spec, OtaV2Kind, OtaV2Spec,
};

#[test]
fn ota_v1_spec_rejects_revisions_that_do_not_fit_its_wire_format() {
    let range = FirmwareRange::new(
        FirmwareRevision::new(0),
        FirmwareRevision::new(u64::from(u32::MAX) + 1),
    )
    .unwrap();

    assert!(OtaV1Spec::new(OtaV1Kind::Ota, range, DeviceCode(0x201), 0).is_err());
}

#[test]
fn ota_v2_spec_rejects_metadata_that_cannot_be_encoded() {
    let range =
        FirmwareRange::new(FirmwareRevision::new(0), FirmwareRevision::new(u64::MAX)).unwrap();
    let oversized = vec![0_u8; usize::from(u16::MAX) + 1];

    assert!(
        OtaV2Spec::new(
            OtaV2Kind::Versionless,
            range,
            vec![DeviceCode(0x201)],
            0,
            vec![oversized],
        )
        .is_err()
    );
}
