//! Public v2 package lifecycle behavior.

use kindletool::{
    DeviceCode, EncodeOptions, Error, FirmwareRange, FirmwareRevision, OtaV1Kind, OtaV1Spec,
    Package, PackageEncoder, PackageSpec, PayloadSource, PayloadView, RecoveryV1Kind,
    RecoveryV1Spec,
};
use std::io::Cursor;

#[test]
fn package_encoder_and_consuming_payload_view_round_trip() {
    let spec = PackageSpec::OtaV1(
        OtaV1Spec::new(
            OtaV1Kind::Versionless,
            FirmwareRange::new(FirmwareRevision::new(1), FirmwareRevision::new(2)).unwrap(),
            DeviceCode(0x201),
            7,
        )
        .unwrap(),
    );
    let payload = b"v2 payload";
    let mut encoded = Vec::new();

    let report = PackageEncoder::encode(
        &spec,
        Cursor::new(payload),
        &mut encoded,
        EncodeOptions::unsigned(PayloadSource::Decoded),
    )
    .unwrap();
    assert_eq!(report.payload_bytes(), payload.len() as u64);

    let package = Package::parse(Cursor::new(encoded)).unwrap();
    assert_eq!(package.descriptor().magic().to_string(), "FD03");
    let mut decoded = Vec::new();
    package
        .copy_payload(PayloadView::Decoded, &mut decoded)
        .unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn component_parser_rejects_an_inverted_firmware_range() {
    let mut encoded = vec![0_u8; 4 + kindletool::model::RECOVERY_HEADER_LEN];
    encoded[..4].copy_from_slice(b"CB01");
    encoded[4..12].copy_from_slice(&2_u64.to_le_bytes());
    encoded[12..20].copy_from_slice(&1_u64.to_le_bytes());
    encoded[20..84].fill(b'0');

    let Err(error) = Package::parse(Cursor::new(encoded)) else {
        panic!("inverted range must be rejected");
    };
    assert!(matches!(
        error,
        Error::InvalidField {
            field: "firmware range",
            ..
        }
    ));
}

#[test]
fn truncated_headers_report_the_exact_available_byte_count() {
    let mut encoded = b"FC02".to_vec();
    encoded.extend_from_slice(&[0; 3]);

    let Err(error) = Package::parse(Cursor::new(encoded)) else {
        panic!("truncated header must be rejected");
    };

    assert!(matches!(
        error,
        Error::Truncated {
            context: "OTA V1 header",
            needed: kindletool::model::OTA_V1_HEADER_LEN,
            remaining: 3,
        }
    ));
}

#[test]
fn legacy_recovery_exposes_its_target_device() {
    let target = DeviceCode(0x201);
    let spec = PackageSpec::RecoveryV1(RecoveryV1Spec::legacy(
        RecoveryV1Kind::Fb01,
        0,
        0,
        0,
        u32::from(target.0),
    ));
    let mut encoded = Vec::new();
    PackageEncoder::encode(
        &spec,
        Cursor::new([]),
        &mut encoded,
        EncodeOptions::unsigned(PayloadSource::Decoded),
    )
    .unwrap();

    let package = Package::parse(Cursor::new(encoded)).unwrap();
    assert_eq!(package.descriptor().target_devices(), &[target]);
}
