//! Public v2 package lifecycle behavior.

use kindletool::{
    DeviceCode, EncodeOptions, FirmwareRange, FirmwareRevision, OtaV1Kind, OtaV1Spec, Package,
    PackageEncoder, PackageSpec, PayloadSource, PayloadView,
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
