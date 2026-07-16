#![no_main]

use kindletool::{
    Board, DeviceCode, EncodeOptions, FirmwareRange, FirmwareRevision, OtaV1Kind, OtaV1Spec,
    OtaV2Kind, OtaV2Spec, Package, PackageEncoder, PackageSpec, PayloadSource, PayloadView,
    Platform, RecoveryV1Kind, RecoveryV1Spec, RecoveryV2Spec, UserdataSpec,
};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

const MAX_PAYLOAD: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or_default();
    let payload = &data[usize::from(!data.is_empty())..data.len().min(MAX_PAYLOAD)];
    let (spec, clear_payload) = package_case(selector, payload);
    let mut encoded = Vec::new();
    if PackageEncoder::encode(
        &spec,
        Cursor::new(&clear_payload),
        &mut encoded,
        EncodeOptions::unsigned(PayloadSource::Decoded),
    )
    .is_err()
    {
        return;
    }
    let Ok(package) = Package::parse(Cursor::new(encoded)) else {
        panic!("encoder output must parse");
    };
    let mut decoded = Vec::new();
    package
        .copy_payload(PayloadView::Decoded, &mut decoded)
        .unwrap();
    assert_eq!(decoded, clear_payload);
});

fn package_case(selector: u8, payload: &[u8]) -> (PackageSpec, Vec<u8>) {
    let revision32 = FirmwareRange::new(
        FirmwareRevision::new(0),
        FirmwareRevision::new(u32::MAX.into()),
    )
    .unwrap();
    let revision64 =
        FirmwareRange::new(FirmwareRevision::new(0), FirmwareRevision::new(u64::MAX)).unwrap();
    let device = DeviceCode(u16::from(selector));
    match selector % 6 {
        0 => (
            PackageSpec::OtaV1(
                OtaV1Spec::new(OtaV1Kind::Ota, revision32, device, selector).unwrap(),
            ),
            payload.to_vec(),
        ),
        1 => (
            PackageSpec::OtaV2(
                OtaV2Spec::new(
                    OtaV2Kind::Versionless,
                    revision64,
                    vec![device],
                    selector,
                    vec![payload.iter().copied().take(255).collect()],
                )
                .unwrap(),
            ),
            payload.to_vec(),
        ),
        2 => (
            PackageSpec::RecoveryV1(RecoveryV1Spec::legacy(
                RecoveryV1Kind::Fb01,
                selector.into(),
                0,
                0,
                device.0.into(),
            )),
            payload.to_vec(),
        ),
        3 => (
            PackageSpec::RecoveryV1(RecoveryV1Spec::revision2(
                FirmwareRevision::new(selector.into()),
                0,
                0,
                0,
                Platform::from_raw(selector.into()),
                Board::from_raw(selector.into()),
            )),
            payload.to_vec(),
        ),
        4 => (
            PackageSpec::RecoveryV2(
                RecoveryV2Spec::new(
                    FirmwareRevision::new(selector.into()),
                    0,
                    0,
                    0,
                    Platform::from_raw(selector.into()),
                    2,
                    Board::from_raw(selector.into()),
                    vec![device],
                )
                .unwrap(),
            ),
            payload.to_vec(),
        ),
        _ => {
            let mut archive = vec![0x1f, 0x8b, 0x08, 0x00];
            archive.extend_from_slice(payload);
            (PackageSpec::Userdata(UserdataSpec), archive)
        }
    }
}
