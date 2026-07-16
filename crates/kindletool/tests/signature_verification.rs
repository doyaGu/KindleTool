//! Public SP01 signature verification behavior.

use kindletool::{
    BundleMagic, Certificate, DeviceCode, DeviceCompatibilityStatus, OtaV1Header, OtaV2Header,
    PackageReader, PackageSpec, PackageWriter, PayloadIntegrityStatus, SignatureStatus,
    SigningConfiguration, SigningKey, VerificationKey, VerificationOptions, WriteOptions,
};
use std::io::{Cursor, Write};

const TEST_PUBLIC_KEY: &str = r"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDs/rQuRUJoHxD1L/h5NFdHHC3
ZCwMiyDtTOSL8k2Hsz6okRuGpJxhCZmsXVGORFode+tNtg4ABaW8X4OKCYI47w7G
IXke2SRjRoWeQyppYHv3/o8M1KpgyS8CM5xoeXmBHKLf0fjhMYCm5ll1bSjmMAhX
CImoIdwPosQdbTy2xQIDAQAB
-----END PUBLIC KEY-----";

const TEST_PUBLIC_KEY_2048: &str = r"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhMmj9t0sQwp3v9gKr/Dv
VU/A03sfq/9CcXYlvetzeyURMKMImHp7Vjjta1xA5vySYeTYWjVKW72Uo43meblJ
qFGBgmuUIIZZ74c0Kto+Mlk661Tev41WVW1yyYWqU8ZKJl65DO7nsZx2emm7xwaO
eXrhxxOJ6VE/4AjpTwGvqPVCcKKhOb/tHvRyDmaf9YRq8jxFlaqMAyJ19k4/aoy6
8zkkSqhUSP55m4niko63zctAKs/GjpHrVQDhGo073BO6fYAfXVJ31y1cE0M02P8+
mV2FM9/nt7jAu0Dj8TA027omYGC+RfSQ5f2ikPCj41g2daRey3wCwvO+fvCb1g2s
wwIDAQAB
-----END PUBLIC KEY-----";

const TEST_PUBLIC_KEY_PKCS1: &str = r"-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMOz+tC5FQmgfEPUv+Hk0V0ccLdkLAyLIO1M5IvyTYezPqiRG4aknGEJ
maxdUY5EWh176022DgAFpbxfg4oJgjjvDsYheR7ZJGNGhZ5DKmlge/f+jwzUqmDJ
LwIznGh5eYEcot/R+OExgKbmWXVtKOYwCFcIiagh3A+ixB1tPLbFAgMBAAE=
-----END RSA PUBLIC KEY-----";

// Generated independently with:
// openssl dgst -sha256 -sign private.pem -out signature.bin inner.bin
const OPENSSL_SIGNATURE_HEX: &str = concat!(
    "6b9e8f26c578633b212089e73a04ae97a66a875da7bb2d9e50370d3cf5ee9f2c",
    "688780269640d00473199352f27512a090fef63452951dd60376bbab588da03c9",
    "daa4701586955c1d522d1c6dc9a991697013055d29dd3d232f69b280e3690636",
    "2db45ebd54e5321f144c6afea1f1ace68531ef5dc8027e29b8132c5581a1c9f",
);

#[test]
fn signed_sp01_package_verifies_with_its_public_key() {
    let signing_key = SigningKey::default_jailbreak().unwrap();
    let verification_key = signing_key.verification_key();
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::SignedUserdata,
            &mut Cursor::new(b"\x1f\x8b\x08\x00signed payload"),
            WriteOptions {
                fake_sign: false,
                signing: Some(SigningConfiguration {
                    key: &signing_key,
                    certificate: Certificate::Developer,
                }),
            },
        )
        .unwrap();

    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();
    let result = reader.verify_signature(Some(&verification_key)).unwrap();

    assert_eq!(result.status, SignatureStatus::Valid);
    assert_eq!(result.certificate, Some(Certificate::Developer));
}

#[test]
fn package_without_sp01_reports_unsigned() {
    let verification_key = VerificationKey::from_pem(TEST_PUBLIC_KEY).unwrap();
    let mut reader = PackageReader::new(Cursor::new(b"\x1f\x8b\x08\x00unsigned")).unwrap();

    let result = reader.verify_signature(Some(&verification_key)).unwrap();

    assert_eq!(result.status, SignatureStatus::Unsigned);
    assert_eq!(result.certificate, None);
}

#[test]
fn signed_sp01_package_without_a_public_key_reports_key_missing() {
    let signing_key = SigningKey::default_jailbreak().unwrap();
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::SignedUserdata,
            &mut Cursor::new(b"\x1f\x8b\x08\x00missing public key"),
            WriteOptions {
                fake_sign: false,
                signing: Some(SigningConfiguration {
                    key: &signing_key,
                    certificate: Certificate::Developer,
                }),
            },
        )
        .unwrap();
    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();

    let result = reader.verify_signature(None).unwrap();

    assert_eq!(result.status, SignatureStatus::KeyMissing);
    assert_eq!(result.certificate, Some(Certificate::Developer));
}

#[test]
fn signed_sp01_package_rejects_a_different_public_key() {
    let signing_key = SigningKey::default_jailbreak().unwrap();
    let wrong_key = VerificationKey::from_pem(TEST_PUBLIC_KEY).unwrap();
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::SignedUserdata,
            &mut Cursor::new(b"\x1f\x8b\x08\x00wrong public key"),
            WriteOptions {
                fake_sign: false,
                signing: Some(SigningConfiguration {
                    key: &signing_key,
                    certificate: Certificate::Developer,
                }),
            },
        )
        .unwrap();
    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();

    let result = reader.verify_signature(Some(&wrong_key)).unwrap();

    assert_eq!(result.status, SignatureStatus::Invalid);
}

#[test]
fn signature_header_and_payload_tampering_are_rejected() {
    let signing_key = SigningKey::default_jailbreak().unwrap();
    let verification_key = signing_key.verification_key();
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::SignedUserdata,
            &mut Cursor::new(b"\x1f\x8b\x08\x00tamper detection payload"),
            WriteOptions {
                fake_sign: false,
                signing: Some(SigningConfiguration {
                    key: &signing_key,
                    certificate: Certificate::Developer,
                }),
            },
        )
        .unwrap();

    let signature_offset = 4 + 60;
    let inner_header_offset = signature_offset + 128 + 3;
    let payload_offset = package.len() - 1;
    for (name, offset) in [
        ("signature", signature_offset),
        ("inner header", inner_header_offset),
        ("payload", payload_offset),
    ] {
        let mut tampered = package.clone();
        tampered[offset] ^= 1;
        let mut reader = PackageReader::new(Cursor::new(tampered)).unwrap();
        let result = reader.verify_signature(Some(&verification_key)).unwrap();
        assert_eq!(result.status, SignatureStatus::Invalid, "{name}");
    }
}

#[test]
fn reserved_sp01_header_bytes_are_outside_the_signature() {
    let signing_key = SigningKey::default_jailbreak().unwrap();
    let verification_key = signing_key.verification_key();
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::SignedUserdata,
            &mut Cursor::new(b"\x1f\x8b\x08\x00reserved header"),
            WriteOptions {
                fake_sign: false,
                signing: Some(SigningConfiguration {
                    key: &signing_key,
                    certificate: Certificate::Developer,
                }),
            },
        )
        .unwrap();
    package[4 + 4] ^= 1;
    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();

    let result = reader.verify_signature(Some(&verification_key)).unwrap();

    assert_eq!(result.status, SignatureStatus::Valid);
}

#[test]
fn openssl_golden_signature_verifies() {
    let inner = b"\x1f\x8b\x08\x00OpenSSL independent SP01 golden vector";
    let mut package = Vec::new();
    package.extend_from_slice(b"SP01");
    package.extend_from_slice(&[0_u8; 60]);
    package.extend_from_slice(&decode_hex(OPENSSL_SIGNATURE_HEX));
    package.extend_from_slice(inner);
    let verification_key = VerificationKey::from_pem(TEST_PUBLIC_KEY).unwrap();
    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();

    let result = reader.verify_signature(Some(&verification_key)).unwrap();

    assert_eq!(result.status, SignatureStatus::Valid);
}

#[test]
fn public_key_can_be_loaded_from_a_pem_file() {
    let mut pem = tempfile::NamedTempFile::new().unwrap();
    pem.write_all(TEST_PUBLIC_KEY.as_bytes()).unwrap();

    let key = VerificationKey::from_pem_file(pem.path()).unwrap();

    assert_eq!(key.size(), 128);
}

#[test]
fn pkcs1_public_key_is_accepted() {
    let key = VerificationKey::from_pem(TEST_PUBLIC_KEY_PKCS1).unwrap();

    assert_eq!(key.size(), 128);
}

#[test]
fn public_key_size_mismatch_is_distinct_from_an_invalid_signature() {
    let signing_key = SigningKey::default_jailbreak().unwrap();
    let verification_key = VerificationKey::from_pem(TEST_PUBLIC_KEY_2048).unwrap();
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::SignedUserdata,
            &mut Cursor::new(b"\x1f\x8b\x08\x00key size mismatch"),
            WriteOptions {
                fake_sign: false,
                signing: Some(SigningConfiguration {
                    key: &signing_key,
                    certificate: Certificate::Developer,
                }),
            },
        )
        .unwrap();
    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();

    let result = reader.verify_signature(Some(&verification_key)).unwrap();

    assert_eq!(result.status, SignatureStatus::KeyMismatch);
}

#[test]
fn ota_payload_matching_the_header_md5_reports_valid_integrity() {
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::OtaV1(OtaV1Header {
                magic: BundleMagic::Fc02,
                source_revision: 1,
                target_revision: 2,
                device: DeviceCode(0x201),
                optional: 0,
                md5: String::new(),
            }),
            &mut Cursor::new(b"payload integrity"),
            WriteOptions::default(),
        )
        .unwrap();
    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();

    let result = reader.verify_payload_integrity().unwrap();

    assert_eq!(result, PayloadIntegrityStatus::Valid);
}

#[test]
fn format_without_a_payload_digest_reports_not_available() {
    let mut reader = PackageReader::new(Cursor::new(b"\x1f\x8b\x08\x00userdata")).unwrap();

    let result = reader.verify_payload_integrity().unwrap();

    assert_eq!(result, PayloadIntegrityStatus::NotAvailable);
}

#[test]
fn ota_payload_tampering_reports_both_digests() {
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::OtaV1(OtaV1Header {
                magic: BundleMagic::Fc02,
                source_revision: 1,
                target_revision: 2,
                device: DeviceCode(0x201),
                optional: 0,
                md5: String::new(),
            }),
            &mut Cursor::new(b"tampered payload"),
            WriteOptions::default(),
        )
        .unwrap();
    let last = package.last_mut().unwrap();
    *last ^= 1;
    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();

    let result = reader.verify_payload_integrity().unwrap();

    let PayloadIntegrityStatus::Invalid { expected, actual } = result else {
        panic!("tampered payload unexpectedly passed integrity verification");
    };
    assert_eq!(expected.len(), 32);
    assert_eq!(actual.len(), 32);
    assert_ne!(expected, actual);
}

#[test]
fn package_verification_reports_signature_and_payload_integrity_together() {
    let signing_key = SigningKey::default_jailbreak().unwrap();
    let verification_key = signing_key.verification_key();
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::OtaV1(OtaV1Header {
                magic: BundleMagic::Fc02,
                source_revision: 1,
                target_revision: 2,
                device: DeviceCode(0x201),
                optional: 0,
                md5: String::new(),
            }),
            &mut Cursor::new(b"complete verification report"),
            WriteOptions {
                fake_sign: false,
                signing: Some(SigningConfiguration {
                    key: &signing_key,
                    certificate: Certificate::Developer,
                }),
            },
        )
        .unwrap();
    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();

    let mut options = VerificationOptions::default();
    options.signature_key = Some(&verification_key);
    options.target_device = Some(DeviceCode(0x201));
    let report = reader.verify(options).unwrap();

    assert_eq!(report.signature.status, SignatureStatus::Valid);
    assert_eq!(report.payload_integrity, PayloadIntegrityStatus::Valid);
    assert_eq!(
        report.device_compatibility,
        DeviceCompatibilityStatus::Compatible
    );
    let mut decoded = Vec::new();
    reader.copy_decoded_payload(&mut decoded, false).unwrap();
    assert_eq!(decoded, b"complete verification report");
}

#[test]
fn package_verification_distinguishes_mismatched_and_unspecified_devices() {
    let mut ota = Vec::new();
    PackageWriter::new(&mut ota)
        .write(
            &PackageSpec::OtaV1(OtaV1Header {
                magic: BundleMagic::Fc02,
                source_revision: 1,
                target_revision: 2,
                device: DeviceCode(0x201),
                optional: 0,
                md5: String::new(),
            }),
            &mut Cursor::new(b"device compatibility"),
            WriteOptions::default(),
        )
        .unwrap();
    let mut options = VerificationOptions::default();
    options.target_device = Some(DeviceCode(0x202));
    let mut ota_reader = PackageReader::new(Cursor::new(ota)).unwrap();
    let ota_report = ota_reader.verify(options).unwrap();

    assert_eq!(
        ota_report.device_compatibility,
        DeviceCompatibilityStatus::Incompatible
    );

    let mut userdata = PackageReader::new(Cursor::new(b"\x1f\x8b\x08\x00userdata")).unwrap();
    let userdata_report = userdata.verify(options).unwrap();
    assert_eq!(
        userdata_report.device_compatibility,
        DeviceCompatibilityStatus::NotSpecified
    );
}

#[test]
fn ota_v2_device_list_is_checked_without_consuming_the_payload() {
    let payload = b"OTA V2 device compatibility";
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::OtaV2(OtaV2Header {
                magic: BundleMagic::Fd04,
                source_revision: 1,
                target_revision: 2,
                devices: vec![DeviceCode(0x201), DeviceCode(0x202)],
                critical: 0,
                padding: 0,
                md5: String::new(),
                metadata: Vec::new(),
            }),
            &mut Cursor::new(payload),
            WriteOptions::default(),
        )
        .unwrap();
    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();
    let mut options = VerificationOptions::default();
    options.target_device = Some(DeviceCode(0x202));

    assert_eq!(
        reader.verify(options).unwrap().device_compatibility,
        DeviceCompatibilityStatus::Compatible
    );
    options.target_device = Some(DeviceCode(0x203));
    assert_eq!(
        reader.verify(options).unwrap().device_compatibility,
        DeviceCompatibilityStatus::Incompatible
    );
    let mut decoded = Vec::new();
    reader.copy_decoded_payload(&mut decoded, false).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn verification_after_payload_consumption_is_rejected_instead_of_reporting_invalid() {
    let signing_key = SigningKey::default_jailbreak().unwrap();
    let verification_key = signing_key.verification_key();
    let mut package = Vec::new();
    PackageWriter::new(&mut package)
        .write(
            &PackageSpec::SignedUserdata,
            &mut Cursor::new(b"\x1f\x8b\x08\x00consumed payload"),
            WriteOptions {
                fake_sign: false,
                signing: Some(SigningConfiguration {
                    key: &signing_key,
                    certificate: Certificate::Developer,
                }),
            },
        )
        .unwrap();
    let mut reader = PackageReader::new(Cursor::new(package)).unwrap();
    reader.copy_decoded_payload(Vec::new(), false).unwrap();

    let error = reader
        .verify_signature(Some(&verification_key))
        .unwrap_err();

    assert!(matches!(
        error,
        kindletool::Error::InvalidField {
            field: "payload position",
            ..
        }
    ));
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}
