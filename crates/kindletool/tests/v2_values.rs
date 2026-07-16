//! Public value-type behavior.

use kindletool::{ArchivePath, FirmwareRange, FirmwareRevision, Md5Digest, Sha256Digest};
use std::str::FromStr;

#[test]
fn md5_digest_accepts_exact_hex_and_has_canonical_display() {
    let digest = Md5Digest::from_str("D41D8CD98F00B204E9800998ECF8427E").unwrap();

    assert_eq!(digest.to_string(), "d41d8cd98f00b204e9800998ecf8427e");
    assert!(Md5Digest::from_str("d41d8cd98f00b204e9800998ecf8427").is_err());
    assert!(Md5Digest::from_str("g41d8cd98f00b204e9800998ecf8427e").is_err());
}

#[test]
fn sha256_digest_accepts_exact_hex_and_has_canonical_display() {
    let text = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
    let digest = Sha256Digest::from_str(text).unwrap();

    assert_eq!(digest.to_string(), text.to_ascii_lowercase());
    assert!(Sha256Digest::from_str(&text[..63]).is_err());
}

#[test]
fn firmware_range_rejects_an_inverted_interval() {
    let minimum = FirmwareRevision::new(20);
    let maximum = FirmwareRevision::new(10);

    assert!(FirmwareRange::new(minimum, maximum).is_err());
    assert!(
        FirmwareRange::new(maximum, minimum)
            .unwrap()
            .contains(FirmwareRevision::new(15))
    );
}

#[test]
fn archive_path_accepts_only_normalized_relative_utf8_paths() {
    assert_eq!(
        ArchivePath::new("bin/run.sh").unwrap().as_str(),
        "bin/run.sh"
    );
    for unsafe_path in [
        "",
        "/etc/passwd",
        "../escape",
        "bin/../escape",
        "bin\\run.sh",
    ] {
        assert!(
            ArchivePath::new(unsafe_path).is_err(),
            "accepted {unsafe_path:?}"
        );
    }
}
