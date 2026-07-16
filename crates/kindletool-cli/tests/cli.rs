//! End-to-end tests for the v2 command line and its safety guarantees.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn kindletool() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kindletool"))
}

fn run(current_dir: &Path, arguments: &[&str]) -> Output {
    Command::new(kindletool())
        .current_dir(current_dir)
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn codec_round_trip_uses_explicit_subcommands() {
    let temporary = tempfile::tempdir().unwrap();
    let bytes = (0_u8..=255).cycle().take(4097).collect::<Vec<_>>();
    fs::write(temporary.path().join("input.bin"), &bytes).unwrap();
    assert!(
        run(
            temporary.path(),
            &["codec", "mangle", "input.bin", "--output", "encoded.bin"]
        )
        .status
        .success()
    );
    assert!(
        run(
            temporary.path(),
            &[
                "codec",
                "demangle",
                "encoded.bin",
                "--output",
                "decoded.bin"
            ]
        )
        .status
        .success()
    );
    assert_eq!(
        fs::read(temporary.path().join("decoded.bin")).unwrap(),
        bytes
    );
    assert_eq!(
        run(temporary.path(), &["md", "input.bin"]).status.code(),
        Some(2)
    );
}

#[test]
fn create_verify_inspect_export_and_extract_form_one_verified_flow() {
    let temporary = tempfile::tempdir().unwrap();
    fs::create_dir(temporary.path().join("payload")).unwrap();
    fs::write(
        temporary.path().join("payload/install.sh"),
        b"#!/bin/sh\nexit 0\n",
    )
    .unwrap();
    fs::write(temporary.path().join("payload/asset.txt"), b"asset").unwrap();

    let create = run(
        temporary.path(),
        &[
            "create",
            "ota-v2",
            "--kind",
            "versionless",
            "--source-revision",
            "0",
            "--target-revision",
            "18446744073709551615",
            "--device",
            "0x201",
            "--output",
            "Update_fixture.bin",
            "payload",
        ],
    );
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );

    let inspect = run(
        temporary.path(),
        &["inspect", "Update_fixture.bin", "--format", "json"],
    );
    assert!(inspect.status.success());
    let document: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["command"], "inspect");
    assert_eq!(document["package"]["magic"], "FD04");

    let verify = run(temporary.path(), &["verify", "Update_fixture.bin"]);
    assert!(
        verify.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("Status: Accepted"));

    assert!(
        run(
            temporary.path(),
            &[
                "export",
                "signature",
                "Update_fixture.bin",
                "--output",
                "signature.bin"
            ]
        )
        .status
        .success()
    );
    assert_eq!(
        fs::metadata(temporary.path().join("signature.bin"))
            .unwrap()
            .len(),
        128
    );
    assert!(
        run(
            temporary.path(),
            &[
                "export",
                "payload",
                "--view",
                "decoded",
                "Update_fixture.bin",
                "--output",
                "payload.tar.gz"
            ]
        )
        .status
        .success()
    );

    let extract = run(
        temporary.path(),
        &["extract", "Update_fixture.bin", "extracted"],
    );
    assert!(
        extract.status.success(),
        "{}",
        String::from_utf8_lossy(&extract.stderr)
    );
    assert_eq!(
        fs::read(temporary.path().join("extracted/payload/asset.txt")).unwrap(),
        b"asset"
    );
    assert!(temporary.path().join("Update_fixture.bin").exists());
}

#[test]
fn rejected_verification_returns_one_and_never_changes_source() {
    let temporary = tempfile::tempdir().unwrap();
    fs::create_dir(temporary.path().join("payload")).unwrap();
    fs::write(temporary.path().join("payload/file.txt"), b"content").unwrap();
    assert!(
        run(
            temporary.path(),
            &[
                "create",
                "ota-v1",
                "--source-revision",
                "1",
                "--target-revision",
                "2",
                "--device",
                "0x201",
                "--output",
                "Update.bin",
                "payload",
            ]
        )
        .status
        .success()
    );
    let path = temporary.path().join("Update.bin");
    let original = fs::read(&path).unwrap();
    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(&path, &tampered).unwrap();

    let verify = run(
        temporary.path(),
        &["verify", "Update.bin", "--policy", "structural"],
    );
    assert_eq!(verify.status.code(), Some(1));
    assert_eq!(fs::read(path).unwrap(), tampered);
    assert!(!temporary.path().join("extracted").exists());
}

#[test]
fn stdin_is_spooled_through_the_same_inspector() {
    let temporary = tempfile::tempdir().unwrap();
    let mut child = Command::new(kindletool())
        .current_dir(temporary.path())
        .args(["inspect", "-", "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"\x1f\x8b\x08\x00")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["package"]["magic"], "GZIP");
}
