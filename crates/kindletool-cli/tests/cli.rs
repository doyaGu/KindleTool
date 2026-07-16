//! End-to-end tests for CLI safety and compatibility behavior.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
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

fn create_fixture(directory: &Path, output: &str) -> PathBuf {
    let payload = directory.join("payload");
    fs::create_dir(&payload).unwrap();
    fs::write(payload.join("install.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(payload.join("asset.txt"), b"asset").unwrap();
    let result = run(
        directory,
        &["create", "ota2", "-d", "0x201", "payload", output],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    directory.join(output)
}

fn corrupt_last_byte(path: &Path) {
    let mut file = File::options().read(true).write(true).open(path).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&[byte[0] ^ 0xFF]).unwrap();
}

#[test]
fn mangle_and_demangle_cli_round_trip() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("input.bin");
    let encoded = temporary.path().join("encoded.bin");
    let decoded = temporary.path().join("decoded.bin");
    let bytes = (0_u8..=255).cycle().take(4097).collect::<Vec<_>>();
    fs::write(&input, &bytes).unwrap();

    assert!(
        run(
            temporary.path(),
            &["md", input.to_str().unwrap(), encoded.to_str().unwrap()]
        )
        .status
        .success()
    );
    let output = Command::new(kindletool())
        .current_dir(temporary.path())
        .args(["dm", encoded.to_str().unwrap(), decoded.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(fs::read(decoded).unwrap(), bytes);
}

#[test]
fn create_inspect_extract_and_convert_are_atomic() {
    let temporary = tempfile::tempdir().unwrap();
    let payload = temporary.path().join("payload");
    fs::create_dir(&payload).unwrap();
    fs::write(payload.join("install.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(payload.join("asset.txt"), b"asset").unwrap();

    let create = run(
        temporary.path(),
        &[
            "create",
            "ota2",
            "-d",
            "0x201",
            "payload",
            "Update_fixture.bin",
        ],
    );
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );

    let inspect = run(temporary.path(), &["convert", "-i", "Update_fixture.bin"]);
    assert!(inspect.status.success());
    assert!(String::from_utf8_lossy(&inspect.stderr).contains("Bundle Type    OTA V2"));

    let signed_copy = temporary.path().join("Update_signed.bin");
    fs::copy(temporary.path().join("Update_fixture.bin"), &signed_copy).unwrap();
    let signed = run(
        temporary.path(),
        &["convert", "-s", "-k", "Update_signed.bin"],
    );
    assert!(signed.status.success());
    assert!(signed_copy.exists());
    assert_eq!(
        fs::metadata(temporary.path().join("Update_signed.psig"))
            .unwrap()
            .len(),
        128
    );
    assert!(
        temporary
            .path()
            .join("Update_signed_converted.tar.gz")
            .exists()
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

    let valid_copy = temporary.path().join("Update_valid_copy.bin");
    fs::copy(temporary.path().join("Update_fixture.bin"), &valid_copy).unwrap();
    let convert = run(temporary.path(), &["convert", "Update_valid_copy.bin"]);
    assert!(convert.status.success());
    assert!(!valid_copy.exists());
    assert!(
        temporary
            .path()
            .join("Update_valid_copy_converted.tar.gz")
            .exists()
    );

    let corrupt = temporary.path().join("Update_corrupt.bin");
    fs::copy(temporary.path().join("Update_fixture.bin"), &corrupt).unwrap();
    let mut file = File::options()
        .read(true)
        .write(true)
        .open(&corrupt)
        .unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&[byte[0] ^ 0xFF]).unwrap();
    drop(file);

    let convert = run(temporary.path(), &["convert", "Update_corrupt.bin"]);
    assert!(!convert.status.success());
    assert!(corrupt.exists());
    assert!(
        !temporary
            .path()
            .join("Update_corrupt_converted.tar.gz")
            .exists()
    );
}

#[test]
fn one_failed_input_makes_multi_convert_fail_without_stopping_other_inputs() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("bad.bin"), b"not a package").unwrap();
    fs::write(
        temporary.path().join("plain.stgz"),
        b"\x1F\x8B\x08\x00payload",
    )
    .unwrap();
    let output = run(temporary.path(), &["convert", "bad.bin", "plain.stgz"]);
    assert!(!output.status.success());
    assert!(temporary.path().join("bad.bin").exists());
    assert!(!temporary.path().join("plain.stgz").exists());
    assert!(temporary.path().join("plain_converted.tar.gz").exists());
}

#[test]
fn stdout_conversion_never_deletes_the_source() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(
        temporary.path().join("plain.stgz"),
        b"\x1F\x8B\x08\x00payload",
    )
    .unwrap();
    let output = run(temporary.path(), &["convert", "-c", "plain.stgz"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"\x1F\x8B\x08\x00payload");
    assert!(temporary.path().join("plain.stgz").exists());
    assert!(!temporary.path().join("plain_converted.tar.gz").exists());
}

#[test]
fn stdout_conversion_rejects_a_corrupt_payload_before_writing() {
    let temporary = tempfile::tempdir().unwrap();
    let package = create_fixture(temporary.path(), "Update_corrupt_stdout.bin");
    corrupt_last_byte(&package);

    let output = run(
        temporary.path(),
        &["convert", "-c", "Update_corrupt_stdout.bin"],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(package.exists());
}

#[test]
fn stdin_conversion_rejects_a_corrupt_payload_before_writing() {
    let temporary = tempfile::tempdir().unwrap();
    let package = create_fixture(temporary.path(), "Update_corrupt_stdin.bin");
    corrupt_last_byte(&package);
    let mut child = Command::new(kindletool())
        .current_dir(temporary.path())
        .args(["convert", "-c", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&fs::read(package).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn v2_only_commands_are_not_part_of_the_cli_contract() {
    let temporary = tempfile::tempdir().unwrap();
    for command in ["inspect", "verify", "export", "codec", "serial"] {
        assert_eq!(run(temporary.path(), &[command]).status.code(), Some(2));
    }
}
