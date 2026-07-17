//! Rust-only command-line compatibility matrix for supported package formats.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kindletool::codec::mangle;
use kindletool::crypto::sha256_hex;
use kindletool::model::RECOVERY_HEADER_LEN;
use kindletool::{ArchiveInput, ArchiveOptions, SigningKey, UpdateArchiveBuilder};

struct PackageCase {
    name: &'static str,
    create_arguments: &'static [&'static str],
    output_name: &'static str,
    expected_magic: &'static str,
}

fn run(program: &Path, directory: &Path, arguments: &[&str]) -> Output {
    Command::new(program)
        .current_dir(directory)
        .args(arguments)
        .output()
        .unwrap()
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn build_archive(directory: &Path, source_name: &str, content: &[u8]) -> Vec<u8> {
    let source = directory.join(source_name);
    fs::write(&source, content).unwrap();
    let mut archive = Vec::new();
    UpdateArchiveBuilder::new(&SigningKey::default_jailbreak().unwrap())
        .options(ArchiveOptions::new(true, 64).unwrap())
        .build(&[ArchiveInput::from_source(source).unwrap()], &mut archive)
        .unwrap();
    archive
}

#[test]
fn every_creatable_format_round_trips_through_the_cli() {
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_kindletool"));
    let temporary = tempfile::tempdir().unwrap();
    let archive = build_archive(
        temporary.path(),
        "asset.txt",
        b"command-line compatibility fixture",
    );
    fs::write(temporary.path().join("fixture.tar.gz"), &archive).unwrap();

    let cases = [
        PackageCase {
            name: "fc02",
            create_arguments: &["create", "ota", "-d", "k3w", "-b", "FC02", "-t", "max"],
            output_name: "update_fc02.bin",
            expected_magic: "FC02",
        },
        PackageCase {
            name: "fd03",
            create_arguments: &["create", "ota", "-d", "k3w", "-b", "FD03", "-t", "max"],
            output_name: "update_fd03.bin",
            expected_magic: "FD03",
        },
        PackageCase {
            name: "fc04",
            create_arguments: &[
                "create",
                "ota2",
                "-d",
                "paperwhite3",
                "-b",
                "FC04",
                "-x",
                "PackageName=compatibility-fixture",
            ],
            output_name: "update_fc04.bin",
            expected_magic: "FC04",
        },
        PackageCase {
            name: "fd04",
            create_arguments: &[
                "create",
                "ota2",
                "-d",
                "paperwhite3",
                "-b",
                "FD04",
                "-x",
                "PackageName=compatibility-fixture",
            ],
            output_name: "update_fd04.bin",
            expected_magic: "FD04",
        },
        PackageCase {
            name: "fl01",
            create_arguments: &[
                "create",
                "ota2",
                "-d",
                "paperwhite3",
                "-b",
                "FL01",
                "-x",
                "PackageName=compatibility-fixture",
            ],
            output_name: "update_fl01.bin",
            expected_magic: "FL01",
        },
        PackageCase {
            name: "official_fc04",
            create_arguments: &[
                "create",
                "ota2",
                "-d",
                "paperwhite3",
                "-b",
                "FD04",
                "-O",
                "-s",
                "7",
                "-t",
                "9",
            ],
            output_name: "update_official_fc04.bin",
            expected_magic: "FC04",
        },
        PackageCase {
            name: "fb01",
            create_arguments: &["create", "recovery", "-d", "k3w", "-b", "FB01", "-t", "max"],
            output_name: "update_fb01.bin",
            expected_magic: "FB01",
        },
        PackageCase {
            name: "fb02",
            create_arguments: &["create", "recovery", "-d", "k3w", "-b", "FB02", "-t", "max"],
            output_name: "update_fb02.bin",
            expected_magic: "FB02",
        },
        PackageCase {
            name: "fb02_h2",
            create_arguments: &[
                "create",
                "recovery",
                "-d",
                "none",
                "-b",
                "FB02",
                "-h",
                "2",
                "-p",
                "unspecified",
                "-B",
                "unspecified",
                "-t",
                "max",
            ],
            output_name: "update_fb02_h2.bin",
            expected_magic: "FB02",
        },
        PackageCase {
            name: "fb03",
            create_arguments: &[
                "create",
                "recovery2",
                "-d",
                "none",
                "-p",
                "unspecified",
                "-B",
                "unspecified",
                "-t",
                "max",
            ],
            output_name: "update_fb03.bin",
            expected_magic: "FB03",
        },
        PackageCase {
            name: "sp01_userdata",
            create_arguments: &["create", "sig", "-U"],
            output_name: "data.stgz",
            expected_magic: "SP01",
        },
    ];

    for case in cases {
        let directory = temporary.path().join(case.name);
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("fixture.tar.gz"), &archive).unwrap();

        let mut arguments = case.create_arguments.to_vec();
        arguments.extend(["fixture.tar.gz", case.output_name]);
        assert_success(&run(&rust, &directory, &arguments), case.name);

        let inspection = run(&rust, &directory, &["convert", "-i", case.output_name]);
        assert_success(&inspection, &format!("inspect {}", case.name));
        assert!(String::from_utf8_lossy(&inspection.stderr).contains(case.expected_magic));

        let conversion = run(&rust, &directory, &["convert", "-c", case.output_name]);
        assert_success(&conversion, &format!("convert {}", case.name));
        assert_eq!(
            conversion.stdout, archive,
            "decoded payload differs for {}",
            case.name
        );

        let extraction = format!("extract-{}", case.name);
        assert_success(
            &run(
                &rust,
                &directory,
                &["extract", case.output_name, &extraction],
            ),
            &format!("extract {}", case.name),
        );
        assert_eq!(
            fs::read(directory.join(extraction).join("asset.txt")).unwrap(),
            b"command-line compatibility fixture"
        );
    }
}

#[test]
fn component_gzip_and_zip_detection_remain_available() {
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_kindletool"));
    let temporary = tempfile::tempdir().unwrap();
    let component_content = b"synthetic component payload";
    let archive = build_archive(temporary.path(), "component.bin", component_content);
    let component = component_package(&archive, component_content);
    fs::write(temporary.path().join("component.bin"), &component).unwrap();

    let inspection = run(&rust, temporary.path(), &["convert", "-i", "component.bin"]);
    assert_success(&inspection, "inspect component");
    assert!(String::from_utf8_lossy(&inspection.stderr).contains("CB01"));

    assert_success(
        &run(&rust, temporary.path(), &["convert", "-k", "component.bin"]),
        "convert component",
    );
    assert_eq!(
        fs::read(temporary.path().join("component_converted.tar.gz")).unwrap(),
        archive
    );

    fs::write(temporary.path().join("plain.stgz"), &archive).unwrap();
    fs::write(temporary.path().join("android.bin"), b"PK\x03\x04fixture").unwrap();
    for (input, expected) in [("plain.stgz", "GZIP"), ("android.bin", "ZIP")] {
        let output = run(&rust, temporary.path(), &["convert", "-i", input]);
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
}

fn component_package(archive: &[u8], component_content: &[u8]) -> Vec<u8> {
    let sha256 = sha256_hex(&mut Cursor::new(component_content)).unwrap();
    let mut package = vec![0_u8; 4 + RECOVERY_HEADER_LEN];
    package[..4].copy_from_slice(b"CB01");
    let raw = &mut package[4..];
    raw[0..8].copy_from_slice(&0_u64.to_le_bytes());
    raw[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    raw[16..80].copy_from_slice(sha256.as_bytes());
    raw[80..84].copy_from_slice(&1_u32.to_le_bytes());
    let mut payload = archive.to_vec();
    mangle(&mut payload);
    package.extend_from_slice(&payload);
    package
}
