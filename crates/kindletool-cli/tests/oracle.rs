//! Bidirectional differential tests against the frozen C implementation.

use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kindletool::codec::mangle;
use kindletool::crypto::sha256_hex;
use kindletool::model::RECOVERY_HEADER_LEN;
use kindletool::{ArchiveOptions, SigningKey, UpdateArchiveBuilder};

struct PackageCase {
    name: &'static str,
    c_create_arguments: &'static [&'static str],
    rust_create_arguments: &'static [&'static str],
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

fn configured_oracle() -> Option<PathBuf> {
    let oracle = std::env::var_os("KINDLETOOL_C_ORACLE").map(PathBuf::from)?;
    assert!(
        oracle.is_file(),
        "C oracle does not exist: {}",
        oracle.display()
    );
    Some(oracle)
}

fn build_fixed_archive(directory: &Path) -> Vec<u8> {
    let source = directory.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("install.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(source.join("asset.txt"), b"differential fixture").unwrap();
    let mut archive = Vec::new();
    UpdateArchiveBuilder::new(&SigningKey::default_jailbreak().unwrap())
        .options(ArchiveOptions::new(true, 64).unwrap())
        .build(
            &[kindletool::ArchiveInput::from_source(source).unwrap()],
            &mut archive,
        )
        .unwrap();
    archive
}

#[test]
fn fixed_archive_package_matrix_is_byte_identical_and_mutually_readable() {
    let Some(oracle) = configured_oracle() else {
        eprintln!("KINDLETOOL_C_ORACLE is unset; skipping differential matrix");
        return;
    };
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_kindletool"));
    let temporary = tempfile::tempdir().unwrap();
    let archive = build_fixed_archive(temporary.path());

    let cases = [
        PackageCase {
            name: "fc02",
            c_create_arguments: &["create", "ota", "-d", "k3w", "-b", "FC02", "-t", "max"],
            rust_create_arguments: &[
                "create",
                "ota-v1",
                "--kind",
                "ota",
                "--source-revision",
                "0",
                "--target-revision",
                "4294967295",
                "--device",
                "k3w",
            ],
            output_name: "update_fc02.bin",
            expected_magic: "FC02",
        },
        PackageCase {
            name: "fd03",
            c_create_arguments: &["create", "ota", "-d", "k3w", "-b", "FD03", "-t", "max"],
            rust_create_arguments: &[
                "create",
                "ota-v1",
                "--kind",
                "versionless",
                "--source-revision",
                "0",
                "--target-revision",
                "4294967295",
                "--device",
                "k3w",
            ],
            output_name: "update_fd03.bin",
            expected_magic: "FD03",
        },
        PackageCase {
            name: "fc04",
            c_create_arguments: &[
                "create",
                "ota2",
                "-d",
                "paperwhite3",
                "-b",
                "FC04",
                "-x",
                "PackageName=differential-fixture",
            ],
            rust_create_arguments: &[
                "create",
                "ota-v2",
                "--kind",
                "ota",
                "--source-revision",
                "0",
                "--target-revision",
                "18446744073709551615",
                "--device",
                "paperwhite3",
                "--metadata",
                "PackageName=differential-fixture",
            ],
            output_name: "update_fc04.bin",
            expected_magic: "FC04",
        },
        PackageCase {
            name: "fd04",
            c_create_arguments: &[
                "create",
                "ota2",
                "-d",
                "paperwhite3",
                "-b",
                "FD04",
                "-x",
                "PackageName=differential-fixture",
            ],
            rust_create_arguments: &[
                "create",
                "ota-v2",
                "--kind",
                "versionless",
                "--source-revision",
                "0",
                "--target-revision",
                "18446744073709551615",
                "--device",
                "paperwhite3",
                "--metadata",
                "PackageName=differential-fixture",
            ],
            output_name: "update_fd04.bin",
            expected_magic: "FD04",
        },
        PackageCase {
            name: "fl01",
            c_create_arguments: &[
                "create",
                "ota2",
                "-d",
                "paperwhite3",
                "-b",
                "FL01",
                "-x",
                "PackageName=differential-fixture",
            ],
            rust_create_arguments: &[
                "create",
                "ota-v2",
                "--kind",
                "language",
                "--source-revision",
                "0",
                "--target-revision",
                "18446744073709551615",
                "--device",
                "paperwhite3",
                "--metadata",
                "PackageName=differential-fixture",
            ],
            output_name: "update_fl01.bin",
            expected_magic: "FL01",
        },
        PackageCase {
            name: "official_fc04",
            c_create_arguments: &[
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
            rust_create_arguments: &[
                "create",
                "ota-v2",
                "--kind",
                "ota",
                "--source-revision",
                "7",
                "--target-revision",
                "9",
                "--device",
                "paperwhite3",
            ],
            output_name: "update_official_fc04.bin",
            expected_magic: "FC04",
        },
        PackageCase {
            name: "fb01",
            c_create_arguments: &["create", "recovery", "-d", "k3w", "-b", "FB01", "-t", "max"],
            rust_create_arguments: &["create", "recovery-v1", "--kind", "fb01", "--device", "k3w"],
            output_name: "update_fb01.bin",
            expected_magic: "FB01",
        },
        PackageCase {
            name: "fb02",
            c_create_arguments: &["create", "recovery", "-d", "k3w", "-b", "FB02", "-t", "max"],
            rust_create_arguments: &["create", "recovery-v1", "--kind", "fb02", "--device", "k3w"],
            output_name: "update_fb02.bin",
            expected_magic: "FB02",
        },
        PackageCase {
            name: "fb02_h2",
            c_create_arguments: &[
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
            rust_create_arguments: &[
                "create",
                "recovery-v1",
                "--kind",
                "fb02",
                "--target-revision",
                "18446744073709551615",
                "--platform",
                "unspecified",
                "--board",
                "unspecified",
            ],
            output_name: "update_fb02_h2.bin",
            expected_magic: "FB02",
        },
        PackageCase {
            name: "fb03",
            c_create_arguments: &[
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
            rust_create_arguments: &[
                "create",
                "recovery-v2",
                "--target-revision",
                "18446744073709551615",
                "--platform",
                "unspecified",
                "--board",
                "unspecified",
                "--device",
                "none",
            ],
            output_name: "update_fb03.bin",
            expected_magic: "FB03",
        },
        PackageCase {
            name: "sp01_userdata",
            c_create_arguments: &["create", "sig", "-U"],
            rust_create_arguments: &["create", "userdata"],
            output_name: "data.stgz",
            expected_magic: "SP01",
        },
    ];

    for case in cases {
        exercise_fixed_archive_case(&rust, &oracle, temporary.path(), &archive, &case);
    }
}

fn exercise_fixed_archive_case(
    rust: &Path,
    oracle: &Path,
    root: &Path,
    archive: &[u8],
    case: &PackageCase,
) {
    let directory = root.join(case.name);
    fs::create_dir(&directory).unwrap();
    fs::create_dir(directory.join("rust")).unwrap();
    fs::create_dir(directory.join("c")).unwrap();
    fs::write(directory.join("fixture.tar.gz"), archive).unwrap();

    let rust_output = format!("rust/{}", case.output_name);
    let c_output = format!("c/{}", case.output_name);
    let mut rust_arguments = case.rust_create_arguments.to_vec();
    rust_arguments.extend(["--archive", "fixture.tar.gz", "--output", &rust_output]);
    let output = run(rust, &directory, &rust_arguments);
    assert_success(&output, &format!("Rust create {}", case.name));

    let mut c_arguments = case.c_create_arguments.to_vec();
    c_arguments.extend(["fixture.tar.gz", &c_output]);
    let output = run(oracle, &directory, &c_arguments);
    assert_success(&output, &format!("C create {}", case.name));

    assert_eq!(
        fs::read(directory.join(&rust_output)).unwrap(),
        fs::read(directory.join(&c_output)).unwrap(),
        "package bytes differ for {}",
        case.name
    );

    let rust_inspect = run(rust, &directory, &["inspect", &c_output]);
    assert_success(&rust_inspect, &format!("Rust reads C {}", case.name));
    assert!(String::from_utf8_lossy(&rust_inspect.stdout).contains(case.expected_magic));
    let c_inspect = run(oracle, &directory, &["convert", "-i", &rust_output]);
    assert_success(&c_inspect, &format!("C reads Rust {}", case.name));
    assert!(String::from_utf8_lossy(&c_inspect.stderr).contains(case.expected_magic));

    let rust_converted = format!("rust/{}.tar.gz", case.name);
    let output = run(
        rust,
        &directory,
        &[
            "export",
            "payload",
            "--view",
            "decoded",
            &c_output,
            "--output",
            &rust_converted,
        ],
    );
    assert_success(&output, &format!("Rust converts C {}", case.name));
    assert_eq!(fs::read(directory.join(&rust_converted)).unwrap(), archive);

    let output = run(oracle, &directory, &["convert", "-k", &rust_output]);
    assert_success(&output, &format!("C converts Rust {}", case.name));
    assert_eq!(
        fs::read(converted_path(&directory.join(&rust_output))).unwrap(),
        archive
    );

    let output = run(rust, &directory, &["extract", &c_output, "rust-extracted"]);
    assert_success(&output, &format!("Rust extracts C {}", case.name));
    let output = run(
        oracle,
        &directory,
        &["extract", &rust_output, "c-extracted"],
    );
    assert_success(&output, &format!("C extracts Rust {}", case.name));
    for output_dir in ["rust-extracted", "c-extracted"] {
        assert_eq!(
            fs::read(directory.join(output_dir).join("asset.txt")).unwrap(),
            b"differential fixture"
        );
    }
}

#[test]
fn directory_archives_have_matching_manifests_signatures_and_contents() {
    let Some(oracle) = configured_oracle() else {
        eprintln!("KINDLETOOL_C_ORACLE is unset; skipping directory differential test");
        return;
    };
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_kindletool"));
    let temporary = tempfile::tempdir().unwrap();
    let payload = temporary.path().join("payload");
    fs::create_dir(&payload).unwrap();
    fs::write(payload.join("install.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(payload.join("asset.txt"), b"directory differential").unwrap();
    fs::write(payload.join("ignored.sig"), b"old signature").unwrap();
    fs::write(payload.join("ignored.dat"), b"old file list").unwrap();
    fs::create_dir(temporary.path().join("rust")).unwrap();
    fs::create_dir(temporary.path().join("c")).unwrap();

    let rust_args = [
        "create",
        "ota-v2",
        "--kind",
        "versionless",
        "--source-revision",
        "0",
        "--target-revision",
        "18446744073709551615",
        "--device",
        "paperwhite3",
        "--output",
        "rust/update_directory.bin",
        "payload",
    ];
    assert_success(
        &run(&rust, temporary.path(), &rust_args),
        "Rust directory create",
    );
    let mut c_args = vec!["create", "ota2", "-d", "paperwhite3", "payload"];
    c_args.push("c/update_directory.bin");
    assert_success(
        &run(&oracle, temporary.path(), &c_args),
        "C directory create",
    );

    assert_success(
        &run(
            &rust,
            temporary.path(),
            &["extract", "c/update_directory.bin", "rust-extracted-c"],
        ),
        "Rust extracts C directory package",
    );
    assert_success(
        &run(
            &oracle,
            temporary.path(),
            &["extract", "rust/update_directory.bin", "c-extracted-rust"],
        ),
        "C extracts Rust directory package",
    );

    assert_equivalent_directory_outputs(
        &temporary.path().join("rust-extracted-c"),
        &temporary.path().join("c-extracted-rust"),
    );
}

#[test]
fn directory_manifest_comparison_accepts_platform_dependent_index_order() {
    let temporary = tempfile::tempdir().unwrap();
    let left = temporary.path().join("left");
    let right = temporary.path().join("right");
    fs::create_dir(&left).unwrap();
    fs::create_dir(&right).unwrap();

    for root in [&left, &right] {
        fs::write(root.join("asset.txt"), b"payload").unwrap();
        fs::write(root.join("asset.txt.sig"), b"file signature").unwrap();
    }
    let left_index = b"128 a payload/asset.txt\n129 b payload/install.sh\n";
    let right_index = b"129 b payload/install.sh\n128 a payload/asset.txt\n";
    let key = SigningKey::default_jailbreak().unwrap();
    for (root, index) in [
        (&left, left_index.as_slice()),
        (&right, right_index.as_slice()),
    ] {
        fs::write(root.join("update-filelist.dat"), index).unwrap();
        fs::write(
            root.join("update-filelist.dat.sig"),
            key.sign(&mut Cursor::new(index)).unwrap(),
        )
        .unwrap();
    }

    assert_equivalent_directory_outputs(&left, &right);
}

#[test]
fn component_gzip_and_zip_detection_match_the_oracle() {
    let Some(oracle) = configured_oracle() else {
        eprintln!("KINDLETOOL_C_ORACLE is unset; skipping detection differential test");
        return;
    };
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_kindletool"));
    let temporary = tempfile::tempdir().unwrap();
    let archive = build_fixed_archive(temporary.path());
    fs::create_dir(temporary.path().join("rust")).unwrap();
    fs::create_dir(temporary.path().join("c")).unwrap();

    let component = component_package(&archive);
    fs::write(temporary.path().join("rust/component.bin"), &component).unwrap();
    fs::write(temporary.path().join("c/component.bin"), &component).unwrap();
    let output = run(&rust, temporary.path(), &["inspect", "c/component.bin"]);
    assert_success(&output, "Rust component inspection");
    assert!(String::from_utf8_lossy(&output.stdout).contains("CB01"));
    let output = run(
        &oracle,
        temporary.path(),
        &["convert", "-i", "rust/component.bin"],
    );
    assert_success(&output, "C component inspection");
    assert!(String::from_utf8_lossy(&output.stderr).contains("CB01"));
    assert_success(
        &run(
            &rust,
            temporary.path(),
            &[
                "export",
                "payload",
                "--view",
                "decoded",
                "c/component.bin",
                "--output",
                "c/component_converted.tar.gz",
            ],
        ),
        "Rust converts C component",
    );
    assert_success(
        &run(
            &oracle,
            temporary.path(),
            &["convert", "-k", "rust/component.bin"],
        ),
        "C converts Rust component",
    );
    assert_eq!(
        fs::read(temporary.path().join("c/component_converted.tar.gz")).unwrap(),
        archive
    );
    assert_eq!(
        fs::read(temporary.path().join("rust/component_converted.tar.gz")).unwrap(),
        archive
    );

    fs::write(temporary.path().join("plain.stgz"), &archive).unwrap();
    fs::write(temporary.path().join("android.bin"), b"PK\x03\x04fixture").unwrap();
    for (input, expected) in [("plain.stgz", "GZIP"), ("android.bin", "ZIP")] {
        let output = run(&rust, temporary.path(), &["inspect", input]);
        assert_success(&output, "Rust raw inspection");
        assert!(String::from_utf8_lossy(&output.stdout).contains(expected));
        let output = run(&oracle, temporary.path(), &["convert", "-i", input]);
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
}

fn component_package(archive: &[u8]) -> Vec<u8> {
    let sha256 = sha256_hex(&mut Cursor::new(archive)).unwrap();
    let mut package = vec![0_u8; 4 + RECOVERY_HEADER_LEN];
    package[..4].copy_from_slice(b"CB01");
    let raw = &mut package[4..];
    raw[0..8].copy_from_slice(&0_u64.to_le_bytes());
    raw[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    raw[16..80].copy_from_slice(sha256.as_bytes());
    raw[80..84].copy_from_slice(&1_u32.to_le_bytes());
    raw[84..88].copy_from_slice(&0_u32.to_le_bytes());
    raw[88..92].copy_from_slice(&0_u32.to_le_bytes());
    raw[92..96].copy_from_slice(&0_u32.to_le_bytes());
    let mut payload = archive.to_vec();
    mangle(&mut payload);
    package.extend_from_slice(&payload);
    package
}

fn converted_path(input: &Path) -> PathBuf {
    let stem = input.file_stem().unwrap().to_string_lossy();
    input.with_file_name(format!("{stem}_converted.tar.gz"))
}

fn file_manifest(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, current: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(current)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &path, output);
            } else {
                output.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }

    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

fn assert_equivalent_directory_outputs(left_root: &Path, right_root: &Path) {
    let index_path = Path::new("update-filelist.dat");
    let signature_path = Path::new("update-filelist.dat.sig");
    let mut left = file_manifest(left_root);
    let mut right = file_manifest(right_root);
    let left_index = left.remove(index_path).expect("left index is present");
    let right_index = right.remove(index_path).expect("right index is present");
    let left_signature = left
        .remove(signature_path)
        .expect("left index signature is present");
    let right_signature = right
        .remove(signature_path)
        .expect("right index signature is present");

    assert_eq!(left, right, "payloads or per-file signatures differ");
    assert_eq!(
        sorted_index_lines(&left_index),
        sorted_index_lines(&right_index),
        "update-filelist.dat entries differ"
    );

    let key = SigningKey::default_jailbreak().unwrap();
    assert_eq!(
        key.sign(&mut Cursor::new(&left_index)).unwrap(),
        left_signature,
        "left update-filelist.dat signature is invalid"
    );
    assert_eq!(
        key.sign(&mut Cursor::new(&right_index)).unwrap(),
        right_signature,
        "right update-filelist.dat signature is invalid"
    );
}

fn sorted_index_lines(index: &[u8]) -> Vec<Vec<u8>> {
    let mut lines = index
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    lines.sort_unstable();
    lines
}
