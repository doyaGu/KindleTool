# KindleTool 2.0

[![CI](https://github.com/doyaGu/KindleTool/actions/workflows/ci.yml/badge.svg)](https://github.com/doyaGu/KindleTool/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/doyaGu/KindleTool)](https://github.com/doyaGu/KindleTool/releases/latest) [![License](https://img.shields.io/github/license/doyaGu/KindleTool.svg)](/LICENSE)

KindleTool is a safe Rust library and command-line tool for Kindle update packages. Version 2.0
keeps the established v1.6.6 command line and disk formats while replacing the provisional Rust
1.7 library API with a smaller, correctness-oriented interface.

It recognizes FB01/FB02/FB03, FC02/FC04, FD03/FD04, FL01, SP01, CB01, gzip, and ZIP. The parser
uses checked little-endian reads and contains no `unsafe`. Package rules come from one static Rust
format catalog, with compatibility protected by golden vectors, property tests, fuzzing, and a
read-only package corpus.

## Install and build

Four standalone binaries are published on [GitHub Releases](https://github.com/doyaGu/KindleTool/releases/):
Windows x64, Linux x64 musl, macOS x64, and macOS ARM64. Verify downloads with `SHA256SUMS`.
Kindle ARM binaries are intentionally not part of the desktop release.

```sh
cargo build --release --locked
cargo test --workspace --locked
```

Rust 1.85 or newer is required. The release binary is `target/release/kindletool` (or
`kindletool.exe`). The root `Makefile` provides Cargo-backed build, test, check, and install targets.

## CLI

```text
kindletool md [INPUT] [OUTPUT]
kindletool dm [INPUT] [OUTPUT]
kindletool convert [-ciksuw] INPUT...
kindletool extract [-u] INPUT OUTPUT
kindletool create ota|ota2|recovery|recovery2|sig [OPTIONS] INPUT... [OUTPUT]
kindletool info SERIAL
kindletool version
kindletool help [COMMAND]
```

The interface, short and long options, environment variables, default output names, and normal
stdout/stderr behavior remain compatible with KindleTool 1.6.6/1.7. Run `kindletool help create`
for the data-driven device, platform, board, magic, and certificate catalogs.
Unknown future platform and board selectors may be supplied as decimal or `0x`-prefixed raw values.

`convert` creates `<stem>_converted.tar.gz` and deletes the source after the output is validated,
flushed, and atomically committed. `-k` keeps the source, `-c` writes staged stdout without deleting
anything, `-i` prints package information, `-s` exports the SP01 signature, `-u` preserves stored
payload bytes, and `-w` removes one SP01 envelope. A failure in any multi-input conversion makes
the final exit status nonzero without preventing other inputs from being attempted.

`KT_WITH_UNKNOWN_DEVCODES` enables data-mined device codes while expanding aliases.
`KT_PKG_METADATA_DUMP` writes shell-friendly `convert -i` metadata to the selected path. `TMPDIR`
selects temporary storage. Command-line usage errors exit 2; successful commands exit 0 and
execution failures exit 1.

Authenticity and policy verification remain available through the public Rust API rather than a
new, incompatible command surface. See the [2.0 migration guide](docs/migration-2.0.md) for the
library-only break.

## Public Rust API

```rust
use kindletool::{Package, PayloadView, Result};
use std::fs::File;

fn decode(path: &str, output: &mut Vec<u8>) -> Result<()> {
    let package = Package::parse(File::open(path)?)?;
    println!("{} {:?}", package.descriptor().magic(), package.descriptor().format());
    package.copy_payload(PayloadView::Decoded, output)?;
    Ok(())
}
```

`PackageDescriptor` exposes common read-only queries while `PackageHeader` remains available for
format-specific callers. Creation uses validated `OtaV1Spec`, `OtaV2Spec`, `RecoveryV1Spec`,
`RecoveryV2Spec`, or `UserdataSpec`, then `PackageEncoder::encode`. Input payload representation
and signed/unsigned behavior are explicit; no security-sensitive `Default` exists.

`Package::verify` returns `ValidationOutcome::Accepted` or `Rejected` with fixed signature,
payload, archive, and target reports. Detailed archive issues remain available through
`VerificationReport::archive_report`, and `VerificationKey::default_jailbreak` exposes the
embedded developer public key without constructing its private half. Verification preserves the seek position. `SafeExtractor`
verifies into a spool and only commits an accepted archive from same-filesystem staging.
Third-party RSA, tar, and gzip types do not appear in the public API.

## Compatibility and development

Device codes, mangle tables, and the jailbreak key are canonical Rust compatibility data. New
formats normally require one `FormatRecord`; a new header layout is added only when the on-disk
structure is genuinely different. Catalog invariants, golden vectors, round trips, adversarial
archives, property tests, and fuzz targets are enforced in CI. The project is GPL-3.0-or-later
and is not published to crates.io.

The historical C implementation was removed from the main branch after the Rust implementation
became authoritative. It remains available in Git history and the `v2.0.1` source tag for
archaeology and attribution, but is no longer a build or test dependency.

Local packages that cannot be redistributed can be verified through the read-only corpus harness.
Paths use the host platform's path-list separator. Every source is copied to temporary storage
before parsing and structural verification:

```sh
KINDLETOOL_CORPUS="/path/KUAL.bin:/path/USBNetLite.bin:/path/official-FB03.bin" \
  cargo test -p kindletool --test corpus -- --nocapture
```

Known-invalid vendor artifacts can be kept as negative corpus cases without weakening verification.
Set `KINDLETOOL_CORPUS_DIGEST_MISMATCH` to a host path-list of packages expected to be rejected
solely for archive entry digest mismatches.
