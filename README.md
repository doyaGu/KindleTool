# KindleTool 2.0

[![CI](https://github.com/doyaGu/KindleTool/actions/workflows/ci.yml/badge.svg)](https://github.com/doyaGu/KindleTool/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/doyaGu/KindleTool)](https://github.com/doyaGu/KindleTool/releases/latest) [![License](https://img.shields.io/github/license/doyaGu/KindleTool.svg)](/LICENSE)

KindleTool is a safe Rust library and command-line tool for Kindle update packages. Version 2.0
keeps the established v1.6.6 command line and disk formats while replacing the provisional Rust
1.7 library API with a smaller, correctness-oriented interface.

It recognizes FB01/FB02/FB03, FC02/FC04, FD03/FD04, FL01, SP01, CB01, gzip, and ZIP. The parser
uses checked little-endian reads and contains no `unsafe`. Package rules come from one static Rust
format catalog; the frozen C implementation under [`KindleTool/`](KindleTool/) remains the oracle.

## Install and build

Four standalone binaries are published on [GitHub Releases](https://github.com/doyaGu/KindleTool/releases/):
Windows x64, Linux x64 musl, macOS x64, and macOS ARM64. Verify downloads with `SHA256SUMS`.
Kindle ARM binaries are intentionally not part of the desktop release.

```sh
cargo build --release --locked
cargo test --workspace --locked
```

Rust 1.85 or newer is required. The release binary is `target/release/kindletool` (or
`kindletool.exe`). `make` builds Rust; `make legacy` builds the C oracle.

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
payload, archive, and target reports. Verification preserves the seek position. `SafeExtractor`
verifies into a spool and only commits an accepted archive from same-filesystem staging.
Third-party RSA, tar, and gzip types do not appear in the public API.

## Compatibility and development

```sh
python3 tools/generate_legacy_tables.py --check
make legacy
KINDLETOOL_C_ORACLE=KindleTool/Release/kindletool \
  cargo test -p kindletool-cli --test oracle --locked
```

Generated device, mangle, and jailbreak-key tables are derived from the frozen C oracle and
checked in CI. New formats normally require one `FormatRecord`; a new header codec is added only
when the on-disk layout is genuinely different. The project is GPL-3.0-or-later and is not
published to crates.io.
