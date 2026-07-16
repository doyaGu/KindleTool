# KindleTool in Rust

This workspace contains the safe Rust implementation of KindleTool 1.6.6:

- `kindletool`: stable parsing, encoding, signing, archive, extraction, device-catalog,
  and serial-number APIs.
- `kindletool-cli`: the `kindletool` executable and its compatible command surface.

The implementation uses Rust 2024 with MSRV 1.85 and forbids unsafe code. It has no C
runtime or external compression dependency: gzip uses `flate2`'s `rust_backend`.

## Build and test

```sh
cd rust
cargo build --release --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

The executable is `target/release/kindletool` (`kindletool.exe` on Windows). Release CI
publishes Windows x64, Linux x64 musl, macOS x64, and macOS ARM64 standalone binaries.
Kindle ARM targets are intentionally outside this release.

## Public API

```rust
use kindletool::{PackageReader, Result};
use std::fs::File;

fn inspect(path: &str) -> Result<()> {
    let package = PackageReader::new(File::open(path)?)?;
    println!("{}", package.info().header.magic());
    Ok(())
}
```

`PackageSpec` exposes only valid OTA V1, OTA V2, recovery V1, recovery V2, and signed
userdata combinations. `SigningKey` accepts 1024/2048-bit PKCS#1 or PKCS#8 PEM keys
without exposing the underlying cryptography crate.

`kindletool help create` renders device aliases, platforms, boards, bundle magic values,
and certificates directly from the library catalogs. Safe extraction validates a complete
archive in a private sibling directory and atomically commits it to an absent or empty
destination, so a rejected archive cannot leave partial output behind.

## Compatibility verification

Normal tests cover all supported magic values, truncated headers, metadata limits,
chunk boundaries, aliases, RSA key sizes, archive manifests, and extraction escape
attempts. Set `KINDLETOOL_C_ORACLE` to a C 1.6.6 executable to enable the optional
byte-for-byte, bidirectional differential test:

```sh
KINDLETOOL_C_ORACLE=../KindleTool/Release/kindletool \
  cargo test -p kindletool-cli --test oracle
```

Large or proprietary firmware is never copied into the repository. Local corpus checks
must copy inputs to a temporary directory before conversion because successful file-mode
conversion preserves KindleTool's default behavior of deleting its source.
