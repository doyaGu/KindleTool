# KindleTool

KindleTool is a Rust library and command-line utility for creating, inspecting,
converting, and extracting Kindle update packages.

It supports FB01/FB02/FB03, FC02/FC04, FD03/FD04, FL01, SP01, CB01, gzip,
and ZIP package detection. The command line and Kindle package formats remain
compatible with KindleTool 1.6.6.

## Download

Prebuilt binaries for Windows x64, Linux x64 musl, macOS x64, and macOS ARM64
are available from [GitHub Releases](https://github.com/doyaGu/KindleTool/releases/).
Verify downloaded files with the accompanying `SHA256SUMS` file.

## Usage

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

Run `kindletool help` or `kindletool help create` for complete option and target
device documentation.

## Build

Rust 1.85 or newer is required.

```sh
cargo build --release --locked
cargo test --workspace --locked
```

The executable is written to `target/release/kindletool` (or
`target/release/kindletool.exe` on Windows).

## Rust library

The `kindletool` crate provides typed APIs for parsing, encoding, verifying,
and safely extracting packages. Generate the API documentation locally with:

```sh
cargo doc -p kindletool --open
```

See the [2.0 migration guide](docs/migration-2.0.md) when updating code written
against the earlier Rust API.

## License

KindleTool is licensed under [GPL-3.0-or-later](LICENSE). See [NOTICE.md](NOTICE.md)
for authorship and attribution.
