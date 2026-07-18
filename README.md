# KindleTool

KindleTool is a Rust library and command-line utility for creating, inspecting,
converting, and extracting Kindle update packages.

It supports FB01/FB02/FB03, FC02/FC04, FD03/FD04, FL01, SP01, CB01, gzip,
and ZIP package detection. Package parsing uses checked little-endian reads and
the project forbids `unsafe` code. The command line and Kindle package formats
remain compatible with KindleTool 1.6.6.

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

### Common operations

Look up device information from a Kindle serial number:

```sh
kindletool info SERIAL
```

Convert a package to a decoded archive while keeping the source package:

```sh
kindletool convert -k Update_example.bin
```

Extract a package into a directory:

```sh
kindletool extract Update_example.bin output-directory
```

Create commands accept device aliases such as `kindle5` and `basic5`. Consult
`kindletool help create` for the exact options required by each package type.

> [!CAUTION]
> `kindletool convert` deletes each successfully converted source file by
> default. Pass `-k` to keep it. Writing to stdout with `-c` never deletes the
> source.

### Environment variables

- `KT_WITH_UNKNOWN_DEVCODES=1` enables data-mined device codes when expanding
  aliases, including current `basic5`/KT6 variants.
- `KT_PKG_METADATA_DUMP=PATH` writes shell-friendly metadata produced by
  `convert -i`.
- `TMPDIR` selects the directory used for temporary files.

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
and safely extracting packages.

```rust
use kindletool::{Package, PayloadView, Result};
use std::fs::File;

fn decode(path: &str, output: &mut Vec<u8>) -> Result<()> {
    let package = Package::parse(File::open(path)?)?;
    println!("{}", package.descriptor().magic());
    package.copy_payload(PayloadView::Decoded, output)?;
    Ok(())
}
```

Generate the complete API documentation locally with:

```sh
cargo doc -p kindletool --open
```

See the [2.0 migration guide](docs/migration-2.0.md) when updating code written
against the earlier Rust API.

## License

KindleTool is licensed under [GPL-3.0-or-later](LICENSE). See [NOTICE.md](NOTICE.md)
for authorship and attribution.
