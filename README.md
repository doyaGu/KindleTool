# KindleTool
[![License](https://img.shields.io/github/license/NiLuJe/KindleTool.svg)](/LICENSE) [![Latest tag](https://img.shields.io/github/tag-date/NiLuJe/KindleTool.svg)](https://github.com/NiLuJe/KindleTool/releases/)

KindleTool's mainline implementation is the safe Rust workspace in this repository root. It
preserves the v1.6.6 package and CLI compatibility baseline while providing standalone Windows
x64, Linux x64 musl, macOS x64, and macOS ARM64 executables. Rust 1.85 or newer is required.

```sh
cargo build --release --locked
cargo test --workspace --locked
```

The executable is `target/release/kindletool` (`kindletool.exe` on Windows). The `kindletool`
library crate exposes typed package readers, writers, archive builders, device catalogs, and
signing APIs; the `kindletool-cli` crate provides the compatible executable. Project code forbids
`unsafe`, and gzip uses the pure-Rust `flate2` backend.

The C implementation remains in [`KindleTool/`](KindleTool/) as the legacy differential-test
oracle. Build it explicitly with `make legacy`; the root `make` target builds Rust.

### Public Rust API

```rust
use kindletool::{PackageReader, Result};
use std::fs::File;

fn inspect(path: &str) -> Result<()> {
    let package = PackageReader::new(File::open(path)?)?;
    println!("{}", package.info().header.magic());
    Ok(())
}
```

`PackageSpec` represents only valid OTA V1, OTA V2, recovery V1, recovery V2, and signed-userdata
combinations. `SigningKey` accepts 1024/2048-bit PKCS#1 or PKCS#8 PEM keys without exposing the
underlying cryptography crate. Safe extraction validates complete archives in private staging and
atomically commits them to absent or empty destinations.

### Compatibility verification

Set `KINDLETOOL_C_ORACLE` to a C 1.6.6 executable to enable the bidirectional differential matrix:

```sh
make legacy
KINDLETOOL_C_ORACLE=KindleTool/Release/kindletool \
  cargo test -p kindletool-cli --test oracle --locked
```

## Usage
-   KindleTool md [ &lt;<b>input</b>&gt; ] [ &lt;<b>output</b>&gt; ]

> Obfuscates data using Amazon's update algorithm.  
> If no input is provided, input from stdin  
> If no output is provided, output to stdout

-   KindleTool dm [ &lt;<b>input</b>&gt; ] [ &lt;<b>output</b>&gt; ]

> Deobfuscates data using Amazon's update algorithm.  
> If no input is provided, input from stdin  
> If no output is provided, output to stdout

-   KindleTool convert [<i>options</i>] &lt;<b>input</b>&gt;...

> Converts a Kindle update package to a gzipped tar archive file, and delete input.

	Options:
		-c, --stdout                  Write to standard output, keeping original files unchanged.
		-i, --info                    Just print the package information, no conversion done.
		-s, --sig                     OTA V2, Recovery V2 & Recovery FB02 with header rev 2 updates only. Extract the payload signature.
		-k, --keep                    Don't delete the input package.
		-u, --unsigned                Assume input is an unsigned & mangled userdata package.
		-w, --unwrap                  Just unwrap the package, if it's wrapped in an UpdateSignature header (especially useful for userdata packages).

-   KindleTool extract [<i>options</i>] &lt;<b>input</b>&gt; &lt;<b>output</b>&gt;

> Extracts a Kindle update package to a directory.

	Options:
		-u, --unsigned                Assume input is an unsigned & mangled userdata package.

-   KindleTool create &lt;<b>type</b>&gt; &lt;<b>devices</b>&gt; [<i>options</i>] &lt;<b>dir</b>|<b>file</b>&gt;... [ &lt;<b>output</b>&gt; ]

> Creates a Kindle update package.  
> You should be able to throw a mix of files &amp; directories as input without trouble.  
> Just keep in mind that by default, if you feed it absolute paths, it will archive absolute paths, which usually isn't what you want!  
> If input is a single gzipped tarball (".tgz" or ".tar.gz") file, we assume it is properly packaged (bundlefile &amp; sigfile), and will only convert it to an update.  
> Output should be a file with the extension ".bin", if it is not provided, or if it's a single dash, outputs to standard output.  
> In case of OTA updates, all files with the extension ".ffs" or ".sh" will be treated as update scripts.

	Type:
		ota                           OTA V1 update package. Works on Kindle 3 and older.
		ota2                          OTA V2 signed update package. Works on Kindle 4 and newer.
		recovery                      Recovery package for restoring partitions.
		recovery2                     Recovery V2 package for restoring partitions. Works on FW >= 5.2 (PaperWhite) and newer
		sig                           Signature envelope. Use this to build a signed userdata package with the -U switch (FW >= 5.1 only, but device agnostic).

	Devices:
		OTA V1 & Recovery packages only support one device. OTA V2 & Recovery V2 packages can support multiple devices.
		The complete alias list is generated from DeviceCatalog; run `kindletool help create` to view it.

	Platforms:
		Recovery V2 & Recovery FB02 with header rev 2 updates only. Use a single platform per package.
		The complete platform list is generated from the format catalog; run `kindletool help create` to view it.
	Boards:
		Recovery V2 & Recovery FB02 with header rev 2 updates only. Use a single board per package.
		The complete board list is generated from the format catalog; run `kindletool help create` to view it.

	Options:
		All the following options are optional and advanced.
		-k, --key <file>              PEM file containing RSA private key to sign update. Default is popular jailbreak key.
		-b, --bundle <type>           Manually specify package magic number. May override the value dictated by "type", if it makes sense. Valid bundle versions:
                                        FB01, FB02 = recovery; FB03 = recovery2; FC02, FD03 = ota; FC04, FD04, FL01 = ota2; SP01 = sig
		-s, --srcrev <ulong|uint>     OTA updates only. Source revision. OTA V1 uses uint, OTA V2 uses ulong.
                                        Lowest version of device that package supports. Default is 0.
                                        Also acccepts min for 0.
		-t, --tgtrev <ulong|uint>     OTA, Recovery V2 & Recovery FB02 with header rev 2 updates only. Target revision. OTA V1 & Recovery V1H2 uses uint, OTA V2 & Recovery V2 uses ulong.
                                        Highest version of device that package supports. Default is ulong/uint max value.
                                        Also acccepts max for the appropriate maximum value for the chosen update package type.
		-h, --hdrrev <uint>           Recovery V2 & Recovery FB02 updates only. Header Revision. Default is 0.
		-1, --magic1 <uint>           Recovery updates only. Magic number 1. Default is 0.
		-2, --magic2 <uint>           Recovery updates only. Magic number 2. Default is 0.
		-m, --minor <uint>            Recovery updates only. Minor number. Default is 0.
		-c, --cert <ushort>           OTA V2 & Recovery V2 updates only. The number of the certificate to use (found in /etc/uks on device). Default is 0.
                                        0 = pubdevkey01.pem, 1 = pubprodkey01.pem, 2 = pubprodkey02.pem
		-o, --opt <uchar>             OTA V1 updates only. One byte optional data expressed as a number. Default is 0.
		-r, --crit <uchar>            OTA V2 updates only. One byte optional data expressed as a number. Default is 0.
		-x, --meta <str>              OTA V2 updates only. An optional string to add. Multiple "--meta" options supported.
                                        Format of metastring must be: key=value
		-X, --packaging               OTA V2 updates only. Adds PackagedWith, PackagedBy & PackagedOn metastrings, storing packaging metadata.
		-a, --archive                 Keep the intermediate archive.
		-u, --unsigned                Build an unsigned & mangled userdata package.
		-U, --userdata                Build an userdata package (can only be used with the sig update type).
		-O, --ota                     Build a versioned OTA bundle (can only be used with the ota2 update type).
		-C, --legacy                  Emulate the behaviour of yifanlu's KindleTool regarding directories. By default, we behave like tar:
                                        every path passed on the commandline is stored as-is in the archive. This switch changes that, and store paths
                                        relative to the path passed on the commandline, like if we had chdir'ed into it.

-   KindleTool info &lt;<b>serialno</b>&gt;

> Get the default root password.  
> Unless you changed your password manually, the first password shown will be the right one.  
> (The Kindle defaults to DES hashed passwords, which are truncated to 8 characters).  
> If you're looking for the recovery MMC export password, that's the second one.

-   KindleTool version

> Show some info about this KindleTool build.

-   KindleTool help

> Show this help screen.

### Notices
1.  If the variable KT_WITH_UNKNOWN_DEVCODES is set in your environment (no matter the value), some device checks will be relaxed with the create command.
2.  If the variable KT_PKG_METADATA_DUMP is set in your environment, convert will dump header info in a shell-friendly format in the file this variable points to.
3.  Updates with meta-strings will probably fail to run when passed to "Update Your Kindle".
4.  Currently, even though OTA V2 supports updates that run on multiple devices, it is not possible to create an update package that will run on both FW 4.x (Kindle 4) and FW 5.x (Basically everything since the Kindle Touch).

### Building

Run `cargo build --release --locked` or simply `make`. See [COMPILING](/COMPILING) for the complete
Rust and legacy C build targets.

<!-- kate: indent-mode cstyle; indent-width 4; replace-tabs on; remove-trailing-spaces none; -->
