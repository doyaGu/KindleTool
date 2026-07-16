# Migrating to KindleTool 2.0

Version 2.0 preserves the KindleTool 1.6.6/1.7 command line and Kindle package bytes. Existing
scripts continue to use `md`, `dm`, `convert`, `extract`, `create`, `info`, `version`, and `help`,
including their short/long options, environment variables, inferred output names, and source-file
deletion rules. The experimental `inspect`, `verify`, `export`, `codec`, and `serial` command names
are not part of the 2.0 interface.

The clean break applies only to Rust callers. Replace `PackageReader`/`PackageWriter`,
`WriteOptions`, and `VerificationOptions` with `Package`, `PackageEncoder`, explicit
`EncodeOptions`, `VerificationContext`, and one of the two fixed `VerificationPolicy`
constructors. Payload copy and SP01 unwrap consume `Package`, so a second call cannot observe a
partially consumed stream. Parsed fields are read through accessors; creation uses validated
format-specific specs.

`Package::verify` provides typed structural and authentic verification outcomes. This capability
has intentionally not been exposed by changing the stable CLI.
