# Migrating to KindleTool 2.0

Version 2.0 preserves Kindle package bytes, not the 1.x command or Rust interface.

| Before | 2.0 |
|---|---|
| `md` / `dm` | `codec mangle` / `codec demangle` |
| `convert -i` | `inspect` |
| `convert` | `export payload --view decoded` |
| `convert -u` | `export payload --view stored` |
| `convert -s` | `export signature` |
| `convert -w` | `export inner` |
| `info SERIAL` | `serial SERIAL` |
| multi-input conversion | one explicit package per invocation |
| implicit output names/deletion | mandatory output; source is never deleted |
| archive guessed by extension | explicit `create ... --archive FILE` |

`verify` defaults to authentic verification. `extract` defaults to structural verification and
accepts `--policy authentic`. Machine consumers should use `inspect --format json` or
`verify --format json`; `KT_PKG_METADATA_DUMP` was removed.

Rust callers replace `PackageReader`/`PackageWriter`, `WriteOptions`, and `VerificationOptions`
with `Package`, `PackageEncoder`, explicit `EncodeOptions`, `VerificationContext`, and one of the
two fixed `VerificationPolicy` constructors. Payload copy and SP01 unwrap consume `Package`, so a
second call cannot observe a partially consumed stream. Parsed fields are read through accessors;
creation uses validated format-specific specs.
