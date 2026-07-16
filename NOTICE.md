# Attribution

The mainline Rust implementation is derived from KindleTool 1.6.6 and remains licensed under
GPL-3.0-or-later. The original KindleTool work is by Yifan Lu, NiLuJe, and the
KindleTool contributors. The byte-mangling tables, update-header layouts, device
catalog, embedded jailbreak key, archive manifest conventions, and password derivation
retain their original provenance and licensing.

The C implementation under `KindleTool/` is intentionally retained as the frozen
compatibility oracle. Generated Rust lookup files identify the generator that imports
the relevant compatibility data; they are not independently authored lookup tables.
