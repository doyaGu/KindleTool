# Attribution

The mainline Rust implementation is derived from KindleTool 1.6.6 and remains licensed under
GPL-3.0-or-later. The original KindleTool work is by Yifan Lu, NiLuJe, and the
KindleTool contributors. The byte-mangling tables, update-header layouts, device
catalog, embedded jailbreak key, archive manifest conventions, and password derivation
retain their original provenance and licensing.

The historical C implementation remains available in Git history and the `v2.0.1`
source tag. It is no longer shipped on the main branch. The canonical Rust device
catalog, byte-mangling tables, and embedded key remain derived compatibility data;
they are not independently authored lookup tables.
