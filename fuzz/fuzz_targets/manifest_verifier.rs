#![no_main]

use flate2::Compression;
use flate2::write::GzEncoder;
use kindletool::{ArchiveKind, UpdateArchiveVerifier, VerificationLimits, VerificationPolicy};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use tar::{Builder, Header};

const MAX_FIELD_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    let split = data
        .first()
        .map_or(0, |selector| usize::from(*selector) % data.len().max(1));
    let manifest_start = usize::from(!data.is_empty());
    let manifest_end = split.max(manifest_start).min(data.len());
    let manifest = &data[manifest_start..manifest_end.min(manifest_start + MAX_FIELD_BYTES)];
    let payload = &data[manifest_end..data.len().min(manifest_end + MAX_FIELD_BYTES)];
    let archive = archive(manifest, payload);
    let limits = VerificationLimits::new(1024 * 1024, 16, 4096, 64 * 1024).unwrap();
    for kind in [
        ArchiveKind::Ota,
        ArchiveKind::Recovery,
        ArchiveKind::Component,
    ] {
        let verifier =
            UpdateArchiveVerifier::new(kind, VerificationPolicy::structural(), None, limits);
        let _ = verifier.verify(Cursor::new(&archive));
    }
});

fn archive(manifest: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let encoder = GzEncoder::new(&mut output, Compression::fast());
    let mut archive = Builder::new(encoder);
    append(&mut archive, "payload.bin", payload);
    append(&mut archive, "payload.bin.sig", &[0; 128]);
    append(&mut archive, "update-filelist.dat.sig", &[0; 128]);
    append(&mut archive, "update-filelist.dat", manifest);
    archive.finish().unwrap();
    archive.into_inner().unwrap().finish().unwrap();
    output
}

fn append<W: std::io::Write>(archive: &mut Builder<W>, path: &str, data: &[u8]) {
    let mut header = Header::new_gnu();
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_size(data.len() as u64);
    header.set_cksum();
    archive
        .append_data(&mut header, path, Cursor::new(data))
        .unwrap();
}
