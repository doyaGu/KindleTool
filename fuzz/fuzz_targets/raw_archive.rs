#![no_main]

use kindletool::{ArchiveKind, UpdateArchiveVerifier, VerificationLimits, VerificationPolicy};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let limits = VerificationLimits::new(64 * 1024, 128, 4096, 16 * 1024).unwrap();
    for kind in [
        ArchiveKind::Ota,
        ArchiveKind::Recovery,
        ArchiveKind::Component,
        ArchiveKind::Userdata,
    ] {
        let verifier =
            UpdateArchiveVerifier::new(kind, VerificationPolicy::structural(), None, limits);
        let _ = verifier.verify(Cursor::new(data));
    }
});
