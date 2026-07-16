#![no_main]

use kindletool::{PackageReader, VerificationOptions};
use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, sink};

fuzz_target!(|data: &[u8]| {
    if let Ok(mut package) = PackageReader::new(Cursor::new(data)) {
        let _ = package.verify(VerificationOptions::default());
        let _ = package.copy_decoded_payload(sink(), false);
    }
});
