#![no_main]

use kindletool::{Package, PayloadView, VerificationContext, VerificationPolicy};
use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, sink};

fuzz_target!(|data: &[u8]| {
    if let Ok(mut package) = Package::parse(Cursor::new(data)) {
        let _ = package.verify(
            &VerificationContext::new(),
            VerificationPolicy::structural(),
        );
        let _ = package.copy_payload(PayloadView::Decoded, sink());
    }
});
