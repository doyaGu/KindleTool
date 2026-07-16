#![no_main]

use kindletool::ArchivePath;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(path) = std::str::from_utf8(data) {
        let _ = ArchivePath::new(path);
    }
});
