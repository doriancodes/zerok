#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Expectation: never panic. Either Ok(_) or a clean Err(_).
    let _ = zerok::kpkg::parse_manifest(data);
});
