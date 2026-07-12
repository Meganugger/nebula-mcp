//! Fuzz the JSON-RPC frame decoder: arbitrary byte streams must never cause a
//! panic, unbounded loop or memory blow-up in `FrameReader`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nebula_mcp_protocol::FrameReader;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build single-thread runtime");
    rt.block_on(async {
        let mut reader = FrameReader::new(data);
        // Bounded by the number of newlines in the input plus one partial
        // line; each call must return without panicking.
        loop {
            match reader.next_frame().await {
                Ok(None) => break,
                Ok(Some(_)) | Err(_) => continue,
            }
        }
    });
});
