//! Fuzz the tool argument parsers: arbitrary JSON documents must never panic
//! the typed `Args` accessors or `CallToolParams` deserialisation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nebula_mcp_protocol::CallToolParams;
use nebula_mcp_tools::common::Args;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    // tools/call params deserialisation (including the _meta progress token).
    if let Ok(params) = serde_json::from_value::<CallToolParams>(value.clone()) {
        let _ = params.progress_token();
    }

    // Typed argument extraction over every key present.
    if let Ok(args) = Args::new(&value) {
        if let Some(obj) = value.as_object() {
            for key in obj.keys() {
                let _ = args.opt_str(key);
                let _ = args.opt_u64(key);
                let _ = args.opt_i64(key);
                let _ = args.bool_or(key, false);
                let _ = args.opt_str_array(key);
                let _ = args.opt_string_map(key);
            }
        }
    }
});
