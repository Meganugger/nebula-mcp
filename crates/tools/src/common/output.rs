//! Result-formatting helpers shared across tools.
//!
//! Every helper emits the tool's JSON payload twice: pretty-printed inside the
//! ordinary text content block (for text-only clients) and verbatim as MCP
//! `structuredContent` (for schema-aware clients that want typed results).

use nebula_mcp_protocol::{CallToolResult, Content};
use serde::Serialize;
use serde_json::Value;

use crate::common::exec::ExecResult;

/// Build a success result whose single text block is pretty-printed JSON, with
/// the same value attached as `structuredContent`.
pub fn json_result<T: Serialize>(value: &T) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(v) => json_value_result(v),
        Err(e) => CallToolResult {
            content: vec![Content::text(format!(
                "{{\"error\":\"failed to serialise result: {e}\"}}"
            ))],
            structured_content: None,
            is_error: Some(false),
        },
    }
}

/// Build a success result from a raw JSON value (text + `structuredContent`).
pub fn json_value_result(value: Value) -> CallToolResult {
    let text = serde_json::to_string_pretty(&value)
        .unwrap_or_else(|e| format!("{{\"error\":\"failed to serialise result: {e}\"}}"));
    CallToolResult {
        content: vec![Content::text(text)],
        structured_content: Some(value),
        is_error: Some(false),
    }
}

/// Render an [`ExecResult`] as a structured JSON tool result, marking it as an
/// error result when the process exited non-zero.
pub fn exec_result(command: &str, r: &ExecResult) -> CallToolResult {
    let value = exec_result_value(command, r);
    let text = serde_json::to_string_pretty(&value).unwrap_or_default();
    CallToolResult {
        content: vec![Content::text(text)],
        structured_content: Some(value),
        is_error: Some(!r.success()),
    }
}

/// The canonical JSON shape for a completed process, shared by [`exec_result`]
/// and tools that augment it with extra fields (e.g. parsed diagnostics).
pub fn exec_result_value(command: &str, r: &ExecResult) -> Value {
    serde_json::json!({
        "command": command,
        "exitCode": r.code,
        "success": r.success(),
        "durationMs": r.duration.as_millis(),
        "stdout": r.stdout,
        "stderr": r.stderr,
        "stdoutTruncated": r.stdout_truncated,
        "stderrTruncated": r.stderr_truncated,
    })
}

/// Build a tool result from an arbitrary JSON value with an explicit error
/// flag (text + `structuredContent`).
pub fn json_value_result_with_error(value: Value, is_error: bool) -> CallToolResult {
    let text = serde_json::to_string_pretty(&value).unwrap_or_default();
    CallToolResult {
        content: vec![Content::text(text)],
        structured_content: Some(value),
        is_error: Some(is_error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn exec_result_marks_failure() {
        let r = ExecResult {
            code: Some(1),
            stdout: String::new(),
            stderr: "boom".into(),
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(5),
        };
        let res = exec_result("git status", &r);
        assert_eq!(res.is_error, Some(true));
    }

    #[test]
    fn results_carry_structured_content() {
        let res = json_value_result(serde_json::json!({"a": 1}));
        assert_eq!(res.structured_content.as_ref().unwrap()["a"], 1);

        let r = ExecResult {
            code: Some(0),
            stdout: "hi".into(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(1),
        };
        let res = exec_result("echo hi", &r);
        let sc = res.structured_content.unwrap();
        assert_eq!(sc["exitCode"], 0);
        assert_eq!(sc["stdout"], "hi");
    }
}
