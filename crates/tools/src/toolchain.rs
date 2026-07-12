//! Toolchain helpers: first-class wrappers for common build ecosystems
//! (cargo, npm, pnpm, pip, poetry, go, gradle, maven) layered on the same
//! hardened execution engine as `terminal.run`, with **parsed diagnostics**.
//!
//! Each tool runs the ecosystem's CLI (which must be on the command allowlist,
//! exactly like `terminal.run`) and additionally extracts a structured
//! `diagnostics` array — severity, message, file/line/column and error code
//! where the output format provides them — so agents can react to compiler
//! errors, test failures and dependency problems without re-parsing raw text.

use std::sync::Arc;

use async_trait::async_trait;
use nebula_mcp_core::{Result, Tool, ToolContext};
use nebula_mcp_protocol::mcp::ToolAnnotations;
use nebula_mcp_protocol::CallToolResult;
use serde::Serialize;
use serde_json::{json, Value};

use crate::common::exec::{run_checked, CommandSpec, ExecResult};
use crate::common::output::{exec_result_value, json_value_result_with_error};
use crate::common::{Args, ObjectSchema};

const CATEGORY: &str = "toolchain";

/// Build every toolchain tool.
pub fn tools() -> Vec<Arc<dyn Tool>> {
    ECOSYSTEMS
        .iter()
        .map(|e| Arc::new(ToolchainTool { eco: e }) as Arc<dyn Tool>)
        .collect()
}

/// One parsed diagnostic extracted from tool output.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Diagnostic {
    /// `error`, `warning` or `note`.
    pub severity: String,
    /// Human-readable message.
    pub message: String,
    /// Source file, when the output names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// 1-based line number, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// 1-based column number, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// Tool-specific code (e.g. `E0308`, `ERR_PNPM_FETCH_404`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl Diagnostic {
    fn new(severity: &str, message: impl Into<String>) -> Self {
        Self {
            severity: severity.to_string(),
            message: message.into(),
            file: None,
            line: None,
            column: None,
            code: None,
        }
    }
}

/// Static description of one supported ecosystem.
struct Ecosystem {
    /// Tool suffix (`toolchain.<suffix>`).
    suffix: &'static str,
    /// Default executable (overridable via the `program` argument).
    program: &'static str,
    /// Description shown to the model.
    description: &'static str,
    /// Diagnostics parser over the combined output.
    parse: fn(&ExecResult) -> Vec<Diagnostic>,
}

static ECOSYSTEMS: &[Ecosystem] = &[
    Ecosystem {
        suffix: "cargo",
        program: "cargo",
        description: "Run cargo (build/check/test/clippy/...) with parsed rustc diagnostics \
                      (severity, code, file:line:col) and test failures. The cargo binary must \
                      be allowlisted; args are passed verbatim.",
        parse: parse_rust,
    },
    Ecosystem {
        suffix: "npm",
        program: "npm",
        description: "Run npm (install/run/test/...) with parsed npm ERR!/WARN diagnostics. \
                      The npm binary must be allowlisted; args are passed verbatim.",
        parse: parse_npm,
    },
    Ecosystem {
        suffix: "pnpm",
        program: "pnpm",
        description: "Run pnpm (install/run/test/...) with parsed ERR_PNPM_*/WARN diagnostics. \
                      The pnpm binary must be allowlisted; args are passed verbatim.",
        parse: parse_pnpm,
    },
    Ecosystem {
        suffix: "pip",
        program: "pip",
        description: "Run pip (install/download/...) with parsed ERROR:/WARNING: diagnostics. \
                      The pip binary must be allowlisted (override program to pip3 if needed); \
                      args are passed verbatim.",
        parse: parse_pip,
    },
    Ecosystem {
        suffix: "poetry",
        program: "poetry",
        description: "Run poetry (install/add/build/...) with parsed error/warning diagnostics. \
                      The poetry binary must be allowlisted; args are passed verbatim.",
        parse: parse_poetry,
    },
    Ecosystem {
        suffix: "go",
        program: "go",
        description: "Run go (build/test/vet/...) with parsed file:line:col diagnostics and \
                      test failures. The go binary must be allowlisted; args are passed verbatim.",
        parse: parse_go,
    },
    Ecosystem {
        suffix: "gradle",
        program: "gradle",
        description: "Run gradle (build/test/...) with parsed compiler and task-failure \
                      diagnostics. The gradle binary must be allowlisted (override program to \
                      ./gradlew for wrapper builds); args are passed verbatim.",
        parse: parse_gradle,
    },
    Ecosystem {
        suffix: "maven",
        program: "mvn",
        description: "Run Maven (package/test/...) with parsed [ERROR]/[WARNING] diagnostics \
                      including file:[line,col] locations. The mvn binary must be allowlisted; \
                      args are passed verbatim.",
        parse: parse_maven,
    },
];

/// A single toolchain wrapper tool.
struct ToolchainTool {
    eco: &'static Ecosystem,
}

#[async_trait]
impl Tool for ToolchainTool {
    fn name(&self) -> &str {
        // Names are static per ecosystem; build them once.
        match self.eco.suffix {
            "cargo" => "toolchain.cargo",
            "npm" => "toolchain.npm",
            "pnpm" => "toolchain.pnpm",
            "pip" => "toolchain.pip",
            "poetry" => "toolchain.poetry",
            "go" => "toolchain.go",
            "gradle" => "toolchain.gradle",
            "maven" => "toolchain.maven",
            other => other,
        }
    }
    fn category(&self) -> &str {
        CATEGORY
    }
    fn description(&self) -> &str {
        self.eco.description
    }
    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .string_array(
                "args",
                "Arguments passed verbatim to the tool (e.g. [\"build\", \"--release\"]).",
                true,
            )
            .string(
                "program",
                "Override the executable (default shown in the description); must be allowlisted.",
                false,
            )
            .string("cwd", "Working directory (default: workspace root).", false)
            .prop(
                "env",
                json!({"type": "object", "description": "Environment variables to set.", "additionalProperties": {"type": "string"}}),
                false,
            )
            .integer("timeoutSecs", "Timeout in seconds (clamped to policy max).", false)
            .build()
    }
    fn annotations(&self) -> Option<ToolAnnotations> {
        Some(ToolAnnotations {
            open_world_hint: Some(true),
            ..Default::default()
        })
    }
    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        let a = Args::new(&args)?;
        let cmd_args = a.str_array("args")?;
        let program = a.str_or("program", self.eco.program)?.to_string();
        let cwd = match a.opt_str("cwd")? {
            Some(c) => ctx.resolve_path(c)?,
            None => ctx.working_dir.clone(),
        };
        let env = a.opt_string_map("env")?;
        let timeout = a.opt_u64("timeoutSecs")?;

        let spec = CommandSpec::new(&program, cwd, ctx)
            .args(cmd_args.clone())
            .envs(env);
        let display = format!("{program} {}", cmd_args.join(" "));
        let result = run_checked(ctx, spec, timeout).await?;

        let diagnostics = (self.eco.parse)(&result);
        let errors = diagnostics.iter().filter(|d| d.severity == "error").count();
        let warnings = diagnostics
            .iter()
            .filter(|d| d.severity == "warning")
            .count();
        let mut value = exec_result_value(&display, &result);
        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "diagnostics".into(),
                serde_json::to_value(&diagnostics).unwrap_or_default(),
            );
            obj.insert(
                "diagnosticCounts".into(),
                json!({ "errors": errors, "warnings": warnings }),
            );
        }
        Ok(json_value_result_with_error(value, !result.success()))
    }
}

/// Combined stdout + stderr lines, stderr last (most compilers emit there).
fn all_lines(r: &ExecResult) -> impl Iterator<Item = &str> {
    r.stdout.lines().chain(r.stderr.lines())
}

/// Try to parse a `path:line:col` (or `path:line`) location suffix.
fn split_location(s: &str) -> Option<(String, u32, Option<u32>)> {
    let mut parts = s.rsplitn(3, ':');
    let last = parts.next()?;
    let mid = parts.next()?;
    let rest = parts.next();
    if let (Ok(line), Ok(col)) = (mid.parse::<u32>(), last.parse::<u32>()) {
        // path:line:col
        return rest.map(|p| (p.to_string(), line, Some(col)));
    }
    if let Ok(line) = last.parse::<u32>() {
        // path:line — re-join the untouched prefix.
        let path = match rest {
            Some(r) => format!("{r}:{mid}"),
            None => mid.to_string(),
        };
        return Some((path, line, None));
    }
    None
}

/// rustc/cargo human-readable output: `error[E0308]: msg` headers followed by
/// ` --> file:line:col`, plus libtest `... FAILED` markers.
fn parse_rust(r: &ExecResult) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in all_lines(r) {
        let trimmed = line.trim_end();
        let header = trimmed
            .strip_prefix("error")
            .map(|rest| ("error", rest))
            .or_else(|| {
                trimmed
                    .strip_prefix("warning")
                    .map(|rest| ("warning", rest))
            });
        if let Some((severity, rest)) = header {
            // `[E0308]: msg` or `: msg`.
            let (code, msg) = if let Some(rest) = rest.strip_prefix('[') {
                match rest.split_once(']') {
                    Some((code, tail)) => (
                        Some(code.to_string()),
                        tail.strip_prefix(':').unwrap_or(tail).trim().to_string(),
                    ),
                    None => continue,
                }
            } else if let Some(msg) = rest.strip_prefix(':') {
                (None, msg.trim().to_string())
            } else {
                continue;
            };
            // Skip pure summary lines ("error: aborting due to ...").
            if msg.starts_with("aborting due to") {
                continue;
            }
            let mut d = Diagnostic::new(severity, msg);
            d.code = code;
            out.push(d);
            continue;
        }
        // Location line attaches to the most recent diagnostic without one.
        if let Some(loc) = trimmed.trim_start().strip_prefix("--> ") {
            if let Some((file, line_no, col)) = split_location(loc.trim()) {
                if let Some(d) = out.last_mut() {
                    if d.file.is_none() {
                        d.file = Some(file);
                        d.line = Some(line_no);
                        d.column = col;
                    }
                }
            }
            continue;
        }
        // libtest failure markers: `test tests::t ... FAILED`.
        if let Some(name) = trimmed
            .strip_prefix("test ")
            .and_then(|t| t.strip_suffix(" ... FAILED"))
        {
            out.push(Diagnostic::new("error", format!("test failed: {name}")));
        }
    }
    out
}

/// go build/vet: `file.go:12:5: message`; go test: `--- FAIL: TestName`.
fn parse_go(r: &ExecResult) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in all_lines(r) {
        let trimmed = line.trim_end();
        if let Some(rest) = trimmed.trim_start().strip_prefix("--- FAIL: ") {
            let name = rest.split_whitespace().next().unwrap_or(rest);
            out.push(Diagnostic::new("error", format!("test failed: {name}")));
            continue;
        }
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        // `path.go:line:col: message` (also matches vet output).
        if let Some((loc_and_msg, _)) = trimmed.split_once(".go:") {
            let after = &trimmed[loc_and_msg.len() + 4..];
            let mut nums = after.splitn(3, ':');
            if let (Some(l), Some(second)) = (nums.next(), nums.next()) {
                if let Ok(line_no) = l.trim().parse::<u32>() {
                    let file = format!("{loc_and_msg}.go");
                    let (col, msg) = match second.trim().parse::<u32>() {
                        Ok(c) => (Some(c), nums.next().unwrap_or("").trim().to_string()),
                        Err(_) => {
                            let mut m = second.trim().to_string();
                            if let Some(restmsg) = nums.next() {
                                m.push(':');
                                m.push_str(restmsg);
                            }
                            (None, m)
                        }
                    };
                    if !msg.is_empty() {
                        let mut d = Diagnostic::new("error", msg);
                        d.file = Some(file);
                        d.line = Some(line_no);
                        d.column = col;
                        out.push(d);
                    }
                }
            }
        }
    }
    out
}

/// npm: `npm ERR! ...` / `npm error ...` and `npm WARN ...` / `npm warn ...`.
fn parse_npm(r: &ExecResult) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in all_lines(r) {
        let trimmed = line.trim_end();
        let rest = trimmed.strip_prefix("npm ");
        let Some(rest) = rest else { continue };
        if let Some(msg) = rest
            .strip_prefix("ERR! ")
            .or_else(|| rest.strip_prefix("error "))
        {
            if !msg.trim().is_empty() {
                let mut d = Diagnostic::new("error", msg.trim());
                if let Some(code) = msg.trim().strip_prefix("code ") {
                    d.code = Some(code.trim().to_string());
                    d.message = format!("npm error code {}", code.trim());
                }
                out.push(d);
            }
        } else if let Some(msg) = rest
            .strip_prefix("WARN ")
            .or_else(|| rest.strip_prefix("warn "))
        {
            if !msg.trim().is_empty() {
                out.push(Diagnostic::new("warning", msg.trim()));
            }
        }
    }
    out
}

/// pnpm: ` ERR_PNPM_<CODE>  message` and ` WARN  message`.
fn parse_pnpm(r: &ExecResult) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in all_lines(r) {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("ERR_PNPM_") {
            let (code, msg) = rest.split_once(' ').unwrap_or((rest, ""));
            let mut d = Diagnostic::new("error", msg.trim());
            d.code = Some(format!("ERR_PNPM_{code}"));
            if d.message.is_empty() {
                d.message = d.code.clone().unwrap_or_default();
            }
            out.push(d);
        } else if let Some(msg) = trimmed.strip_prefix("WARN ") {
            out.push(Diagnostic::new("warning", msg.trim()));
        } else if let Some(msg) = trimmed.strip_prefix("ERROR ") {
            out.push(Diagnostic::new("error", msg.trim()));
        }
    }
    out
}

/// pip: `ERROR: message` / `WARNING: message`.
fn parse_pip(r: &ExecResult) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in all_lines(r) {
        let trimmed = line.trim();
        if let Some(msg) = trimmed.strip_prefix("ERROR: ") {
            out.push(Diagnostic::new("error", msg.trim()));
        } else if let Some(msg) = trimmed.strip_prefix("WARNING: ") {
            out.push(Diagnostic::new("warning", msg.trim()));
        }
    }
    out
}

/// poetry: `Error: message`, bracketed exception names (`[SolverProblemError]`)
/// and `Warning: message`.
fn parse_poetry(r: &ExecResult) -> Vec<Diagnostic> {
    let mut out: Vec<Diagnostic> = Vec::new();
    let mut pending_code: Option<String> = None;
    for line in all_lines(r) {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() > 2 {
            let name = &trimmed[1..trimmed.len() - 1];
            if name.chars().all(|c| c.is_ascii_alphanumeric()) && name.contains("Error") {
                pending_code = Some(name.to_string());
            }
            continue;
        }
        if let Some(msg) = trimmed
            .strip_prefix("Error: ")
            .or_else(|| trimmed.strip_prefix("error: "))
        {
            let mut d = Diagnostic::new("error", msg.trim());
            d.code = pending_code.take();
            out.push(d);
        } else if let Some(msg) = trimmed
            .strip_prefix("Warning: ")
            .or_else(|| trimmed.strip_prefix("warning: "))
        {
            out.push(Diagnostic::new("warning", msg.trim()));
        } else if let Some(code) = pending_code.take() {
            // The line after a bracketed exception name carries its message.
            if !trimmed.is_empty() {
                let mut d = Diagnostic::new("error", trimmed);
                d.code = Some(code);
                out.push(d);
            } else {
                pending_code = Some(code);
            }
        }
    }
    out
}

/// gradle: Kotlin `e:`/`w:` diagnostics, javac `File.java:12: error: msg`,
/// task failures and the `What went wrong` block.
fn parse_gradle(r: &ExecResult) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let mut lines = all_lines(r).peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_end();
        // Kotlin compiler: `e: file: (12, 5): msg` or `e: file:12:5 msg`.
        if let Some(rest) = trimmed
            .strip_prefix("e: ")
            .map(|r| ("error", r))
            .or_else(|| trimmed.strip_prefix("w: ").map(|r| ("warning", r)))
        {
            let (severity, body) = rest;
            let body = body.trim();
            let mut d = Diagnostic::new(severity, body);
            // Kotlin emits `e: <path>:<line>:<col> <message>`; the location is
            // the first whitespace-separated token.
            if let Some((loc, msg)) = body.split_once(char::is_whitespace) {
                if let Some((file, line_no, col)) = split_location(loc) {
                    if file.contains('/') || file.contains('\\') || file.contains(".kt") {
                        d.file = Some(file);
                        d.line = Some(line_no);
                        d.column = col;
                        d.message = msg.trim().to_string();
                    }
                }
            }
            out.push(d);
            continue;
        }
        // javac via gradle: `/path/File.java:12: error: ';' expected`.
        if let Some(idx) = trimmed.find(".java:") {
            let (path, rest) = trimmed.split_at(idx + 5);
            if let Some(rest) = rest.strip_prefix(':') {
                let mut parts = rest.splitn(2, ':');
                if let (Some(l), Some(tail)) = (parts.next(), parts.next()) {
                    if let Ok(line_no) = l.trim().parse::<u32>() {
                        let tail = tail.trim();
                        let (severity, msg) = if let Some(m) = tail.strip_prefix("error:") {
                            ("error", m.trim())
                        } else if let Some(m) = tail.strip_prefix("warning:") {
                            ("warning", m.trim())
                        } else {
                            ("error", tail)
                        };
                        let mut d = Diagnostic::new(severity, msg);
                        d.file = Some(path.to_string());
                        d.line = Some(line_no);
                        out.push(d);
                        continue;
                    }
                }
            }
        }
        // Task failure: `> Task :app:test FAILED`.
        if let Some(task) = trimmed
            .strip_prefix("> Task ")
            .and_then(|t| t.strip_suffix(" FAILED"))
        {
            out.push(Diagnostic::new("error", format!("task failed: {task}")));
            continue;
        }
        // `* What went wrong:` — the next non-empty line is the message.
        if trimmed.starts_with("* What went wrong") {
            for next in lines.by_ref() {
                let n = next.trim();
                if !n.is_empty() {
                    out.push(Diagnostic::new("error", n));
                    break;
                }
            }
        }
    }
    out
}

/// maven: `[ERROR] /path/File.java:[12,5] msg` and plain `[ERROR]`/`[WARNING]`.
fn parse_maven(r: &ExecResult) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in all_lines(r) {
        let trimmed = line.trim_end();
        let (severity, msg) = if let Some(m) = trimmed.strip_prefix("[ERROR] ") {
            ("error", m)
        } else if let Some(m) = trimmed.strip_prefix("[WARNING] ") {
            ("warning", m)
        } else {
            continue;
        };
        let msg = msg.trim();
        if msg.is_empty()
            || msg.starts_with("For more information")
            || msg.starts_with("Re-run Maven")
            || msg.starts_with("To see the full stack trace")
            || msg.starts_with("-> [Help")
        {
            continue;
        }
        let mut d = Diagnostic::new(severity, msg);
        // `path:[line,col] message`.
        if let Some(idx) = msg.find(":[") {
            if let Some(end) = msg[idx..].find(']') {
                let loc = &msg[idx + 2..idx + end];
                let mut nums = loc.splitn(2, ',');
                if let Some(Ok(line_no)) = nums.next().map(|v| v.trim().parse::<u32>()) {
                    d.file = Some(msg[..idx].to_string());
                    d.line = Some(line_no);
                    d.column = nums.next().and_then(|v| v.trim().parse().ok());
                    d.message = msg[idx + end + 1..].trim().to_string();
                }
            }
        }
        out.push(d);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn exec(stdout: &str, stderr: &str, code: i32) -> ExecResult {
        ExecResult {
            code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(10),
        }
    }

    #[test]
    fn registers_all_ecosystems() {
        let ts = tools();
        assert_eq!(ts.len(), 8);
        let names: Vec<&str> = ts.iter().map(|t| t.name()).collect();
        for expected in [
            "toolchain.cargo",
            "toolchain.npm",
            "toolchain.pnpm",
            "toolchain.pip",
            "toolchain.poetry",
            "toolchain.go",
            "toolchain.gradle",
            "toolchain.maven",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn parses_rustc_diagnostics() {
        let stderr = "\
error[E0308]: mismatched types
  --> src/main.rs:5:20
   |
 5 |     let x: u32 = \"hi\";
   |                  ^^^^ expected `u32`, found `&str`
warning: unused variable: `y`
 --> src/lib.rs:4:9
error: aborting due to 1 previous error
test util::tests::parses ... FAILED
";
        let ds = parse_rust(&exec("", stderr, 1));
        assert_eq!(ds.len(), 3);
        assert_eq!(ds[0].severity, "error");
        assert_eq!(ds[0].code.as_deref(), Some("E0308"));
        assert_eq!(ds[0].message, "mismatched types");
        assert_eq!(ds[0].file.as_deref(), Some("src/main.rs"));
        assert_eq!(ds[0].line, Some(5));
        assert_eq!(ds[0].column, Some(20));
        assert_eq!(ds[1].severity, "warning");
        assert_eq!(ds[1].file.as_deref(), Some("src/lib.rs"));
        assert_eq!(ds[2].message, "test failed: util::tests::parses");
    }

    #[test]
    fn parses_go_diagnostics() {
        let stderr = "# example.com/m\nmain.go:12:5: undefined: foo\npkg/util.go:3:1: syntax error: unexpected }\n";
        let stdout = "--- FAIL: TestThing (0.00s)\n    thing_test.go:10: got 2, want 3\nFAIL\n";
        let ds = parse_go(&exec(stdout, stderr, 1));
        assert!(ds.iter().any(|d| d.message == "test failed: TestThing"));
        let undef = ds.iter().find(|d| d.message.contains("undefined")).unwrap();
        assert_eq!(undef.file.as_deref(), Some("main.go"));
        assert_eq!(undef.line, Some(12));
        assert_eq!(undef.column, Some(5));
    }

    #[test]
    fn parses_npm_diagnostics() {
        let stderr = "\
npm WARN deprecated left-pad@1.3.0: use String.prototype.padStart()
npm ERR! code E404
npm ERR! 404 Not Found - GET https://registry.npmjs.org/nope
";
        let ds = parse_npm(&exec("", stderr, 1));
        assert_eq!(ds.len(), 3);
        assert_eq!(ds[0].severity, "warning");
        assert_eq!(ds[1].code.as_deref(), Some("E404"));
        assert!(ds[2].message.contains("404 Not Found"));
    }

    #[test]
    fn parses_pnpm_diagnostics() {
        let out = " ERR_PNPM_FETCH_404  GET https://registry.npmjs.org/nope: Not Found - 404\n WARN  deprecated pkg@1.0.0\n";
        let ds = parse_pnpm(&exec(out, "", 1));
        assert_eq!(ds.len(), 2);
        assert_eq!(ds[0].code.as_deref(), Some("ERR_PNPM_FETCH_404"));
        assert_eq!(ds[1].severity, "warning");
    }

    #[test]
    fn parses_pip_diagnostics() {
        let err = "ERROR: Could not find a version that satisfies the requirement nope\nWARNING: You are using pip version 21.0\n";
        let ds = parse_pip(&exec("", err, 1));
        assert_eq!(ds.len(), 2);
        assert_eq!(ds[0].severity, "error");
        assert_eq!(ds[1].severity, "warning");
    }

    #[test]
    fn parses_poetry_diagnostics() {
        let out = "\
[SolverProblemError]
Because myapp depends on nope (^1.0) which doesn't match any versions, version solving failed.
Error: The lock file is not up to date.
";
        let ds = parse_poetry(&exec(out, "", 1));
        assert_eq!(ds.len(), 2);
        assert_eq!(ds[0].code.as_deref(), Some("SolverProblemError"));
        assert!(ds[0].message.contains("version solving failed"));
        assert!(ds[1].message.contains("lock file"));
    }

    #[test]
    fn parses_gradle_diagnostics() {
        let out = "\
> Task :app:compileJava FAILED
/home/x/App.java:12: error: ';' expected
        int x = 1
                 ^
e: /home/x/Main.kt:8:5 Unresolved reference: foo
* What went wrong:
Execution failed for task ':app:compileJava'.
";
        let ds = parse_gradle(&exec(out, "", 1));
        assert!(ds
            .iter()
            .any(|d| d.message == "task failed: :app:compileJava"));
        let javac = ds
            .iter()
            .find(|d| d.message.contains("';' expected"))
            .unwrap();
        assert_eq!(javac.file.as_deref(), Some("/home/x/App.java"));
        assert_eq!(javac.line, Some(12));
        let kt = ds
            .iter()
            .find(|d| d.message.contains("Unresolved reference"))
            .unwrap();
        assert_eq!(kt.file.as_deref(), Some("/home/x/Main.kt"));
        assert_eq!(kt.line, Some(8));
        assert_eq!(kt.column, Some(5));
        assert!(ds
            .iter()
            .any(|d| d.message.contains("Execution failed for task")));
    }

    #[test]
    fn parses_maven_diagnostics() {
        let out = "\
[INFO] Compiling 3 source files
[WARNING] Using platform encoding (UTF-8)
[ERROR] /src/main/java/App.java:[10,15] ';' expected
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin
[ERROR] -> [Help 1]
";
        let ds = parse_maven(&exec(out, "", 1));
        assert_eq!(ds.len(), 3);
        assert_eq!(ds[0].severity, "warning");
        assert_eq!(ds[1].file.as_deref(), Some("/src/main/java/App.java"));
        assert_eq!(ds[1].line, Some(10));
        assert_eq!(ds[1].column, Some(15));
        assert_eq!(ds[1].message, "';' expected");
        assert!(ds[2].message.starts_with("Failed to execute goal"));
    }

    #[test]
    fn split_location_handles_line_and_col() {
        assert_eq!(
            split_location("src/main.rs:5:20"),
            Some(("src/main.rs".into(), 5, Some(20)))
        );
        assert_eq!(
            split_location("C:/x/y.rs:7"),
            Some(("C:/x/y.rs".into(), 7, None))
        );
        assert_eq!(split_location("no-location-here"), None);
    }

    #[tokio::test]
    async fn toolchain_tool_runs_and_reports_diagnostics() {
        use nebula_mcp_core::config::SecurityConfig;
        use nebula_mcp_core::security::EffectivePolicy;
        use nebula_mcp_core::Metrics;
        use tokio_util::sync::CancellationToken;

        // Use `sh` as a stand-in "cargo" so the test runs anywhere: it prints a
        // realistic rustc error to stderr and exits 1.
        let base = SecurityConfig {
            allowed_paths: vec!["/**".into()],
            allowed_commands: vec!["sh".into()],
            ..Default::default()
        };
        let policy = EffectivePolicy::build("toolchain.cargo", &base, None).unwrap();
        let ctx = ToolContext {
            policy: Arc::new(policy),
            working_dir: std::env::temp_dir(),
            cancel: CancellationToken::new(),
            metrics: Metrics::new(),
            config: Arc::new(Default::default()),
            request_id: "r".into(),
            progress: None,
        };
        let tool = ToolchainTool {
            eco: &ECOSYSTEMS[0],
        };
        let script =
            "printf 'error[E0308]: mismatched types\\n  --> src/main.rs:5:20\\n' >&2; exit 1";
        let result = tool
            .call(&ctx, json!({"program": "sh", "args": ["-c", script]}))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        let sc = result.structured_content.unwrap();
        assert_eq!(sc["diagnosticCounts"]["errors"], 1);
        assert_eq!(sc["diagnostics"][0]["code"], "E0308");
        assert_eq!(sc["diagnostics"][0]["file"], "src/main.rs");
        assert_eq!(sc["diagnostics"][0]["line"], 5);
    }
}
