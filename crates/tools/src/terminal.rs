//! Terminal tools: run a program the operator allowed, once or as an
//! interactive session.
//!
//! These run caller-chosen programs. The program must be in
//! `allowed_commands` and is matched on the file that will run; no shell is
//! involved and arguments are passed verbatim. What the program then does is
//! up to the program: it has the server user's privileges.

use std::sync::Arc;
use std::time::Duration;

use nebula_mcp_core::args::Args;
use nebula_mcp_core::fs::{CheckedPath, Kind};
use nebula_mcp_core::policy::Access;
use nebula_mcp_core::process::{Command, Exec, Output};
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::tool::Content;
use nebula_mcp_core::{Category, Effects, Result, Tool, ToolContext, ToolError, ToolOutput};
use serde_json::{json, Value};

use crate::common::{spec, tool, SpecExt};
use crate::sessions::{describe_exit, Chunk, Sessions};

const PROGRAM_HELP: &str =
    "Program to run: a name found on the server's PATH, or a path. It must be allowed by the \
     operator (allowed_commands).";
const ARGS_HELP: &str = "Arguments, passed verbatim as separate strings. There is no shell: \
                         quoting, pipes, globs and redirection are not interpreted.";
const CWD_HELP: &str =
    "Directory to run in, inside an allowed directory (default: the server's working directory).";
const ENV_HELP: &str = "Environment variables to set. The operator decides which names may be \
                        set (caller_env); the child otherwise gets a minimal environment without \
                        the server's secrets.";

fn effects() -> Effects {
    // Arbitrary execution: anything can happen, so clients are told the
    // worst. No gate fits; allowed_commands is the control.
    Effects::writes()
        .overwrites()
        .open_world()
        .exec(Exec::CallerChosen(&[]))
}

/// The `terminal` tools.
pub(crate) fn tools(sessions: &Arc<Sessions>) -> Vec<Arc<dyn Tool>> {
    let c = Category::Terminal;
    let command_schema = |with_stdin: bool| {
        let mut s = ObjectSchema::new()
            .string("program", PROGRAM_HELP, true)
            .string_array_max("args", ARGS_HELP, 1000, false)
            .string("cwd", CWD_HELP, false)
            .string_map("env", ENV_HELP, false);
        if with_stdin {
            s = s
                .string(
                    "stdin",
                    "Text written to the program's standard input, which is then closed.",
                    false,
                )
                .integer_min(
                    "timeoutSecs",
                    "Seconds before the program and everything it started are stopped (default \
                     and ceiling set by the operator).",
                    1,
                    false,
                );
        }
        s.build()
    };
    let id_schema =
        || ObjectSchema::new().string("sessionId", "Session id from terminal_session_open.", true);
    let (open, write, read, list, close) = (
        sessions.clone(),
        sessions.clone(),
        sessions.clone(),
        sessions.clone(),
        sessions.clone(),
    );
    vec![
        tool(
            spec(
                "terminal_run",
                c,
                "Run program",
                "Run an allowed program to completion and return its output and exit code. No \
                 shell is involved. The program and everything it starts are stopped at the \
                 timeout, on cancellation and when it exits.",
                command_schema(true),
                effects(),
            ),
            |ctx, args| Box::pin(run(ctx, args)),
        ),
        tool(
            spec(
                "terminal_session_open",
                c,
                "Open session",
                "Start an allowed program that stays running (a REPL, a server, a watcher) and \
                 return a session id. Write to it with terminal_session_write, read its output \
                 with terminal_session_read and stop it with terminal_session_close. Idle \
                 sessions are closed by the server.",
                command_schema(false),
                effects(),
            )
            .returns(
                ObjectSchema::open()
                    .string("sessionId", "Id for the other session tools.", true)
                    .nullable_integer("pid", "Process id of the program.", true)
                    .build(),
            ),
            move |ctx, args| {
                let sessions = open.clone();
                Box::pin(async move { session_open(ctx, &sessions, args).await })
            },
        ),
        tool(
            spec(
                "terminal_session_write",
                c,
                "Write to session",
                "Write text to a session's standard input. Include a trailing newline to submit \
                 a line.",
                id_schema()
                    .string("data", "Text to write, exactly as given.", true)
                    .build(),
                effects(),
            ),
            move |ctx, args| {
                let sessions = write.clone();
                Box::pin(async move { session_write(ctx, &sessions, args).await })
            },
        ),
        tool(
            spec(
                "terminal_session_read",
                c,
                "Read from session",
                "Return what a session has printed (standard output and error, in arrival \
                 order) since the last read, and whether it is still running. Output nobody \
                 reads is dropped oldest-first once the buffer is full.",
                id_schema()
                    .integer_range(
                        "waitMs",
                        "Wait up to this long for output when none is buffered (default 1000).",
                        0,
                        60_000,
                        false,
                    )
                    .integer_min(
                        "maxBytes",
                        "Most bytes to return (default and ceiling: the server's output limit).",
                        1,
                        false,
                    )
                    .build(),
                effects(),
            ),
            move |ctx, args| {
                let sessions = read.clone();
                Box::pin(async move { session_read(ctx, &sessions, args).await })
            },
        ),
        tool(
            spec(
                "terminal_session_list",
                c,
                "List sessions",
                "List the terminal sessions this client has open.",
                ObjectSchema::new().build(),
                Effects::read_only(),
            )
            .returns(
                ObjectSchema::open()
                    .object_array(
                        "sessions",
                        "Open sessions, oldest first.",
                        ObjectSchema::open()
                            .string("sessionId", "Session id.", true)
                            .string("program", "Program as it was requested.", true)
                            .nullable_integer("pid", "Process id while running.", true)
                            .boolean("running", "Whether the program is still running.", true)
                            .nullable_integer("exitCode", "Exit code once exited.", true)
                            .integer("ageSecs", "Seconds since it was opened.", true)
                            .integer("idleSecs", "Seconds since it was last used.", true)
                            .integer("bufferedBytes", "Unread output.", true),
                        true,
                    )
                    .build(),
            ),
            move |ctx, args| {
                let sessions = list.clone();
                Box::pin(async move { session_list(ctx, &sessions, args).await })
            },
        ),
        tool(
            spec(
                "terminal_session_close",
                c,
                "Close session",
                "Stop a session's program and everything it started, and return any output \
                 that was not read yet.",
                id_schema().build(),
                effects(),
            ),
            move |ctx, args| {
                let sessions = close.clone();
                Box::pin(async move { session_close(ctx, &sessions, args).await })
            },
        ),
    ]
}

/// Check `input` as a directory to run in.
async fn working_dir(ctx: &ToolContext, input: &str) -> Result<CheckedPath> {
    let input = input.to_string();
    ctx.fs()
        .blocking(move |fs| {
            let dir = fs.resolve(&input, Access::Read)?;
            match fs.metadata(&dir)?.kind {
                Kind::Dir => Ok(dir),
                _ => Err(ToolError::invalid(format!(
                    "cwd '{}' is not a directory",
                    dir.display()
                ))),
            }
        })
        .await
}

/// Build the command from `program`, `args`, `cwd` and `env`.
async fn command(ctx: &ToolContext, a: &Args<'_>) -> Result<Command> {
    let mut cmd = Command::caller(a.str("program")?)
        .args(a.opt_str_array("args")?)
        .caller_env(a.opt_string_map("env")?);
    if let Some(cwd) = a.opt_str("cwd")? {
        cmd = cmd.cwd(&working_dir(ctx, cwd).await?);
    }
    Ok(cmd)
}

async fn run(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let mut cmd = command(ctx, &a)
        .await?
        .timeout(ctx.timeout(a.opt_u64("timeoutSecs")?))
        .timeout_is_result();
    if let Some(stdin) = a.opt_str("stdin")? {
        cmd = cmd.stdin(stdin);
    }
    let output = ctx.run(cmd).await?;
    Ok(render_run("terminal_run", &output))
}

/// A finished command as text: stdout, then stderr, then a status line.
pub(crate) fn render_run(tool: &str, out: &Output) -> ToolOutput {
    let mut content = Vec::new();
    if !out.stdout.text.is_empty() {
        content.push(Content::Text(out.stdout.text.clone()));
    }
    if !out.stderr.text.is_empty() {
        content.push(Content::Text(format!("[stderr]\n{}", out.stderr.text)));
    }
    let secs = out.duration.as_secs_f64();
    let mut status = if out.timed_out {
        format!(
            "[{tool}: timed out after {secs:.1}s; the program and everything it started were \
             stopped. Output up to that point is above"
        )
    } else {
        format!("[{tool}: {} after {secs:.1}s", describe_exit(out.code))
    };
    for (name, stream) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        if stream.truncated {
            status.push_str(&format!(
                "; {name} was {} bytes and its middle was omitted",
                stream.total_bytes
            ));
        }
    }
    status.push(']');
    content.push(Content::Text(status));
    ToolOutput {
        content,
        structured: None,
    }
}

async fn session_open(ctx: &ToolContext, sessions: &Sessions, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let cmd = command(ctx, &a).await?;
    let (id, pid) = sessions.open(ctx, cmd)?;
    Ok(ToolOutput::json(json!({"sessionId": id, "pid": pid})))
}

async fn session_write(ctx: &ToolContext, sessions: &Sessions, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let data = a.str("data")?;
    sessions
        .write(ctx, a.str("sessionId")?, data.as_bytes())
        .await?;
    Ok(ToolOutput::text(format!(
        "[terminal_session_write: {} bytes written]",
        data.len()
    )))
}

fn render_chunk(tool: &str, chunk: Chunk) -> ToolOutput {
    let mut content = Vec::new();
    if !chunk.text.is_empty() {
        content.push(Content::Text(chunk.text));
    }
    let mut status = match chunk.exit {
        None => format!("[{tool}: the program is running"),
        Some(code) => format!("[{tool}: the program has exited ({})", describe_exit(code)),
    };
    if chunk.dropped > 0 {
        status.push_str(&format!(
            "; {} bytes of older output were dropped because the buffer was full",
            chunk.dropped
        ));
    }
    if chunk.remaining > 0 {
        status.push_str(&format!(
            "; {} more bytes are buffered, read again",
            chunk.remaining
        ));
    }
    status.push(']');
    content.push(Content::Text(status));
    ToolOutput {
        content,
        structured: None,
    }
}

async fn session_read(ctx: &ToolContext, sessions: &Sessions, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let wait = Duration::from_millis(a.u64_or("waitMs", 1000)?);
    let max = a
        .usize_or("maxBytes", ctx.max_output_bytes())?
        .min(ctx.max_output_bytes());
    let chunk = sessions.read(ctx, a.str("sessionId")?, wait, max).await?;
    Ok(render_chunk("terminal_session_read", chunk))
}

async fn session_list(ctx: &ToolContext, sessions: &Sessions, _args: Value) -> Result<ToolOutput> {
    let list: Vec<Value> = sessions
        .list(ctx)
        .await
        .into_iter()
        .map(|s| {
            json!({
                "sessionId": s.id,
                "program": s.program,
                "pid": s.pid,
                "running": s.exit.is_none(),
                "exitCode": s.exit.flatten(),
                "ageSecs": s.age.as_secs(),
                "idleSecs": s.idle.as_secs(),
                "bufferedBytes": s.buffered,
            })
        })
        .collect();
    Ok(ToolOutput::json(json!({"sessions": list})))
}

async fn session_close(ctx: &ToolContext, sessions: &Sessions, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let chunk = sessions
        .close(ctx, a.str("sessionId")?, ctx.max_output_bytes())
        .await?;
    Ok(render_chunk("terminal_session_close", chunk))
}

#[cfg(test)]
#[path = "terminal_tests.rs"]
mod tests;
