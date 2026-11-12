//! Process execution.
//!
//! Every process the server starts is started here. A [`Command`] can only be
//! built from a [`CheckedCommand`], so the program has always passed the
//! allowlist and is spawned by the absolute path the allowlist resolved.
//!
//! A call owns its whole process tree. The child is placed in a new process
//! group (a Job Object on Windows) and, however the call ends (exit, timeout,
//! cancellation, or the caller simply dropping the future), the entire group
//! is killed and reaped by a supervisor task that does not depend on the
//! caller being polled again.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};
use tokio_util::sync::CancellationToken;

use crate::error::ToolError;
use crate::policy::{CheckedCommand, CheckedPath, EnvRules};
use crate::progress::ProgressSink;

/// How long a process group is given to exit after SIGTERM before SIGKILL.
const TERMINATE_GRACE: Duration = Duration::from_secs(2);
/// How long to keep collecting output once the process tree has been killed.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
/// Interval between progress heartbeats for a running process.
const HEARTBEAT: Duration = Duration::from_secs(5);

#[cfg(unix)]
const SIGTERM: i32 = 15;

/// Variables kept when a caller asks for a cleared environment; without them
/// most programs cannot start at all.
const ESSENTIAL_VARIABLES: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SystemRoot",
    "SystemDrive",
    "USERPROFILE",
    "PATHEXT",
    "ComSpec",
    "windir",
];

/// A process to run. Built through [`crate::ToolContext::command`].
#[derive(Debug, Clone)]
pub struct Command {
    program: CheckedCommand,
    args: Vec<OsString>,
    cwd: PathBuf,
    env: Vec<(String, String)>,
    clear_env: bool,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    output_limit: usize,
    env_rules: Arc<EnvRules>,
}

impl Command {
    pub(crate) fn new(
        program: CheckedCommand,
        cwd: PathBuf,
        timeout: Duration,
        output_limit: usize,
        env_rules: Arc<EnvRules>,
    ) -> Self {
        Self {
            program,
            args: Vec::new(),
            cwd,
            env: Vec::new(),
            clear_env: false,
            stdin: None,
            timeout,
            output_limit,
            env_rules,
        }
    }

    /// Append one argument. Arguments are passed verbatim; no shell is
    /// involved.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Run in this directory instead of the working directory.
    #[must_use]
    pub fn cwd(mut self, dir: &CheckedPath) -> Self {
        self.cwd = dir.as_path().to_path_buf();
        self
    }

    /// Set a variable chosen by the tool itself (not by the caller).
    #[must_use]
    pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }

    /// Set variables supplied by the caller. Variables that change which code
    /// a program loads are refused.
    pub fn caller_env<I>(mut self, vars: I) -> Result<Self, ToolError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        for (name, value) in vars {
            self.env_rules.check_caller_variable(&name)?;
            if value.contains('\0') {
                return Err(ToolError::InvalidArguments(format!(
                    "the value of environment variable '{name}' contains a NUL byte"
                )));
            }
            self.env.push((name, value));
        }
        Ok(self)
    }

    /// Start from a nearly empty environment instead of the server's.
    #[must_use]
    pub fn clear_env(mut self, clear: bool) -> Self {
        self.clear_env = clear;
        self
    }

    /// Bytes to write to the process's standard input.
    #[must_use]
    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    /// Override the time limit (already clamped by the policy).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The time limit in force.
    #[must_use]
    pub fn time_limit(&self) -> Duration {
        self.timeout
    }

    /// `program arg arg ...` for display in results and logs.
    #[must_use]
    pub fn display(&self) -> String {
        let mut out = self.program.name().to_string();
        for arg in &self.args {
            out.push(' ');
            out.push_str(&arg.to_string_lossy());
        }
        out
    }

    /// The name the caller used for the program.
    #[must_use]
    pub fn program_name(&self) -> &str {
        self.program.name()
    }

    fn spawn(&self, piped_stdin: bool) -> Result<Box<dyn ChildWrapper>, ToolError> {
        let mut wrap = CommandWrap::with_new(self.program.program(), |c| {
            c.args(&self.args)
                .current_dir(&self.cwd)
                .stdin(if piped_stdin {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            c.env_clear();
            for (name, value) in std::env::vars_os() {
                let keep = match name.to_str() {
                    Some(n) if self.clear_env => {
                        ESSENTIAL_VARIABLES.iter().any(|e| e.eq_ignore_ascii_case(n))
                    }
                    Some(n) => !self.env_rules.is_scrubbed(n),
                    None => !self.clear_env,
                };
                if keep {
                    c.env(name, value);
                }
            }
            for (name, value) in &self.env {
                c.env(name, value);
            }
        });
        #[cfg(unix)]
        wrap.wrap(process_wrap::tokio::ProcessGroup::leader());
        #[cfg(windows)]
        wrap.wrap(process_wrap::tokio::JobObject);
        wrap.wrap(KillOnDrop);
        wrap.spawn().map_err(|e| {
            ToolError::Io(format!(
                "starting '{}' in {}: {e}",
                self.program.name(),
                self.cwd.display()
            ))
        })
    }
}

/// What a finished process produced.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    /// Exit code, or `None` if the process was killed.
    pub exit_code: Option<i32>,
    /// Captured standard output (lossy UTF-8; the middle is dropped when the
    /// output exceeds the limit).
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Whether part of standard output was dropped.
    pub stdout_truncated: bool,
    /// Whether part of standard error was dropped.
    pub stderr_truncated: bool,
    /// Whether the process was killed because it ran out of time.
    pub timed_out: bool,
    /// Wall-clock time.
    pub duration: Duration,
}

impl ExecOutput {
    /// Whether the process ran to completion and exited with status 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }

    /// Turn a failure into an error that carries the end of the process's
    /// error output.
    pub fn require_success(self, what: &str) -> Result<Self, ToolError> {
        if self.success() {
            return Ok(self);
        }
        let detail = if self.stderr.trim().is_empty() {
            self.stdout.trim()
        } else {
            self.stderr.trim()
        };
        let status = if self.timed_out {
            "timed out".to_string()
        } else {
            match self.exit_code {
                Some(code) => format!("exited with status {code}"),
                None => "was killed".to_string(),
            }
        };
        Err(ToolError::Execution(format!(
            "{what} {status}: {}",
            tail_chars(detail, 2000)
        )))
    }
}

/// The last `max` bytes of `text`, cut on a character boundary.
#[must_use]
pub fn tail_chars(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// Refuse a value that an external program would read as an option.
///
/// Typed tools pass caller strings (a branch, a remote, an image name) as
/// positional arguments. Without a shell there is no shell injection, but a
/// value such as `--output=/etc/x` would still be taken as an option.
pub fn positional<'a>(value: &'a str, what: &str) -> Result<&'a str, ToolError> {
    if value.is_empty() {
        return Err(ToolError::InvalidArguments(format!("{what} is empty")));
    }
    if value.starts_with('-') {
        return Err(ToolError::InvalidArguments(format!(
            "{what} '{value}' starts with '-', which the program would read as an option"
        )));
    }
    if value.contains('\0') {
        return Err(ToolError::InvalidArguments(format!(
            "{what} contains a NUL byte"
        )));
    }
    Ok(value)
}

/// Bounded capture of one output stream: the first half of the budget is kept
/// from the start and the rest from the end, because the outcome of a build
/// or test run is at the end.
struct Capture {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    head_limit: usize,
    tail_limit: usize,
    total: u64,
}

impl Capture {
    fn new(limit: usize) -> Self {
        let head_limit = limit / 2;
        Self {
            head: Vec::new(),
            tail: VecDeque::new(),
            head_limit,
            tail_limit: limit - head_limit,
            total: 0,
        }
    }

    fn push(&mut self, mut bytes: &[u8]) {
        self.total += bytes.len() as u64;
        if self.head.len() < self.head_limit {
            let take = (self.head_limit - self.head.len()).min(bytes.len());
            self.head.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
        if bytes.len() >= self.tail_limit {
            self.tail.clear();
            self.tail
                .extend(&bytes[bytes.len() - self.tail_limit..]);
        } else {
            let overflow = (self.tail.len() + bytes.len()).saturating_sub(self.tail_limit);
            self.tail.drain(..overflow);
            self.tail.extend(bytes);
        }
    }

    fn finish(&self) -> (String, bool) {
        let kept = (self.head.len() + self.tail.len()) as u64;
        let omitted = self.total - kept;
        let tail: Vec<u8> = self.tail.iter().copied().collect();
        if omitted == 0 {
            let mut all = self.head.clone();
            all.extend_from_slice(&tail);
            (String::from_utf8_lossy(&all).into_owned(), false)
        } else {
            (
                format!(
                    "{}\n[... {omitted} bytes omitted ...]\n{}",
                    String::from_utf8_lossy(&self.head),
                    String::from_utf8_lossy(&tail)
                ),
                true,
            )
        }
    }
}

async fn capture<R: AsyncRead + Unpin>(reader: Option<R>, sink: Arc<Mutex<Capture>>) {
    let Some(mut reader) = reader else { return };
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => sink.lock().push(&buf[..n]),
        }
    }
}

/// Aborts a task when dropped, so helper tasks cannot outlive their owner.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum Ending {
    Exited(std::io::Result<std::process::ExitStatus>),
    TimedOut,
    Cancelled,
}

/// Run a command to completion under its time limit.
///
/// Returns `Ok` with `timed_out` set when the limit is hit, so the caller
/// still gets the output produced so far, and [`ToolError::Cancelled`] when
/// `cancel` fires. In every case the process tree is gone when this returns.
/// Dropping the returned future also kills the tree.
pub async fn run(
    command: Command,
    cancel: &CancellationToken,
    progress: Option<ProgressSink>,
) -> Result<ExecOutput, ToolError> {
    let stop = cancel.child_token();
    // If this future is dropped, the guard tells the supervisor to clean up.
    let guard = stop.clone().drop_guard();
    let supervisor = tokio::spawn(supervise(command, stop, progress));
    let result = supervisor
        .await
        .map_err(|e| ToolError::Internal(format!("process supervisor failed: {e}")));
    drop(guard.disarm());
    result?
}

async fn supervise(
    command: Command,
    stop: CancellationToken,
    progress: Option<ProgressSink>,
) -> Result<ExecOutput, ToolError> {
    let started = Instant::now();
    let mut child = command.spawn(command.stdin.is_some())?;

    let stdout = Arc::new(Mutex::new(Capture::new(command.output_limit)));
    let stderr = Arc::new(Mutex::new(Capture::new(command.output_limit)));
    let mut readers = vec![
        tokio::spawn(capture(child.stdout().take(), stdout.clone())),
        tokio::spawn(capture(child.stderr().take(), stderr.clone())),
    ];
    // Fed from its own task: a child that never reads its input must not be
    // able to stall the supervisor past the time limit.
    let _feeder = command.stdin.clone().and_then(|data| {
        child.stdin().take().map(|mut sink| {
            AbortOnDrop(tokio::spawn(async move {
                let _ = sink.write_all(&data).await;
                let _ = sink.shutdown().await;
            }))
        })
    });
    let _heartbeat = progress.map(|sink| {
        let name = command.program.name().to_string();
        sink.report(0.0, None, Some(format!("started {name}")));
        AbortOnDrop(tokio::spawn(async move {
            let mut ticks = 0.0;
            loop {
                tokio::time::sleep(HEARTBEAT).await;
                ticks += 1.0;
                sink.report(
                    ticks,
                    None,
                    Some(format!("{name} running for {}s", started.elapsed().as_secs())),
                );
            }
        }))
    });

    let ending = tokio::select! {
        biased;
        () = stop.cancelled() => Ending::Cancelled,
        () = tokio::time::sleep(command.timeout) => Ending::TimedOut,
        status = child.wait() => Ending::Exited(status),
    };

    // Nothing this call started may outlive it, including processes the
    // program left running in the background.
    kill_tree(child.as_mut(), !matches!(ending, Ending::Exited(_))).await;

    // The pipes close once every process holding them is gone. Give the
    // readers a moment, then stop waiting.
    let drained = async {
        for reader in &mut readers {
            let _ = reader.await;
        }
    };
    if tokio::time::timeout(DRAIN_GRACE, drained).await.is_err() {
        for reader in &readers {
            reader.abort();
        }
    }

    let (stdout, stdout_truncated) = stdout.lock().finish();
    let (stderr, stderr_truncated) = stderr.lock().finish();
    let duration = started.elapsed();
    match ending {
        Ending::Cancelled => Err(ToolError::Cancelled),
        Ending::TimedOut => Ok(ExecOutput {
            exit_code: None,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            timed_out: true,
            duration,
        }),
        Ending::Exited(Ok(status)) => Ok(ExecOutput {
            exit_code: status.code(),
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            timed_out: false,
            duration,
        }),
        Ending::Exited(Err(e)) => Err(ToolError::Io(format!(
            "waiting for '{}': {e}",
            command.program.name()
        ))),
    }
}

/// Kill a child's whole process group and reap it. With `graceful`, the group
/// first gets SIGTERM and a short time to exit.
pub(crate) async fn kill_tree(child: &mut dyn ChildWrapper, graceful: bool) {
    #[cfg(unix)]
    if graceful && child.signal(SIGTERM).is_ok() {
        let _ = tokio::time::timeout(TERMINATE_GRACE, child.wait()).await;
    }
    #[cfg(not(unix))]
    let _ = graceful;
    // SIGKILL to the group (TerminateJobObject on Windows). An error only
    // means there was nothing left to kill.
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
}

/// A long-lived process with piped standard streams, for interactive
/// sessions. Dropping it kills the process tree.
pub struct ChildProcess {
    child: Option<Box<dyn ChildWrapper>>,
    name: String,
}

impl ChildProcess {
    /// Start `command` with all three standard streams piped.
    pub fn spawn(command: &Command) -> Result<Self, ToolError> {
        Ok(Self {
            child: Some(command.spawn(true)?),
            name: command.program.name().to_string(),
        })
    }

    fn inner(&mut self) -> &mut dyn ChildWrapper {
        self.child
            .as_mut()
            .expect("child is present until drop")
            .as_mut()
    }

    /// The name of the program that was started.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Operating-system process id, while the process is running.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.child.as_ref().and_then(|c| c.id())
    }

    /// Take the standard input handle (once).
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.inner().stdin().take()
    }

    /// Take the standard output handle (once).
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.inner().stdout().take()
    }

    /// Take the standard error handle (once).
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.inner().stderr().take()
    }

    /// Exit code if the process has exited.
    pub fn try_exit_code(&mut self) -> Option<Option<i32>> {
        self.inner().try_wait().ok().flatten().map(|s| s.code())
    }

    /// Kill the whole process tree and wait for it to be gone.
    pub async fn kill_tree(&mut self) {
        kill_tree(self.inner(), true).await;
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        // Reaping needs the runtime; without one the kill signal is still
        // sent synchronously.
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
                });
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::policy::CommandRules;

    fn command(program: &str, args: &[&str], timeout: Duration, limit: usize) -> Command {
        let rules = CommandRules::build(&["*".to_string()], std::env::var_os("PATH"));
        let cwd = std::env::temp_dir();
        let checked = rules.resolve(program, &cwd).unwrap();
        let env = crate::policy::Policy::resolve(
            &crate::config::Config::default(),
            "t",
            &crate::policy::PolicyEnv::current(cwd.clone(), None),
        )
        .unwrap()
        .env()
        .clone();
        Command::new(checked, cwd, timeout, limit, env).args(args.iter().copied())
    }

    fn sh(script: &str, timeout: Duration) -> Command {
        command("sh", &["-c", script], timeout, 64 * 1024)
    }

    fn alive(pid: &str) -> bool {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
            || std::process::Command::new("kill")
                .args(["-0", pid])
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
    }

    async fn wait_until_dead(pid: &str) -> bool {
        for _ in 0..50 {
            if !alive(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    #[tokio::test]
    async fn runs_and_captures_output_and_status() {
        let out = run(sh("echo out; echo err >&2; exit 3", Duration::from_secs(10)), &CancellationToken::new(), None)
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(3));
        assert_eq!(out.stdout, "out\n");
        assert_eq!(out.stderr, "err\n");
        assert!(!out.success());
        assert!(out.clone().require_success("sh").is_err());
    }

    #[tokio::test]
    async fn feeds_stdin() {
        let cmd = command("cat", &[], Duration::from_secs(10), 1024).stdin("piped-input");
        let out = run(cmd, &CancellationToken::new(), None).await.unwrap();
        assert_eq!(out.stdout, "piped-input");
    }

    #[tokio::test]
    async fn keeps_the_head_and_the_tail_of_long_output() {
        let cmd = command("sh", &["-c", "echo START; seq 1 20000; echo END"], Duration::from_secs(20), 400);
        let out = run(cmd, &CancellationToken::new(), None).await.unwrap();
        assert!(out.stdout_truncated);
        assert!(out.stdout.starts_with("START\n"), "{}", &out.stdout[..40]);
        assert!(out.stdout.ends_with("END\n"));
        assert!(out.stdout.contains("bytes omitted"));
        assert!(out.stdout.len() < 600);
    }

    #[tokio::test]
    async fn timeout_kills_the_whole_tree_and_returns_partial_output() {
        let script = "sleep 300 & echo $! ; echo partial; wait";
        let started = Instant::now();
        let out = run(sh(script, Duration::from_millis(600)), &CancellationToken::new(), None)
            .await
            .unwrap();
        assert!(out.timed_out);
        assert!(started.elapsed() < Duration::from_secs(8));
        assert!(out.stdout.contains("partial"));
        let pid = out.stdout.lines().next().unwrap().trim().to_string();
        assert!(wait_until_dead(&pid).await, "grandchild {pid} survived the timeout");
    }

    #[tokio::test]
    async fn cancellation_kills_the_whole_tree() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!("sleep 300 & echo $! > {}; wait", pidfile.display());
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            trigger.cancel();
        });
        let err = run(sh(&script, Duration::from_secs(60)), &cancel, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Cancelled));
        let pid = std::fs::read_to_string(&pidfile).unwrap().trim().to_string();
        assert!(wait_until_dead(&pid).await, "grandchild {pid} survived cancellation");
    }

    #[tokio::test]
    async fn dropping_the_future_kills_the_whole_tree() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!("sleep 300 & echo $! > {}; wait", pidfile.display());
        let cancel = CancellationToken::new();
        let fut = run(sh(&script, Duration::from_secs(60)), &cancel, None);
        // The caller gives up without cancelling, as an outer timeout would.
        let _ = tokio::time::timeout(Duration::from_millis(500), fut).await;
        let pid = std::fs::read_to_string(&pidfile).unwrap().trim().to_string();
        assert!(wait_until_dead(&pid).await, "grandchild {pid} survived the drop");
    }

    #[tokio::test]
    async fn a_background_process_does_not_outlive_or_stall_the_call() {
        // The program exits at once but leaves a child holding the output pipe.
        let started = Instant::now();
        let out = run(sh("sleep 300 & echo $!", Duration::from_secs(60)), &CancellationToken::new(), None)
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert!(started.elapsed() < Duration::from_secs(8));
        let pid = out.stdout.trim().to_string();
        assert!(wait_until_dead(&pid).await, "background process {pid} survived");
    }

    #[tokio::test]
    async fn a_child_that_ignores_sigterm_is_killed() {
        let script = "trap '' TERM; echo ready; while true; do sleep 1; done";
        let started = Instant::now();
        let out = run(sh(script, Duration::from_millis(500)), &CancellationToken::new(), None)
            .await
            .unwrap();
        assert!(out.timed_out);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn a_child_that_never_reads_stdin_still_times_out() {
        let big = vec![b'x'; 4 * 1024 * 1024];
        let cmd = sh("sleep 300", Duration::from_millis(500)).stdin(big);
        let started = Instant::now();
        let out = run(cmd, &CancellationToken::new(), None).await.unwrap();
        assert!(out.timed_out);
        assert!(started.elapsed() < Duration::from_secs(8));
    }

    #[tokio::test]
    async fn credentials_in_the_server_environment_do_not_reach_children() {
        // Set for this process only; the scrub list must keep it from the child.
        std::env::set_var("NEBULA_MCP_TEST_SECRET_TOKEN", "hunter2");
        std::env::set_var("NEBULA_VISIBLE_SETTING", "shown");
        let out = run(sh("env", Duration::from_secs(10)), &CancellationToken::new(), None)
            .await
            .unwrap();
        assert!(!out.stdout.contains("hunter2"), "secret leaked to the child");
        assert!(out.stdout.contains("NEBULA_VISIBLE_SETTING=shown"));

        let cleared = sh("env", Duration::from_secs(10)).clear_env(true).env("ONLY", "this");
        let out = run(cleared, &CancellationToken::new(), None).await.unwrap();
        assert!(out.stdout.contains("ONLY=this"));
        assert!(!out.stdout.contains("NEBULA_VISIBLE_SETTING"));
    }

    #[tokio::test]
    async fn loader_variables_from_a_caller_are_refused() {
        let cmd = sh("true", Duration::from_secs(5));
        assert!(cmd
            .clone()
            .caller_env([("LD_PRELOAD".to_string(), "/tmp/x.so".to_string())])
            .is_err());
        assert!(cmd
            .caller_env([("RUST_BACKTRACE".to_string(), "1".to_string())])
            .is_ok());
    }

    #[test]
    fn positional_refuses_option_like_values() {
        assert!(positional("main", "branch").is_ok());
        assert!(positional("--output=/etc/x", "revision").is_err());
        assert!(positional("-v", "image").is_err());
        assert!(positional("", "remote").is_err());
    }

    #[test]
    fn tail_chars_cuts_on_a_boundary() {
        let s = "aé".repeat(100);
        let t = tail_chars(&s, 51);
        assert!(t.len() <= 51);
        assert!(s.ends_with(t));
    }
}
