//! Process execution.
//!
//! [`Spawner`] is the only way tools start processes. It decides which
//! executable runs (the policy's allowlist for caller-chosen programs, the
//! tool's declared programs otherwise), builds the child's environment from
//! the policy's allowlist, and owns the whole process tree for the lifetime
//! of the call:
//!
//! * the child leads its own process group (Unix) or job object (Windows);
//! * cancellation and timeout terminate the group, then kill it;
//! * when the leader exits, anything it left running is killed;
//! * dropping the future (a client disconnect, the runtime ceiling) kills
//!   the group synchronously, so no code path leaves processes behind.
//!
//! Commands never go through a shell; arguments are passed verbatim.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::config::SandboxMode;
use crate::context::ProgressSink;
use crate::error::{Result, ToolError};
use crate::fs::CheckedPath;
use crate::policy::{resolve_trusted_program, Policy};

/// Time a process group gets between the polite signal and the kill.
const TERMINATE_GRACE: Duration = Duration::from_secs(2);
/// Time allowed for pipes to drain once the tree has been killed.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
/// Interval between progress heartbeats for a running command.
const HEARTBEAT: Duration = Duration::from_secs(5);

/// Whether this build can confine child processes with an operating-system
/// mechanism on the current platform. While it cannot, `sandbox.mode =
/// "require"` refuses to start anything rather than run it unconfined.
pub const CONFINEMENT_AVAILABLE: bool = false;

/// What programs a tool may run. Declared in the tool's metadata and
/// enforced here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exec {
    /// The tool runs no programs.
    None,
    /// The tool runs only these programs, with arguments it builds itself.
    Programs(&'static [&'static str]),
    /// The tool runs a program the caller names, subject to
    /// `allowed_commands`. It may also run the listed fixed programs.
    CallerChosen(&'static [&'static str]),
}

/// Which program a command runs.
#[derive(Debug, Clone)]
enum Program {
    Typed(&'static str),
    Caller(String),
}

/// A process to run. Built by tools, executed by [`Spawner`].
#[derive(Debug, Clone)]
pub struct Command {
    program: Program,
    args: Vec<OsString>,
    cwd: Option<CheckedPath>,
    env: Vec<(String, String)>,
    caller_env: Vec<(String, String)>,
    pass_env: Vec<String>,
    stdin: Option<Vec<u8>>,
    timeout: Option<Duration>,
    max_output: Option<usize>,
    timeout_is_result: bool,
}

impl Command {
    fn new(program: Program) -> Self {
        Self {
            program,
            args: Vec::new(),
            cwd: None,
            env: Vec::new(),
            caller_env: Vec::new(),
            pass_env: Vec::new(),
            stdin: None,
            timeout: None,
            max_output: None,
            timeout_is_result: false,
        }
    }

    /// A program the tool itself chose. It must be one the tool declared.
    #[must_use]
    pub fn typed(program: &'static str) -> Self {
        Self::new(Program::Typed(program))
    }

    /// A program the caller named; checked against `allowed_commands`.
    #[must_use]
    pub fn caller(program: impl Into<String>) -> Self {
        Self::new(Program::Caller(program.into()))
    }

    /// Append one argument, passed verbatim.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append arguments, passed verbatim.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Append a policy-checked path as an argument.
    #[must_use]
    pub fn arg_path(mut self, path: &CheckedPath) -> Self {
        self.args.push(path.abs().into_os_string());
        self
    }

    /// Append `prefix` immediately followed by a policy-checked path, for
    /// options of the form `--file=<path>`.
    #[must_use]
    pub fn arg_prefixed_path(mut self, prefix: &str, path: &CheckedPath) -> Self {
        let mut arg = OsString::from(prefix);
        arg.push(path.abs());
        self.args.push(arg);
        self
    }

    /// Run in a policy-checked directory instead of the workspace root.
    #[must_use]
    pub fn cwd(mut self, dir: &CheckedPath) -> Self {
        self.cwd = Some(dir.clone());
        self
    }

    /// Set a variable chosen by the tool (not by the caller).
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Set variables supplied by the caller. Each name must be permitted by
    /// `[security] caller_env`.
    #[must_use]
    pub fn caller_env(mut self, vars: impl IntoIterator<Item = (String, String)>) -> Self {
        self.caller_env.extend(vars);
        self
    }

    /// Pass one of the server's own variables to the child even though the
    /// environment allowlist would drop it. Only honoured for typed programs.
    #[must_use]
    pub fn pass_env(mut self, name: impl Into<String>) -> Self {
        self.pass_env.push(name.into());
        self
    }

    /// Bytes written to the child's stdin, which is then closed.
    #[must_use]
    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(bytes.into());
        self
    }

    /// Timeout for the whole run (clamped to the policy ceiling).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Cap captured bytes per stream (never above the policy limit).
    #[must_use]
    pub fn max_output(mut self, bytes: usize) -> Self {
        self.max_output = Some(bytes);
        self
    }

    /// Return the partial output with `timed_out = true` instead of a
    /// [`ToolError::Timeout`] when the command runs out of time.
    #[must_use]
    pub fn timeout_is_result(mut self) -> Self {
        self.timeout_is_result = true;
        self
    }

    /// The program as the tool wrote it, for messages.
    #[must_use]
    pub fn program_label(&self) -> String {
        match &self.program {
            Program::Typed(p) => (*p).to_string(),
            Program::Caller(p) => p.clone(),
        }
    }
}

/// One captured output stream. When the stream was longer than the limit the
/// first and last parts are kept, because failures are usually at the end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Captured {
    /// Captured text (lossy UTF-8), with a marker where bytes were dropped.
    pub text: String,
    /// Whether bytes were dropped.
    pub truncated: bool,
    /// Bytes the process wrote in total.
    pub total_bytes: u64,
}

/// Result of a finished command.
#[derive(Debug, Clone)]
pub struct Output {
    /// Exit code; `None` when the process was killed by a signal or timed out.
    pub code: Option<i32>,
    /// Captured stdout.
    pub stdout: Captured,
    /// Captured stderr.
    pub stderr: Captured,
    /// Wall-clock duration.
    pub duration: Duration,
    /// Whether the run was cut by its timeout (only with
    /// [`Command::timeout_is_result`]).
    pub timed_out: bool,
}

impl Output {
    /// Whether the process exited with code 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Turn a non-zero exit into [`ToolError::Execution`] carrying the end
    /// of stderr (or stdout).
    pub fn check(self, what: &str) -> Result<Output> {
        if self.success() {
            return Ok(self);
        }
        let detail = if self.stderr.text.trim().is_empty() {
            self.stdout.text.trim()
        } else {
            self.stderr.text.trim()
        };
        let code = self
            .code
            .map_or_else(|| "a signal".to_string(), |c| format!("code {c}"));
        Err(ToolError::Execution(format!(
            "{what} exited with {code}: {}",
            tail_chars(detail, 2000)
        )))
    }
}

/// The last `max` characters of `s`, on a character boundary.
fn tail_chars(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    let tail: String = s.chars().skip(count - max).collect();
    format!("… {tail}")
}

/// Keeps the head and the tail of a byte stream within a fixed budget.
struct HeadTail {
    head: Vec<u8>,
    tail: std::collections::VecDeque<u8>,
    head_cap: usize,
    tail_cap: usize,
    total: u64,
}

impl HeadTail {
    fn new(limit: usize) -> Self {
        let head_cap = limit / 2;
        Self {
            head: Vec::new(),
            tail: std::collections::VecDeque::new(),
            head_cap,
            tail_cap: limit - head_cap,
            total: 0,
        }
    }

    fn push(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.head.len() < self.head_cap {
            let take = (self.head_cap - self.head.len()).min(data.len());
            self.head.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        if data.is_empty() || self.tail_cap == 0 {
            return;
        }
        if data.len() >= self.tail_cap {
            self.tail.clear();
            self.tail.extend(&data[data.len() - self.tail_cap..]);
            return;
        }
        let overflow = (self.tail.len() + data.len()).saturating_sub(self.tail_cap);
        self.tail.drain(..overflow);
        self.tail.extend(data);
    }

    fn finish(self) -> Captured {
        let kept = (self.head.len() + self.tail.len()) as u64;
        let dropped = self.total - kept;
        let tail: Vec<u8> = self.tail.into_iter().collect();
        let text = if dropped == 0 {
            let mut all = self.head;
            all.extend_from_slice(&tail);
            String::from_utf8_lossy(&all).into_owned()
        } else {
            format!(
                "{}\n… [{dropped} bytes omitted] …\n{}",
                String::from_utf8_lossy(&self.head),
                String::from_utf8_lossy(&tail)
            )
        };
        Captured {
            text,
            truncated: dropped > 0,
            total_bytes: self.total,
        }
    }
}

/// Process capability bound to one tool call.
#[derive(Clone)]
pub struct Spawner {
    policy: Arc<Policy>,
    exec: Exec,
    working_dir: PathBuf,
    cancel: CancellationToken,
    progress: Option<ProgressSink>,
}

impl std::fmt::Debug for Spawner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spawner")
            .field("tool", &self.policy.tool())
            .field("exec", &self.exec)
            .finish_non_exhaustive()
    }
}

impl Spawner {
    /// Create a spawner for a call.
    #[must_use]
    pub fn new(
        policy: Arc<Policy>,
        exec: Exec,
        working_dir: PathBuf,
        cancel: CancellationToken,
        progress: Option<ProgressSink>,
    ) -> Self {
        Self {
            policy,
            exec,
            working_dir,
            cancel,
            progress,
        }
    }

    /// Decide which executable `command` runs, or refuse.
    pub fn resolve(&self, command: &Command) -> Result<PathBuf> {
        let cwd = self.cwd_of(command);
        match (&command.program, self.exec) {
            (Program::Typed(name), Exec::Programs(list) | Exec::CallerChosen(list))
                if list.contains(name) =>
            {
                resolve_trusted_program(name, self.policy.paths())
            }
            (Program::Typed(name), _) => Err(ToolError::Internal(format!(
                "tool '{}' ran '{name}' without declaring it",
                self.policy.tool()
            ))),
            (Program::Caller(requested), Exec::CallerChosen(_)) => self
                .policy
                .commands()
                .authorize(requested, &cwd, self.policy.paths()),
            (Program::Caller(_), _) => Err(ToolError::Internal(format!(
                "tool '{}' ran a caller-chosen program without declaring it",
                self.policy.tool()
            ))),
        }
    }

    /// Whether a typed program is installed (for capability reporting).
    #[must_use]
    pub fn available(&self, program: &'static str) -> bool {
        resolve_trusted_program(program, self.policy.paths()).is_ok()
    }

    fn cwd_of(&self, command: &Command) -> PathBuf {
        command
            .cwd
            .as_ref()
            .map_or_else(|| self.working_dir.clone(), CheckedPath::abs)
    }

    fn build(&self, command: &Command) -> Result<(tokio::process::Command, PathBuf)> {
        if self.policy.sandbox().mode == SandboxMode::Require && !CONFINEMENT_AVAILABLE {
            return Err(ToolError::PermissionDenied(
                "[security.sandbox] mode = \"require\" is set, and this build cannot confine \
                 processes on this platform, so no program is started. The operator can set \
                 mode = \"off\" to run programs unconfined."
                    .to_string(),
            ));
        }
        let executable = self.resolve(command)?;
        let mut cmd = tokio::process::Command::new(&executable);
        cmd.args(&command.args)
            .current_dir(self.cwd_of(command))
            .env_clear()
            .envs(self.policy.env().base_env());
        if matches!(command.program, Program::Typed(_)) {
            for name in &command.pass_env {
                if let Some(value) = std::env::var_os(name) {
                    cmd.env(name, value);
                }
            }
        }
        for (k, v) in &command.env {
            cmd.env(k, v);
        }
        for (k, v) in &command.caller_env {
            if !self.policy.env().caller_may_set(k) {
                return Err(ToolError::PermissionDenied(format!(
                    "setting environment variable '{k}' is not permitted. The operator can allow \
                     it with [security] caller_env = [\"{k}\"]."
                )));
            }
            if v.contains('\0') {
                return Err(ToolError::invalid(format!(
                    "environment variable '{k}' contains NUL"
                )));
            }
            cmd.env(k, v);
        }
        if command
            .args
            .iter()
            .any(|a| a.to_string_lossy().contains('\0'))
        {
            return Err(ToolError::invalid("arguments must not contain NUL"));
        }
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        Ok((cmd, executable))
    }

    /// Run a command to completion and capture its output.
    pub async fn run(&self, command: Command) -> Result<Output> {
        if self.cancel.is_cancelled() {
            return Err(ToolError::Cancelled);
        }
        let label = command.program_label();
        let (mut cmd, executable) = self.build(&command)?;
        cmd.stdin(if command.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let timeout = command
            .timeout
            .unwrap_or_else(|| self.policy.timeout())
            .min(self.policy.max_runtime());
        let limit = command
            .max_output
            .unwrap_or(usize::MAX)
            .min(self.policy.max_output_bytes());

        let started = Instant::now();
        let mut tree = Tree::spawn(cmd).map_err(|e| spawn_error(&label, &executable, &e))?;
        if let Some(p) = &self.progress {
            p.report(0.0, None, Some(format!("started {label}")));
        }

        let mut stdin = tree.take_stdin();
        let stdin_data = command.stdin.unwrap_or_default();
        let write_stdin = async {
            if let Some(mut pipe) = stdin.take() {
                // A child that exits without reading closes the pipe; that
                // is its business, not an error.
                let _ = pipe.write_all(&stdin_data).await;
                let _ = pipe.shutdown().await;
            }
        };
        tokio::pin!(write_stdin);
        let mut stdin_done = false;

        let mut out = tree.take_stdout();
        let mut err = tree.take_stderr();
        let mut out_buf = HeadTail::new(limit);
        let mut err_buf = HeadTail::new(limit);
        let mut out_open = out.is_some();
        let mut err_open = err.is_some();
        let mut scratch_out = vec![0u8; 16 * 1024];
        let mut scratch_err = vec![0u8; 16 * 1024];

        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        let mut heartbeat =
            tokio::time::interval_at(tokio::time::Instant::now() + HEARTBEAT, HEARTBEAT);
        let mut beats = 0.0_f64;

        #[derive(PartialEq)]
        enum End {
            Exited,
            Cancelled,
            TimedOut,
        }
        let mut status: Option<std::process::ExitStatus> = None;
        // Set when the leader has exited but something outside its group
        // still holds a pipe open; the output read so far is returned.
        let mut pipes_abandoned = false;
        let end = loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => break End::Cancelled,
                () = &mut deadline => {
                    if status.is_some() {
                        pipes_abandoned = true;
                        break End::Exited;
                    }
                    break End::TimedOut;
                },
                () = &mut write_stdin, if !stdin_done => stdin_done = true,
                n = read_some(&mut out, &mut scratch_out), if out_open => match n {
                    Some(n) => out_buf.push(&scratch_out[..n]),
                    None => out_open = false,
                },
                n = read_some(&mut err, &mut scratch_err), if err_open => match n {
                    Some(n) => err_buf.push(&scratch_err[..n]),
                    None => err_open = false,
                },
                waited = tree.wait_leader(), if status.is_none() => match waited {
                    Ok(s) => {
                        status = Some(s);
                        // The group died with its leader, which closes the
                        // pipes. A process that left the group can keep one
                        // open, so the wait for them is bounded.
                        deadline
                            .as_mut()
                            .reset(tokio::time::Instant::now() + DRAIN_GRACE);
                    }
                    Err(e) => {
                        tree.kill_all();
                        return Err(ToolError::Io(format!("waiting for {label}: {e}")));
                    }
                },
                _ = heartbeat.tick(), if self.progress.is_some() => {
                    beats += 1.0;
                    if let Some(p) = &self.progress {
                        p.report(beats, None, Some(format!(
                            "{label} running for {}s", started.elapsed().as_secs()
                        )));
                    }
                }
            }
            if status.is_some() && !out_open && !err_open {
                break End::Exited;
            }
        };

        if end != End::Exited {
            tree.terminate(TERMINATE_GRACE).await;
        }
        // Collect what is already in the pipes, but never wait on a pipe
        // held open by something that escaped the group.
        if !pipes_abandoned {
            let drain = async {
                while out_open || err_open {
                    tokio::select! {
                        n = read_some(&mut out, &mut scratch_out), if out_open => match n {
                            Some(n) => out_buf.push(&scratch_out[..n]),
                            None => out_open = false,
                        },
                        n = read_some(&mut err, &mut scratch_err), if err_open => match n {
                            Some(n) => err_buf.push(&scratch_err[..n]),
                            None => err_open = false,
                        },
                    }
                }
            };
            let _ = tokio::time::timeout(DRAIN_GRACE, drain).await;
        }
        tree.finish();

        let output = Output {
            code: status.and_then(|s| s.code()),
            stdout: out_buf.finish(),
            stderr: err_buf.finish(),
            duration: started.elapsed(),
            timed_out: end == End::TimedOut,
        };
        match end {
            End::Exited => Ok(output),
            End::Cancelled => Err(ToolError::Cancelled),
            End::TimedOut if command.timeout_is_result => Ok(Output {
                code: None,
                ..output
            }),
            End::TimedOut => Err(ToolError::Timeout(timeout)),
        }
    }

    /// Start a long-lived process with piped stdio. The returned [`Child`]
    /// owns the process tree and kills it when dropped.
    pub fn spawn(&self, command: Command) -> Result<Child> {
        if self.cancel.is_cancelled() {
            return Err(ToolError::Cancelled);
        }
        let label = command.program_label();
        let (mut cmd, executable) = self.build(&command)?;
        cmd.stdin(Stdio::piped());
        let mut tree = Tree::spawn(cmd).map_err(|e| spawn_error(&label, &executable, &e))?;
        Ok(Child {
            stdin: tree.take_stdin(),
            stdout: tree.take_stdout(),
            stderr: tree.take_stderr(),
            tree,
            executable,
            started: Instant::now(),
        })
    }
}

fn spawn_error(label: &str, executable: &Path, e: &std::io::Error) -> ToolError {
    match e.kind() {
        std::io::ErrorKind::NotFound => ToolError::ProgramNotFound(label.to_string()),
        _ => ToolError::Io(format!("starting {label} ({}): {e}", executable.display())),
    }
}

/// Read into `buf`; `None` at end of stream or on error.
async fn read_some<R: AsyncRead + Unpin>(reader: &mut Option<R>, buf: &mut [u8]) -> Option<usize> {
    match reader {
        Some(r) => match r.read(buf).await {
            Ok(0) | Err(_) => None,
            Ok(n) => Some(n),
        },
        None => None,
    }
}

/// A long-lived child process and everything it starts.
pub struct Child {
    tree: Tree,
    /// The child's stdin.
    pub stdin: Option<tokio::process::ChildStdin>,
    /// The child's stdout.
    pub stdout: Option<tokio::process::ChildStdout>,
    /// The child's stderr.
    pub stderr: Option<tokio::process::ChildStderr>,
    executable: PathBuf,
    started: Instant,
}

impl std::fmt::Debug for Child {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Child")
            .field("pid", &self.tree.id())
            .field("executable", &self.executable)
            .finish_non_exhaustive()
    }
}

impl Child {
    /// Process id of the leader, while it is running.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.tree.id()
    }

    /// The executable that was started.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// When the process was started.
    #[must_use]
    pub fn started(&self) -> Instant {
        self.started
    }

    /// Wait for the leader to exit and return its exit code.
    pub async fn wait(&mut self) -> Result<Option<i32>> {
        let status = self
            .tree
            .wait_leader()
            .await
            .map_err(|e| ToolError::Io(format!("waiting for process: {e}")))?;
        Ok(status.code())
    }

    /// Exit code if the leader has already exited.
    pub fn try_wait(&mut self) -> Result<Option<Option<i32>>> {
        self.tree
            .try_wait_leader()
            .map(|s| s.map(|st| st.code()))
            .map_err(|e| ToolError::Io(format!("checking process: {e}")))
    }

    /// Ask the tree to stop, wait up to `grace`, then kill what remains.
    pub async fn terminate(&mut self, grace: Duration) {
        self.stdin.take();
        self.tree.terminate(grace).await;
        self.tree.finish();
    }
}

#[cfg(unix)]
mod imp {
    use std::process::ExitStatus;
    use std::time::Duration;

    use tokio::process::{ChildStderr, ChildStdin, ChildStdout};

    /// A child that leads its own process group.
    pub(super) struct Tree {
        child: tokio::process::Child,
        pgid: Option<i32>,
        exited: bool,
    }

    impl Tree {
        pub(super) fn spawn(mut cmd: tokio::process::Command) -> std::io::Result<Self> {
            cmd.process_group(0);
            let child = cmd.spawn()?;
            let pgid = child.id().and_then(|id| i32::try_from(id).ok());
            Ok(Self {
                child,
                pgid,
                exited: false,
            })
        }

        pub(super) fn id(&self) -> Option<u32> {
            self.child.id()
        }

        pub(super) fn take_stdin(&mut self) -> Option<ChildStdin> {
            self.child.stdin.take()
        }
        pub(super) fn take_stdout(&mut self) -> Option<ChildStdout> {
            self.child.stdout.take()
        }
        pub(super) fn take_stderr(&mut self) -> Option<ChildStderr> {
            self.child.stderr.take()
        }

        pub(super) async fn wait_leader(&mut self) -> std::io::Result<ExitStatus> {
            let status = self.child.wait().await?;
            self.leader_exited();
            Ok(status)
        }

        pub(super) fn try_wait_leader(&mut self) -> std::io::Result<Option<ExitStatus>> {
            let status = self.child.try_wait()?;
            if status.is_some() {
                self.leader_exited();
            }
            Ok(status)
        }

        /// Whatever the leader left running goes with it. The group id is
        /// then forgotten: once the leader is reaped the id can be reused by
        /// an unrelated process, and a later signal would hit that instead.
        fn leader_exited(&mut self) {
            if !self.exited {
                self.exited = true;
                self.signal(libc::SIGKILL);
                self.pgid = None;
            }
        }

        fn signal(&self, signal: libc::c_int) {
            if let Some(pgid) = self.pgid {
                // SAFETY: plain syscall; a stale group id yields ESRCH.
                unsafe {
                    libc::killpg(pgid, signal);
                }
            }
        }

        /// Kill every process in the group now.
        pub(super) fn kill_all(&mut self) {
            self.signal(libc::SIGKILL);
        }

        /// SIGTERM the group, give it `grace`, then SIGKILL it.
        pub(super) async fn terminate(&mut self, grace: Duration) {
            if !self.exited {
                self.signal(libc::SIGTERM);
                let _ = tokio::time::timeout(grace, self.wait_leader()).await;
            }
            self.kill_all();
            if !self.exited {
                let _ = self.wait_leader().await;
            }
        }

        /// Mark the tree as dealt with so `Drop` sends nothing further.
        pub(super) fn finish(&mut self) {
            self.pgid = None;
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            // Reached with a live group only when the owning future was
            // dropped mid-run; tokio reaps the leader via kill_on_drop.
            self.kill_all();
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::process::ExitStatus;
    use std::time::Duration;

    use process_wrap::tokio::{ChildWrapper, CommandWrap, JobObject, KillOnDrop};
    use tokio::process::{ChildStderr, ChildStdin, ChildStdout};

    /// A child inside a job object that is terminated as a unit.
    pub(super) struct Tree {
        child: Box<dyn ChildWrapper>,
        exited: bool,
    }

    impl Tree {
        pub(super) fn spawn(cmd: tokio::process::Command) -> std::io::Result<Self> {
            let mut wrap = CommandWrap::from(cmd);
            wrap.wrap(KillOnDrop).wrap(JobObject);
            Ok(Self {
                child: wrap.spawn()?,
                exited: false,
            })
        }

        pub(super) fn id(&self) -> Option<u32> {
            self.child.id()
        }

        pub(super) fn take_stdin(&mut self) -> Option<ChildStdin> {
            self.child.stdin().take()
        }
        pub(super) fn take_stdout(&mut self) -> Option<ChildStdout> {
            self.child.stdout().take()
        }
        pub(super) fn take_stderr(&mut self) -> Option<ChildStderr> {
            self.child.stderr().take()
        }

        /// Wait for the leader only; the job wrapper's own `wait` would also
        /// wait for everything the leader started.
        pub(super) async fn wait_leader(&mut self) -> std::io::Result<ExitStatus> {
            let status = self.child.inner_mut().wait().await?;
            self.leader_exited();
            Ok(status)
        }

        pub(super) fn try_wait_leader(&mut self) -> std::io::Result<Option<ExitStatus>> {
            let status = self.child.inner_mut().try_wait()?;
            if status.is_some() {
                self.leader_exited();
            }
            Ok(status)
        }

        /// Whatever the leader left running in the job goes with it.
        fn leader_exited(&mut self) {
            if !self.exited {
                self.exited = true;
                self.kill_all();
            }
        }

        /// Terminate every process in the job.
        pub(super) fn kill_all(&mut self) {
            let _ = self.child.start_kill();
        }

        /// Windows has no polite signal for a job: terminate it.
        pub(super) async fn terminate(&mut self, grace: Duration) {
            self.kill_all();
            if !self.exited {
                let _ = tokio::time::timeout(grace, self.wait_leader()).await;
            }
        }

        pub(super) fn finish(&mut self) {}
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            self.kill_all();
        }
    }
}

use imp::Tree;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::policy::{simplify, slash_string, PolicySet};

    fn spawner(commands: &[&str], extra: &str, exec: Exec) -> (Spawner, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let root = simplify(&std::fs::canonicalize(tmp.path()).unwrap());
        let cmds = commands
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let cfg = Config::from_toml_str(&format!(
            "[security]\nallowed_paths = [\"{}\"]\nallowed_commands = [{cmds}]\n\
             max_runtime_secs = 60\n{extra}\n",
            slash_string(&root)
        ))
        .unwrap();
        let policy = PolicySet::compile(&cfg, &[]).unwrap().for_tool("t");
        (
            Spawner::new(policy, exec, root, CancellationToken::new(), None),
            tmp,
        )
    }

    const CALLER: Exec = Exec::CallerChosen(&[]);

    #[test]
    fn head_and_tail_are_kept() {
        let mut b = HeadTail::new(8);
        b.push(b"0123456789abcdef");
        let c = b.finish();
        assert!(c.truncated);
        assert_eq!(c.total_bytes, 16);
        assert!(c.text.starts_with("0123"), "{}", c.text);
        assert!(c.text.ends_with("cdef"), "{}", c.text);
        assert!(c.text.contains("8 bytes omitted"));

        let mut b = HeadTail::new(8);
        for chunk in [&b"ab"[..], b"cd", b"ef", b"gh", b"ij", b"kl"] {
            b.push(chunk);
        }
        let c = b.finish();
        assert!(c.text.starts_with("abcd") && c.text.ends_with("ijkl"));

        let mut b = HeadTail::new(64);
        b.push(b"short");
        let c = b.finish();
        assert_eq!((c.text.as_str(), c.truncated), ("short", false));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runs_and_captures_output() {
        let (s, _t) = spawner(&["sh"], "", CALLER);
        let out = s
            .run(Command::caller("sh").args(["-c", "echo out; echo err >&2; exit 3"]))
            .await
            .unwrap();
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stdout.text.trim(), "out");
        assert_eq!(out.stderr.text.trim(), "err");
        assert!(out.check("sh").is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unlisted_and_undeclared_programs_are_refused() {
        let (s, _t) = spawner(&["sh"], "", CALLER);
        assert!(matches!(
            s.run(Command::caller("ls")).await,
            Err(ToolError::CommandNotAllowed(_))
        ));
        // A tool that declared nothing cannot run anything.
        let (none, _t2) = spawner(&["*"], "", Exec::None);
        assert!(matches!(
            none.run(Command::caller("sh")).await,
            Err(ToolError::Internal(_))
        ));
        assert!(matches!(
            none.run(Command::typed("sh")).await,
            Err(ToolError::Internal(_))
        ));
        // Typed programs do not need the allowlist, only the declaration.
        let (typed, _t3) = spawner(&[], "", Exec::Programs(&["sh"]));
        let out = typed
            .run(Command::typed("sh").args(["-c", "echo ok"]))
            .await
            .unwrap();
        assert_eq!(out.stdout.text.trim(), "ok");
        assert!(typed.run(Command::caller("sh")).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn child_environment_is_scrubbed() {
        // Variables set before the spawner is used; names are unique to this test.
        std::env::set_var("NEBULA_MCP_AUTH_TOKEN", "server-secret");
        std::env::set_var("NEBULA_PROC_TEST_SECRET", "other-secret");
        std::env::set_var("NEBULA_PROC_TEST_PASS", "passed");
        let (s, _t) = spawner(
            &["sh"],
            "env_passthrough = [\"NEBULA_PROC_TEST_PASS\"]\ncaller_env = [\"OK_VAR\"]",
            CALLER,
        );
        let out = s
            .run(
                Command::caller("sh")
                    .args(["-c", "env"])
                    .caller_env([("OK_VAR".to_string(), "1".to_string())]),
            )
            .await
            .unwrap();
        let env = out.stdout.text;
        assert!(!env.contains("server-secret"), "{env}");
        assert!(!env.contains("other-secret"), "{env}");
        assert!(env.contains("NEBULA_PROC_TEST_PASS=passed"));
        assert!(env.contains("OK_VAR=1"));
        assert!(env.contains("PATH="));

        let denied = s
            .run(
                Command::caller("sh")
                    .args(["-c", "true"])
                    .caller_env([("LD_PRELOAD".to_string(), "/x.so".to_string())]),
            )
            .await;
        assert!(matches!(denied, Err(ToolError::PermissionDenied(_))));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_the_whole_tree() {
        let (s, t) = spawner(&["sh"], "", CALLER);
        let pidfile = t.path().join("pid");
        let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());
        let started = Instant::now();
        let r = s
            .run(
                Command::caller("sh")
                    .args(["-c", &script])
                    .timeout(Duration::from_millis(600)),
            )
            .await;
        assert!(matches!(r, Err(ToolError::Timeout(_))));
        assert!(started.elapsed() < Duration::from_secs(10));
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(gone(pid).await, "grandchild {pid} survived the timeout");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_the_future_kills_the_whole_tree() {
        let (s, t) = spawner(&["sh"], "", CALLER);
        let pidfile = t.path().join("pid");
        let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());
        let fut = s.run(Command::caller("sh").args(["-c", &script]));
        let _ = tokio::time::timeout(Duration::from_millis(800), fut).await;
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(gone(pid).await, "grandchild {pid} survived the drop");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn background_children_do_not_outlive_the_command() {
        let (s, t) = spawner(&["sh"], "", CALLER);
        let pidfile = t.path().join("pid");
        let script = format!("sleep 300 & echo $! > '{}'; echo done", pidfile.display());
        let started = Instant::now();
        let out = s
            .run(Command::caller("sh").args(["-c", &script]))
            .await
            .unwrap();
        assert_eq!(out.stdout.text.trim(), "done");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "waited on a held pipe"
        );
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(gone(pid).await, "background child {pid} was left running");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_process_that_left_the_group_cannot_hold_the_call_open() {
        if which::which("perl").is_err() {
            return;
        }
        let (s, t) = spawner(&["sh"], "", CALLER);
        let pidfile = t.path().join("pid");
        // The background process starts its own session, so the group kill
        // does not reach it, and it keeps the output pipes open.
        let script = format!(
            "perl -MPOSIX -e 'POSIX::setsid(); open(F, q(>), q({p})); print F $$; close F; \
             sleep 60' & while [ ! -s '{p}' ]; do sleep 0.05; done; echo done",
            p = pidfile.display()
        );
        let started = Instant::now();
        let out = s
            .run(
                Command::caller("sh")
                    .args(["-c", &script])
                    .timeout(Duration::from_secs(40)),
            )
            .await;
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: plain syscall on the one process this test started.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let out = out.unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.text.trim(), "done");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the call waited for a pipe held outside its process group"
        );
    }

    #[tokio::test]
    async fn required_confinement_that_is_unavailable_refuses_to_spawn() {
        if CONFINEMENT_AVAILABLE {
            return;
        }
        let (s, _t) = spawner(&["sh"], "[security.sandbox]\nmode = \"require\"", CALLER);
        let r = s.run(Command::caller("sh").args(["-c", "echo hi"])).await;
        assert!(matches!(r, Err(ToolError::PermissionDenied(_))), "{r:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_stops_the_command() {
        let (s, _t) = spawner(&["sleep"], "", CALLER);
        let cancel = s.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            cancel.cancel();
        });
        let started = Instant::now();
        let r = s.run(Command::caller("sleep").arg("300")).await;
        assert!(matches!(r, Err(ToolError::Cancelled)));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn large_stdin_and_output_do_not_deadlock() {
        let (s, _t) = spawner(&["cat"], "max_output_bytes = 4096", CALLER);
        let input = vec![b'x'; 2 * 1024 * 1024];
        let out = tokio::time::timeout(
            Duration::from_secs(30),
            s.run(Command::caller("cat").stdin(input)),
        )
        .await
        .expect("deadlocked")
        .unwrap();
        assert!(out.success());
        assert!(out.stdout.truncated);
        assert_eq!(out.stdout.total_bytes, 2 * 1024 * 1024);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_can_return_partial_output() {
        let (s, _t) = spawner(&["sh"], "", CALLER);
        let out = s
            .run(
                Command::caller("sh")
                    .args(["-c", "echo before; sleep 300"])
                    .timeout(Duration::from_millis(600))
                    .timeout_is_result(),
            )
            .await
            .unwrap();
        assert!(out.timed_out);
        assert_eq!(out.code, None);
        assert_eq!(out.stdout.text.trim(), "before");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn interactive_child_is_killed_on_drop() {
        let (s, t) = spawner(&["sh"], "", CALLER);
        let pidfile = t.path().join("pid");
        let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());
        let child = s
            .spawn(Command::caller("sh").args(["-c", &script]))
            .unwrap();
        for _ in 0..100 {
            if std::fs::read_to_string(&pidfile).is_ok_and(|s| !s.trim().is_empty()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        drop(child);
        assert!(
            gone(pid).await,
            "grandchild {pid} survived dropping the child"
        );
    }

    #[tokio::test]
    async fn missing_program_is_reported() {
        let (s, _t) = spawner(&["definitely-not-a-real-binary-xyz"], "", CALLER);
        assert!(matches!(
            s.run(Command::caller("definitely-not-a-real-binary-xyz"))
                .await,
            Err(ToolError::ProgramNotFound(_))
        ));
    }

    /// Whether `pid` stops existing (or becomes a zombie) within a few seconds.
    #[cfg(unix)]
    async fn gone(pid: i32) -> bool {
        for _ in 0..100 {
            let out = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            let stat = String::from_utf8_lossy(&out.stdout);
            if stat.trim().is_empty() || stat.trim().starts_with('Z') {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Do not leak the process from a failing test.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        false
    }
}
