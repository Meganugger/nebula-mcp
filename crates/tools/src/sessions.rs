//! Interactive terminal sessions: long-lived child processes owned by one
//! client.
//!
//! A session belongs to the [`OwnerId`] that opened it and is invisible to
//! every other owner. Its whole process tree is killed when it is closed,
//! when it has been idle for too long, when its owner goes away and when the
//! server stops.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nebula_mcp_core::process::{Child, Command};
use nebula_mcp_core::{OwnerId, Result, ToolContext, ToolError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// Time a session's tree gets to stop politely when it is closed.
const CLOSE_GRACE: Duration = Duration::from_secs(2);
/// Time allowed for a write to a session's stdin.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded buffer of a session's output; the oldest bytes are dropped when
/// nobody reads.
struct Buffer {
    inner: Mutex<BufferInner>,
    arrived: tokio::sync::Notify,
    cap: usize,
}

#[derive(Default)]
struct BufferInner {
    data: VecDeque<u8>,
    dropped: u64,
    open_streams: u8,
}

impl Buffer {
    fn push(&self, bytes: &[u8]) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.data.extend(bytes);
        let over = inner.data.len().saturating_sub(self.cap);
        if over > 0 {
            inner.data.drain(..over);
            inner.dropped += over as u64;
        }
        drop(inner);
        self.arrived.notify_waiters();
    }

    fn stream_closed(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.open_streams = inner.open_streams.saturating_sub(1);
        drop(inner);
        self.arrived.notify_waiters();
    }

    /// Take up to `max` bytes, and the count of bytes dropped since the last
    /// take.
    fn take(&self, max: usize) -> (Vec<u8>, u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let n = inner.data.len().min(max);
        let bytes: Vec<u8> = inner.data.drain(..n).collect();
        let dropped = std::mem::take(&mut inner.dropped);
        (bytes, dropped)
    }

    fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .data
            .len()
    }

    fn streams_open(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .open_streams
            > 0
    }
}

async fn pump<R: AsyncRead + Unpin>(mut reader: R, buffer: Arc<Buffer>) {
    let mut chunk = vec![0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buffer.push(&chunk[..n]),
        }
    }
    buffer.stream_closed();
}

struct Session {
    id: String,
    owner: OwnerId,
    /// The command as the caller gave it, to re-check against the policy.
    command: Command,
    program: String,
    executable: PathBuf,
    child: tokio::sync::Mutex<Child>,
    buffer: Arc<Buffer>,
    started: Instant,
    last_used: Mutex<Instant>,
}

impl Session {
    fn touch(&self) {
        *self.last_used.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    fn idle(&self) -> Duration {
        self.last_used
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .elapsed()
    }
}

/// What `list` reports about a session.
pub(crate) struct SessionInfo {
    pub id: String,
    pub program: String,
    pub pid: Option<u32>,
    /// `None` while running; `Some(code)` once exited (`code` is `None`
    /// when a signal ended it).
    pub exit: Option<Option<i32>>,
    pub age: Duration,
    pub idle: Duration,
    pub buffered: usize,
}

/// What a read or a close returns.
pub(crate) struct Chunk {
    pub text: String,
    pub dropped: u64,
    pub exit: Option<Option<i32>>,
    /// Bytes still buffered after this read.
    pub remaining: usize,
}

/// Every open session, of every owner.
#[derive(Default)]
pub(crate) struct Sessions {
    map: Mutex<HashMap<String, Arc<Session>>>,
}

impl Sessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Session>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Start `command` as a session of the calling owner.
    pub(crate) fn open(
        &self,
        ctx: &ToolContext,
        command: Command,
    ) -> Result<(String, Option<u32>)> {
        let limit = ctx.config().limits.max_terminal_sessions;
        let owned = self
            .lock()
            .values()
            .filter(|s| &s.owner == ctx.owner())
            .count();
        if owned >= limit {
            return Err(ToolError::LimitExceeded(format!(
                "{owned} terminal sessions are open, which is the limit; close one with \
                 terminal_session_close first"
            )));
        }
        let program = command.program_label();
        let mut child = ctx.spawn(command.clone())?;
        let buffer = Arc::new(Buffer {
            inner: Mutex::new(BufferInner {
                open_streams: 2,
                ..Default::default()
            }),
            arrived: tokio::sync::Notify::new(),
            cap: ctx.max_output_bytes(),
        });
        match child.stdout.take() {
            Some(out) => drop(tokio::spawn(pump(out, buffer.clone()))),
            None => buffer.stream_closed(),
        }
        match child.stderr.take() {
            Some(err) => drop(tokio::spawn(pump(err, buffer.clone()))),
            None => buffer.stream_closed(),
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let pid = child.id();
        let session = Arc::new(Session {
            id: id.clone(),
            owner: ctx.owner().clone(),
            command,
            program,
            executable: child.executable().to_path_buf(),
            child: tokio::sync::Mutex::new(child),
            buffer,
            started: Instant::now(),
            last_used: Mutex::new(Instant::now()),
        });
        self.lock().insert(id.clone(), session);
        Ok((id, pid))
    }

    /// The caller's session `id`. A session of another owner does not exist
    /// as far as the caller can tell.
    fn find(&self, ctx: &ToolContext, id: &str) -> Result<Arc<Session>> {
        self.lock()
            .get(id)
            .filter(|s| &s.owner == ctx.owner())
            .cloned()
            .ok_or_else(|| {
                ToolError::NotFound(format!(
                    "no terminal session '{id}'; terminal_session_list shows the open ones"
                ))
            })
    }

    /// The caller's session, provided the policy in force now would still
    /// start it. Otherwise the session is closed.
    async fn authorized(&self, ctx: &ToolContext, id: &str) -> Result<Arc<Session>> {
        let session = self.find(ctx, id)?;
        let still_allowed = matches!(
            ctx.spawner().resolve(&session.command),
            Ok(path) if path == session.executable
        );
        if !still_allowed {
            self.remove_and_kill(&session).await;
            return Err(ToolError::PermissionDenied(format!(
                "'{}' is no longer permitted by policy; the session was closed",
                session.program
            )));
        }
        session.touch();
        Ok(session)
    }

    async fn remove_and_kill(&self, session: &Arc<Session>) -> Option<Option<i32>> {
        self.lock().remove(&session.id);
        let mut child = session.child.lock().await;
        child.terminate(CLOSE_GRACE).await;
        child.try_wait().ok().flatten()
    }

    /// Write to a session's stdin.
    pub(crate) async fn write(&self, ctx: &ToolContext, id: &str, data: &[u8]) -> Result<()> {
        let session = self.authorized(ctx, id).await?;
        let mut child = session.child.lock().await;
        if let Some(code) = child.try_wait()? {
            return Err(ToolError::Execution(format!(
                "the session's process has exited ({}); read what it printed with \
                 terminal_session_read, then close the session",
                describe_exit(code)
            )));
        }
        let Some(stdin) = child.stdin.as_mut() else {
            return Err(ToolError::Execution(
                "the session's input is closed".to_string(),
            ));
        };
        ctx.deadline(WRITE_TIMEOUT, async {
            stdin
                .write_all(data)
                .await
                .map_err(|e| ToolError::Io(format!("writing to the session: {e}")))?;
            stdin
                .flush()
                .await
                .map_err(|e| ToolError::Io(format!("writing to the session: {e}")))
        })
        .await
    }

    /// Take buffered output, waiting up to `wait` for some to arrive.
    pub(crate) async fn read(
        &self,
        ctx: &ToolContext,
        id: &str,
        wait: Duration,
        max: usize,
    ) -> Result<Chunk> {
        let session = self.authorized(ctx, id).await?;
        if session.buffer.len() == 0 && session.buffer.streams_open() && !wait.is_zero() {
            let arrived = session.buffer.arrived.notified();
            tokio::pin!(arrived);
            arrived.as_mut().enable();
            if session.buffer.len() == 0 && session.buffer.streams_open() {
                tokio::select! {
                    () = &mut arrived => {}
                    () = tokio::time::sleep(wait) => {}
                    () = ctx.cancel().cancelled() => return Err(ToolError::Cancelled),
                }
            }
        }
        let (bytes, dropped) = session.buffer.take(max);
        let exit = session.child.lock().await.try_wait()?;
        Ok(Chunk {
            text: String::from_utf8_lossy(&bytes).into_owned(),
            dropped,
            exit,
            remaining: session.buffer.len(),
        })
    }

    /// The caller's sessions.
    pub(crate) async fn list(&self, ctx: &ToolContext) -> Vec<SessionInfo> {
        let mine: Vec<Arc<Session>> = self
            .lock()
            .values()
            .filter(|s| &s.owner == ctx.owner())
            .cloned()
            .collect();
        let mut out = Vec::with_capacity(mine.len());
        for s in mine {
            let mut child = s.child.lock().await;
            out.push(SessionInfo {
                id: s.id.clone(),
                program: s.program.clone(),
                pid: child.id(),
                exit: child.try_wait().ok().flatten(),
                age: s.started.elapsed(),
                idle: s.idle(),
                buffered: s.buffer.len(),
            });
        }
        out.sort_by(|a, b| b.age.cmp(&a.age));
        out
    }

    /// Close the caller's session: kill its tree and return what was left in
    /// the buffer.
    pub(crate) async fn close(&self, ctx: &ToolContext, id: &str, max: usize) -> Result<Chunk> {
        let session = self.find(ctx, id)?;
        let exit = self.remove_and_kill(&session).await;
        let (bytes, dropped) = session.buffer.take(max);
        Ok(Chunk {
            text: String::from_utf8_lossy(&bytes).into_owned(),
            dropped,
            exit: Some(exit.flatten()),
            remaining: 0,
        })
    }

    /// Kill every session that matches `which`.
    async fn close_where(&self, which: impl Fn(&Session) -> bool) -> usize {
        let doomed: Vec<Arc<Session>> =
            self.lock().values().filter(|s| which(s)).cloned().collect();
        for session in &doomed {
            self.remove_and_kill(session).await;
        }
        doomed.len()
    }

    /// Kill the sessions of an owner that has gone away.
    pub(crate) async fn close_owner(&self, owner: &OwnerId) -> usize {
        self.close_where(|s| &s.owner == owner).await
    }

    /// Kill the sessions nobody has used for `idle`.
    pub(crate) async fn expire(&self, idle: Duration) -> usize {
        self.close_where(|s| s.idle() >= idle).await
    }

    /// Kill every session.
    pub(crate) async fn close_all(&self) -> usize {
        self.close_where(|_| true).await
    }

    /// Number of open sessions, of all owners.
    pub(crate) fn count(&self) -> usize {
        self.lock().len()
    }
}

/// `exit code 0`, or `a signal` when there is no code.
pub(crate) fn describe_exit(code: Option<i32>) -> String {
    match code {
        Some(c) => format!("exit code {c}"),
        None => "ended by a signal".to_string(),
    }
}
