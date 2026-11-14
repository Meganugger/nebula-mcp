//! Black-box test support: drives the real `nebula-mcp` binary over stdio.
//!
//! Tests built on this talk JSON-RPC to a child process exactly as a client
//! would, so they exercise the real dispatcher, the real config loader and the
//! real process lifecycle rather than internal APIs.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Default time to wait for a response before failing the test.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// A scratch area for one test: `root` is what the policy allows, `outside`
/// is a sibling the policy must never reach, and `home` holds the config.
pub struct Sandbox {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
    pub outside: PathBuf,
    pub home: PathBuf,
}

impl Sandbox {
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().expect("create temp dir");
        // Canonicalise so the paths the tests compare against are the ones the
        // OS reports (macOS: /var -> /private/var; Windows: short names).
        let base = dunce_canonicalize(tmp.path());
        let root = base.join("root");
        let outside = base.join("outside");
        let home = base.join("home");
        for d in [&root, &outside, &home] {
            std::fs::create_dir_all(d).expect("create sandbox dir");
        }
        Self {
            _tmp: tmp,
            root,
            outside,
            home,
        }
    }

    /// The allowed root as a forward-slash string usable inside TOML.
    pub fn root_str(&self) -> String {
        toml_path(&self.root)
    }
}

/// Canonicalise without the Windows `\\?\` verbatim prefix.
pub fn dunce_canonicalize(p: &Path) -> PathBuf {
    let c = std::fs::canonicalize(p).expect("canonicalize");
    let s = c.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => c,
    }
}

/// A path as a forward-slash string (safe inside a TOML basic string).
pub fn toml_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// A running server process speaking newline-delimited JSON-RPC.
pub struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<Value>,
    stderr: Arc<Mutex<String>>,
    next_id: i64,
    /// Messages read while waiting for something else.
    backlog: Vec<Value>,
}

/// Options for starting the server.
pub struct Start<'a> {
    pub config: &'a str,
    pub workdir: &'a Path,
    pub config_dir: &'a Path,
    pub env: Vec<(String, String)>,
    pub args: Vec<String>,
}

impl Proc {
    /// Start the server with `config` (TOML text) and `sandbox.root` as the
    /// working directory.
    pub fn start(sandbox: &Sandbox, config: &str) -> Self {
        Self::start_with(Start {
            config,
            workdir: &sandbox.root,
            config_dir: &sandbox.home,
            env: Vec::new(),
            args: Vec::new(),
        })
    }

    pub fn start_with(opts: Start<'_>) -> Self {
        let config_path = opts.config_dir.join("nebula-test-config.toml");
        std::fs::write(&config_path, opts.config).expect("write config");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nebula-mcp"));
        cmd.arg("--config")
            .arg(&config_path)
            .arg("--workdir")
            .arg(opts.workdir)
            .args(&opts.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &opts.env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn nebula-mcp");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("stdout");
        let stderr_pipe = child.stderr.take().expect("stderr");

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if line.trim().is_empty() {
                    continue;
                }
                let value = serde_json::from_str::<Value>(&line)
                    .unwrap_or_else(|e| json!({"__unparseable": line, "__error": e.to_string()}));
                if tx.send(value).is_err() {
                    break;
                }
            }
        });
        let stderr = Arc::new(Mutex::new(String::new()));
        let sink = stderr.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr_pipe).lines().map_while(Result::ok) {
                let mut s = sink.lock().unwrap();
                s.push_str(&line);
                s.push('\n');
            }
        });

        Self {
            child,
            stdin,
            rx,
            stderr,
            next_id: 1,
            backlog: Vec::new(),
        }
    }

    /// Process id of the server.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Everything the server has written to stderr so far.
    pub fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// Write one raw line to the server's stdin.
    pub fn send_raw(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin already closed");
        stdin.write_all(line.as_bytes()).expect("write stdin");
        stdin.write_all(b"\n").expect("write stdin");
        stdin.flush().expect("flush stdin");
    }

    /// Send a JSON-RPC message.
    pub fn send(&mut self, message: &Value) {
        self.send_raw(&serde_json::to_string(message).unwrap());
    }

    /// Send a request and return its id without waiting for the response.
    pub fn send_request(&mut self, method: &str, params: Value) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        id
    }

    /// Send a notification.
    pub fn notify(&mut self, method: &str, params: Value) {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    /// Next message from the server, or `None` on timeout / closed stdout.
    pub fn next_message(&mut self, timeout: Duration) -> Option<Value> {
        if !self.backlog.is_empty() {
            return Some(self.backlog.remove(0));
        }
        self.rx.recv_timeout(timeout).ok()
    }

    /// Wait for the response to request `id`. Other messages are kept in the
    /// backlog and returned by `drain_notifications`.
    pub fn response(&mut self, id: i64, timeout: Duration) -> Option<Value> {
        if let Some(pos) = self.backlog.iter().position(|m| m["id"] == json!(id)) {
            return Some(self.backlog.remove(pos));
        }
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            match self.rx.recv_timeout(left) {
                Ok(v) if v["id"] == json!(id) && v.get("method").is_none() => return Some(v),
                Ok(v) => self.backlog.push(v),
                Err(_) => return None,
            }
        }
    }

    /// Send a request and wait for its response (panics on timeout).
    pub fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.send_request(method, params);
        match self.response(id, RESPONSE_TIMEOUT) {
            Some(v) => v,
            None => panic!(
                "no response to {method} within {RESPONSE_TIMEOUT:?}; server stderr:\n{}",
                self.stderr()
            ),
        }
    }

    /// Perform the legacy `initialize` handshake at `version`.
    pub fn initialize(&mut self, version: &str) -> Value {
        let resp = self.request(
            "initialize",
            json!({
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name": "nebula-e2e", "version": "0"}
            }),
        );
        self.notify("notifications/initialized", json!({}));
        resp
    }

    /// Call a tool and return the `result` object (panics on a protocol error).
    pub fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let resp = self.request("tools/call", json!({"name": tool, "arguments": arguments}));
        match resp.get("result") {
            Some(r) => r.clone(),
            None => panic!("tools/call {tool} returned a protocol error: {resp}"),
        }
    }

    /// Notifications (and anything else unsolicited) received so far.
    pub fn drain_notifications(&mut self) -> Vec<Value> {
        while let Ok(v) = self.rx.try_recv() {
            self.backlog.push(v);
        }
        std::mem::take(&mut self.backlog)
    }

    /// Close stdin (the portable shutdown signal) and wait for exit.
    pub fn close_stdin_and_wait(&mut self, timeout: Duration) -> Option<ExitStatus> {
        self.stdin.take();
        self.wait(timeout)
    }

    /// Wait for the process to exit.
    pub fn wait(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.stdin.take();
        if self.wait(Duration::from_millis(500)).is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// All text content of a tool result, concatenated.
pub fn text_of(result: &Value) -> String {
    result["content"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|c| c["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Whether a tool result is an error result.
pub fn is_error(result: &Value) -> bool {
    result["isError"] == json!(true)
}

/// Whether a process with this pid currently exists.
#[cfg(unix)]
pub fn pid_alive(pid: u32) -> bool {
    // `kill -0` succeeds for zombies too, so read the state from ps.
    let out = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("run ps");
    let stat = String::from_utf8_lossy(&out.stdout);
    let stat = stat.trim();
    !stat.is_empty() && !stat.starts_with('Z')
}

/// Poll `cond` until it holds or `timeout` elapses.
pub fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
