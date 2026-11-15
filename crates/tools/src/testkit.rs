//! Test support: every tool is driven through the real dispatcher, with a
//! temporary directory as the only allowed root.

#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nebula_mcp_core::config::Config;
use nebula_mcp_core::policy::{simplify, slash_string};
use nebula_mcp_core::tool::Content;
use nebula_mcp_core::{
    Call, CallFailure, ConfigStore, Dispatcher, OwnerId, ToolOutput, ToolRegistry,
};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

pub(crate) struct Kit {
    _tmp: tempfile::TempDir,
    /// The allowed root (canonical).
    pub root: PathBuf,
    /// A directory next to the root that policy does not allow.
    pub outside: PathBuf,
    pub dispatcher: Arc<Dispatcher>,
    pub state: crate::ToolState,
    pub shutdown: CancellationToken,
    categories: String,
}

impl Kit {
    /// A dispatcher with every category enabled and `root` allowed.
    /// `security` is appended to the `[security]` table.
    pub(crate) fn new(security: &str) -> Self {
        Self::build(security, "")
    }

    /// Like [`Kit::new`], with further TOML appended after `[security]`.
    pub(crate) fn with_config(security: &str, rest: &str) -> Self {
        Self::build(security, rest)
    }

    fn build(security: &str, rest: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = simplify(&std::fs::canonicalize(tmp.path()).unwrap());
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let mut registry = ToolRegistry::new();
        let state = crate::register_all(&mut registry).unwrap();
        let categories: Vec<String> = registry
            .catalog()
            .categories
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect();
        let categories = categories.join(", ");
        let config = Self::config(&categories, &root, security, rest);
        config.validate(&registry.catalog()).unwrap();
        let shutdown = CancellationToken::new();
        let dispatcher = Arc::new(Dispatcher::new(
            Arc::new(registry),
            ConfigStore::from_config(config).unwrap(),
            root.clone(),
            shutdown.clone(),
        ));
        state.start(&dispatcher, shutdown.clone());
        Self {
            _tmp: tmp,
            root,
            outside,
            dispatcher,
            state,
            shutdown,
            categories,
        }
    }

    fn config(categories: &str, root: &Path, security: &str, rest: &str) -> Config {
        let text = format!(
            "[server]\ncategories = [{categories}]\n[security]\nallowed_paths = [\"{}\"]\n\
             {security}\n{rest}\n",
            slash_string(root)
        );
        Config::from_toml_str(&text).unwrap()
    }

    /// Swap the live configuration, as a hot reload would.
    pub(crate) fn reconfigure(&self, security: &str) {
        let config = Self::config(&self.categories, &self.root, security, "");
        self.dispatcher.store().replace(config).unwrap();
    }

    pub(crate) fn request(name: &str, arguments: Value, owner: &OwnerId) -> Call {
        Call {
            name: name.to_string(),
            arguments,
            owner: owner.clone(),
            request_id: "test".into(),
            cancel: CancellationToken::new(),
            progress: None,
        }
    }

    /// Call a tool as the stdio owner.
    pub(crate) async fn call(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<ToolOutput, CallFailure> {
        self.call_as(&OwnerId::stdio(), name, arguments).await
    }

    /// Call a tool as `owner`. Successful structured results are checked
    /// against the tool's declared output schema.
    pub(crate) async fn call_as(
        &self,
        owner: &OwnerId,
        name: &str,
        arguments: Value,
    ) -> Result<ToolOutput, CallFailure> {
        let result = self
            .dispatcher
            .call(Self::request(name, arguments, owner))
            .await
            .unwrap_or_else(|e| panic!("{name}: {}", e.message));
        if let Ok(out) = &result {
            let spec = self.dispatcher.registry().get(name).unwrap().spec().clone();
            match (&spec.output, &out.structured) {
                (Some(schema), Some(value)) => {
                    nebula_mcp_core::schema::validate_as(
                        "result",
                        "the structured result",
                        schema,
                        value,
                    )
                    .unwrap_or_else(|e| panic!("{name} broke its output schema: {e}"));
                }
                (Some(_), None) => panic!("{name} declares an output schema but returned text"),
                (None, Some(_)) => panic!("{name} returned a record without an output schema"),
                (None, None) => {}
            }
        }
        result
    }

    /// Call a tool that must succeed.
    pub(crate) async fn ok(&self, name: &str, arguments: Value) -> ToolOutput {
        match self.call(name, arguments).await {
            Ok(out) => out,
            Err(f) => panic!("{name} failed: {}", f.text),
        }
    }

    /// Call a tool that must fail; returns the text shown to the model.
    pub(crate) async fn err(&self, name: &str, arguments: Value) -> String {
        match self.call(name, arguments).await {
            Ok(out) => panic!("{name} unexpectedly succeeded: {}", text_of(&out)),
            Err(f) => f.text,
        }
    }

    /// Call a tool that must succeed and return its structured result.
    pub(crate) async fn json(&self, name: &str, arguments: Value) -> Value {
        self.ok(name, arguments)
            .await
            .structured
            .expect("structured result")
    }

    /// A path under the root as the forward-slash string a caller would send.
    pub(crate) fn path(&self, rel: &str) -> String {
        slash_string(&self.root.join(rel))
    }

    pub(crate) fn write(&self, rel: &str, content: &str) {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    pub(crate) fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.root.join(rel)).unwrap()
    }

    pub(crate) fn exists(&self, rel: &str) -> bool {
        self.root.join(rel).symlink_metadata().is_ok()
    }

    /// Wait for a file under the root to exist with content, and return it.
    pub(crate) async fn wait_for_file(&self, rel: &str) -> String {
        let path = self.root.join(rel);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if !text.trim().is_empty() {
                    return text;
                }
            }
            assert!(Instant::now() < deadline, "{rel} never appeared");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for Kit {
    fn drop(&mut self) {
        // Stops jobs and sessions the test left behind.
        self.shutdown.cancel();
    }
}

/// All text blocks of a result joined with newlines.
pub(crate) fn text_of(out: &ToolOutput) -> String {
    out.content
        .iter()
        .filter_map(|c| match c {
            Content::Text(t) => Some(t.as_str()),
            Content::Image { .. } => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Write a file outside the allowed root.
pub(crate) fn write_outside(dir: &Path, name: &str, content: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

/// Whether process `pid` is gone (or a zombie), polling for a while.
#[cfg(unix)]
pub(crate) async fn gone(pid: &str) -> bool {
    let pid = pid.trim().to_string();
    for _ in 0..100 {
        let out = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid])
            .output()
            .expect("run ps");
        let stat = String::from_utf8_lossy(&out.stdout);
        let stat = stat.trim();
        if stat.is_empty() || stat.starts_with('Z') {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// One request received by [`HttpMock`].
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub method: String,
    /// Path and query, as sent.
    pub target: String,
    /// Header names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Seen {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// What [`HttpMock`] answers: status, extra headers, body.
pub(crate) type Reply = (u16, Vec<(String, String)>, String);

/// A loopback HTTP/1.1 server answering from a closure and recording what
/// it was sent. One request per connection.
pub(crate) struct HttpMock {
    pub port: u16,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl HttpMock {
    pub(crate) fn start<F>(respond: F) -> Self
    where
        F: Fn(&Seen) -> Reply + Send + Sync + 'static,
    {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (log, stopped) = (seen.clone(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopped.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let target = parts.next().unwrap_or_default().to_string();
                let mut headers = Vec::new();
                let mut length = 0usize;
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.trim_end().split_once(':') {
                        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
                        if k == "content-length" {
                            length = v.parse().unwrap_or(0);
                        }
                        headers.push((k, v));
                    }
                }
                let mut body = vec![0u8; length];
                let _ = reader.read_exact(&mut body);
                let request = Seen {
                    method,
                    target,
                    headers,
                    body: String::from_utf8_lossy(&body).into_owned(),
                };
                let (status, extra, text) = respond(&request);
                log.lock().unwrap().push(request);
                let mut head = format!(
                    "HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\nConnection: close\r\n",
                    text.len()
                );
                for (k, v) in extra {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let mut stream = reader.into_inner();
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(text.as_bytes());
                let _ = stream.flush();
            }
        });
        Self { port, seen, stop }
    }

    pub(crate) fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Requests received so far.
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for HttpMock {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wake the accept loop so the thread ends.
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}
