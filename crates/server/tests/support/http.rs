//! HTTP support for the black-box tests: starting the server with the HTTP
//! transport and a minimal HTTP/1.1 client with full control over headers
//! and the ability to stop reading a response part-way.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};

use super::{wait_until, Proc, Sandbox, Start, RESPONSE_TIMEOUT};

impl Proc {
    /// Start the server with the HTTP transport on a port the system picks.
    pub fn start_http(sandbox: &Sandbox, config: &str, args: &[&str]) -> (Self, HttpClient) {
        let mut all = vec![
            "--http".to_string(),
            "--http-addr".to_string(),
            "127.0.0.1:0".to_string(),
        ];
        all.extend(args.iter().map(|a| (*a).to_string()));
        let server = Self::start_with(Start {
            config,
            workdir: &sandbox.root,
            config_dir: &sandbox.home,
            env: Vec::new(),
            args: all,
        });
        let addr = server.http_addr();
        (server, HttpClient { addr, token: None })
    }

    /// The address the HTTP transport bound, read from the startup log.
    pub fn http_addr(&self) -> SocketAddr {
        let mut found = None;
        let ok = wait_until(Duration::from_secs(30), || {
            let log = self.stderr();
            let Some(at) = log.find("http://127.0.0.1:") else {
                return false;
            };
            let rest = &log[at + "http://".len()..];
            let end = rest.find('/').unwrap_or(rest.len());
            found = rest[..end].parse().ok();
            found.is_some()
        });
        assert!(
            ok,
            "the HTTP transport did not start; stderr:\n{}",
            self.stderr()
        );
        found.unwrap()
    }

    /// Path of the configuration file a server in `sandbox` is started with.
    pub fn config_path(sandbox: &Sandbox) -> PathBuf {
        sandbox.home.join("nebula-test-config.toml")
    }
}

/// One connection per request.
#[derive(Clone)]
pub struct HttpClient {
    pub addr: SocketAddr,
    pub token: Option<String>,
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    reader: BufReader<TcpStream>,
    chunked: bool,
    length: Option<usize>,
    pending: String,
    ended: bool,
}

impl HttpClient {
    pub fn with_token(&self, token: &str) -> Self {
        Self {
            addr: self.addr,
            token: Some(token.to_string()),
        }
    }

    /// Write a request and return the connection without reading from it.
    /// `headers` are added after the defaults; a `Host` or `Authorization`
    /// given here replaces the default one.
    pub fn write(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(self.addr).expect("connect");
        stream
            .set_read_timeout(Some(RESPONSE_TIMEOUT))
            .expect("read timeout");
        let has = |name: &str| headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
        let mut head = format!("{method} {path} HTTP/1.1\r\n");
        if !has("host") {
            head.push_str(&format!("Host: {}\r\n", self.addr));
        }
        if !has("authorization") {
            if let Some(token) = &self.token {
                head.push_str(&format!("Authorization: Bearer {token}\r\n"));
            }
        }
        if !has("accept") {
            head.push_str("Accept: application/json, text/event-stream\r\n");
        }
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if let Some(body) = body {
            if !has("content-type") {
                head.push_str("Content-Type: application/json\r\n");
            }
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        // The server may answer and close before it has read everything
        // (an oversized body, a refused request), so write errors are not
        // failures here; the response says what happened.
        let _ = stream.write_all(head.as_bytes());
        if let Some(body) = body {
            let _ = stream.write_all(body.as_bytes());
        }
        let _ = stream.flush();

        stream
    }

    /// Send a request and read the head of the response.
    pub fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> HttpResponse {
        let stream = self.write(method, path, headers, body);
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("status line");
        let status: u16 = line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("bad status line: {line:?}"));
        let mut parsed = Vec::new();
        loop {
            line.clear();
            reader.read_line(&mut line).expect("header line");
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                parsed.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        let get = |name: &str| {
            parsed
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        HttpResponse {
            status,
            chunked: get("transfer-encoding").is_some_and(|v| v.contains("chunked")),
            length: get("content-length").and_then(|v| v.parse().ok()),
            headers: parsed,
            reader,
            pending: String::new(),
            ended: false,
        }
    }

    /// POST a JSON-RPC message to the MCP endpoint.
    pub fn post(&self, headers: &[(&str, &str)], message: &Value) -> HttpResponse {
        self.send("POST", "/mcp", headers, Some(&message.to_string()))
    }

    /// Open a legacy session at `version`; returns the session id.
    pub fn initialize(&self, version: &str) -> String {
        let mut response = self.post(
            &[],
            &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name": "nebula-e2e", "version": "0"}
            }}),
        );
        response.expect_status(200);
        let session = response
            .header("mcp-session-id")
            .expect("session id")
            .to_string();
        let reply = response.result_for(0);
        assert!(reply["result"]["protocolVersion"].is_string(), "{reply}");
        let done = self.post(
            &[
                ("Mcp-Session-Id", &session),
                ("MCP-Protocol-Version", version),
            ],
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        );
        assert!(done.status < 300, "initialized: {}", done.status);
        session
    }

    /// POST a message inside a legacy session.
    pub fn session_post(&self, session: &str, message: &Value) -> HttpResponse {
        self.post(
            &[
                ("Mcp-Session-Id", session),
                ("MCP-Protocol-Version", "2025-11-25"),
            ],
            message,
        )
    }

    /// Call a tool inside a legacy session and return the JSON-RPC response.
    pub fn session_call(&self, session: &str, id: i64, tool: &str, arguments: Value) -> Value {
        let mut response = self.session_post(
            session,
            &json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments}}),
        );
        response.expect_status(200);
        response.result_for(id)
    }

    /// A stateless 2026-07-28 request.
    pub fn modern(&self, id: i64, method: &str, mut params: Value) -> HttpResponse {
        params["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2026-07-28");
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
        let name = params["name"].as_str().unwrap_or_default().to_string();
        let mut headers = vec![
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", method),
        ];
        if !name.is_empty() {
            headers.push(("Mcp-Name", name.as_str()));
        }
        self.post(
            &headers,
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )
    }

    /// Call a tool statelessly and return the JSON-RPC response.
    pub fn modern_call(&self, id: i64, tool: &str, arguments: Value) -> Value {
        let mut response = self.modern(
            id,
            "tools/call",
            json!({"name": tool, "arguments": arguments}),
        );
        response.expect_status(200);
        response.result_for(id)
    }
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Read more of the body into `pending`. Returns false at the end.
    fn fill(&mut self) -> bool {
        if self.ended {
            return false;
        }
        if self.chunked {
            let mut size = String::new();
            if self.reader.read_line(&mut size).unwrap_or(0) == 0 {
                self.ended = true;
                return false;
            }
            let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .unwrap_or(0);
            if n == 0 {
                self.ended = true;
                return false;
            }
            let mut chunk = vec![0u8; n + 2];
            if self.reader.read_exact(&mut chunk).is_err() {
                self.ended = true;
                return false;
            }
            self.pending.push_str(&String::from_utf8_lossy(&chunk[..n]));
            true
        } else {
            let mut body = Vec::new();
            match self.length {
                Some(n) => {
                    body.resize(n, 0);
                    let _ = self.reader.read_exact(&mut body);
                }
                None => {
                    let _ = self.reader.read_to_end(&mut body);
                }
            }
            self.pending.push_str(&String::from_utf8_lossy(&body));
            self.ended = true;
            true
        }
    }

    /// Panic, showing the body, unless the status is `want`.
    pub fn expect_status(&mut self, want: u16) {
        let status = self.status;
        if status != want {
            panic!("expected HTTP {want}, got {status}: {}", self.text());
        }
    }

    /// The whole body as text.
    pub fn text(&mut self) -> String {
        while self.fill() {}
        std::mem::take(&mut self.pending)
    }

    /// The next JSON message: the body itself for a JSON response, or the
    /// next event of an event stream. `None` when the body ends.
    pub fn next_message(&mut self) -> Option<Value> {
        let is_stream = self
            .header("content-type")
            .is_some_and(|t| t.starts_with("text/event-stream"));
        if !is_stream {
            let text = self.text();
            return serde_json::from_str(&text).ok();
        }
        loop {
            while let Some(end) = self.pending.find("\n\n") {
                let event: String = self.pending.drain(..end + 2).collect();
                let data: Vec<&str> = event
                    .lines()
                    .filter_map(|l| l.strip_prefix("data:"))
                    .map(str::trim_start)
                    .collect();
                if let Ok(value) = serde_json::from_str::<Value>(&data.join("\n")) {
                    return Some(value);
                }
            }
            if !self.fill() {
                return None;
            }
        }
    }

    /// Read messages until the response to request `id`; panics if the body
    /// ends first.
    pub fn result_for(&mut self, id: i64) -> Value {
        self.result_with_others(id).0
    }

    /// Like `result_for`, also returning the messages that came before it.
    pub fn result_with_others(&mut self, id: i64) -> (Value, Vec<Value>) {
        let mut others = Vec::new();
        while let Some(message) = self.next_message() {
            if message["id"] == json!(id) && message.get("method").is_none() {
                return (message, others);
            }
            others.push(message);
        }
        panic!("the response ended without an answer to request {id}; saw {others:?}");
    }
}
