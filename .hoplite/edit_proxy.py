p = 'crates/core/src/net.rs'
s = open(p).read()

proxy = r'''
// ---------------------------------------------------------------------------
// A forward proxy for programs that make their own connections
// ---------------------------------------------------------------------------

/// Largest request head the proxy reads before giving up.
const PROXY_HEAD_LIMIT: usize = 16 * 1024;

/// A forward proxy on loopback, for an external program that makes its own
/// connections (a browser). Each connection the program opens through it is
/// vetted and pinned exactly like one the server makes itself, so the
/// network policy holds for the program too, provided it is started so that
/// the proxy is its only way out. Stops when dropped.
pub struct Proxy {
    addr: SocketAddr,
    refused: Arc<std::sync::atomic::AtomicU64>,
    _stop: tokio_util::sync::DropGuard,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy").field("addr", &self.addr).finish()
    }
}

impl Proxy {
    /// The proxy as a URL to configure the program with.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Connections refused so far because policy does not allow their
    /// destination.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.refused.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Net {
    /// Start a [`Proxy`] that enforces this capability's policy.
    pub async fn proxy(&self) -> Result<Proxy> {
        self.require_enabled()?;
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| ToolError::Io(format!("starting the proxy failed: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| ToolError::Io(format!("starting the proxy failed: {e}")))?;
        let stop = self.cancel.child_token();
        let refused = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (net, counter, stopped) = (self.clone(), refused.clone(), stop.clone());
        tokio::spawn(async move {
            loop {
                let client = tokio::select! {
                    () = stopped.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((client, _)) => client,
                        Err(_) => continue,
                    },
                };
                let (net, counter, stopped) = (net.clone(), counter.clone(), stopped.clone());
                tokio::spawn(async move {
                    tokio::select! {
                        () = stopped.cancelled() => {}
                        () = proxy_connection(&net, client, &counter) => {}
                    }
                });
            }
        });
        Ok(Proxy {
            addr,
            refused,
            _stop: stop.drop_guard(),
        })
    }
}

/// Serve one client connection: a `CONNECT` tunnel, or one plain-HTTP
/// request after which the connection closes, so that the next request is
/// vetted on its own.
async fn proxy_connection(
    net: &Net,
    mut client: TcpStream,
    refused: &std::sync::atomic::AtomicU64,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if buf.len() > PROXY_HEAD_LIMIT {
            let _ = client
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                .await;
            return;
        }
        match client.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request = lines.next().unwrap_or_default().split(' ');
    let (method, target, version) = (
        request.next().unwrap_or_default(),
        request.next().unwrap_or_default(),
        request.next().unwrap_or("HTTP/1.1"),
    );
    let connect_timeout = Duration::from_secs(20);

    let outcome: Result<(TcpStream, Vec<u8>)> = async {
        if method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) = target
                .rsplit_once(':')
                .and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?)))
                .ok_or_else(|| ToolError::invalid("CONNECT needs host:port"))?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let (upstream, _) = net.connect_tcp(host, port, connect_timeout).await?;
            Ok((upstream, Vec::new()))
        } else {
            let parsed = parse_url(target, &["http"], false)?;
            let path = match parsed.url.query() {
                Some(q) => format!("{}?{q}", parsed.url.path()),
                None => parsed.url.path().to_string(),
            };
            let mut forward = format!("{method} {path} {version}\r\n");
            for line in lines {
                let name = line.split(':').next().unwrap_or_default();
                if line.is_empty()
                    || name.eq_ignore_ascii_case("connection")
                    || name.to_ascii_lowercase().starts_with("proxy-")
                {
                    continue;
                }
                forward.push_str(line);
                forward.push_str("\r\n");
            }
            forward.push_str("Connection: close\r\n\r\n");
            let (upstream, _) = net
                .connect_tcp(&parsed.host.name(), parsed.port, connect_timeout)
                .await?;
            let mut first = forward.into_bytes();
            first.extend_from_slice(&buf[head_end..]);
            Ok((upstream, first))
        }
    }
    .await;

    let (mut upstream, first) = match outcome {
        Ok(ready) => ready,
        Err(error) => {
            let status = if error.is_denial() || matches!(error, ToolError::InvalidArguments(_)) {
                refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                "403 Forbidden"
            } else {
                "502 Bad Gateway"
            };
            let body = format!("{error}\n");
            let _ = client
                .write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await;
            return;
        }
    };
    let ready = if first.is_empty() {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
    } else {
        upstream.write_all(&first).await
    };
    if ready.is_ok() {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    }
}
'''

tests = r'''
    /// Send `request` to the proxy and return everything it answers.
    async fn through_proxy(proxy: &Proxy, request: &str) -> String {
        let addr = proxy.url().trim_start_matches("http://").to_string();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await;
        String::from_utf8_lossy(&answer).into_owned()
    }

    #[tokio::test]
    async fn the_proxy_forwards_what_policy_allows() {
        let port = serve(|head| ok(&format!("seen: {}", head.lines().next().unwrap_or("")))).await;
        let proxy = net(true, true, &[]).proxy().await.unwrap();

        // Plain HTTP: the absolute URL becomes a path, proxy headers go.
        let answer = through_proxy(
            &proxy,
            &format!(
                "GET http://127.0.0.1:{port}/page?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
                 Proxy-Connection: keep-alive\r\n\r\n"
            ),
        )
        .await;
        assert!(answer.contains("seen: GET /page?q=1 HTTP/1.1"), "{answer}");

        // A tunnel: bytes pass through untouched.
        let addr = proxy.url().trim_start_matches("http://").to_string();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut established = [0u8; 39];
        stream.read_exact(&mut established).await.unwrap();
        assert!(established.starts_with(b"HTTP/1.1 200"));
        stream
            .write_all(b"GET /tunnelled HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await;
        assert!(String::from_utf8_lossy(&answer).contains("seen: GET /tunnelled"));
        assert_eq!(proxy.refused(), 0);
    }

    #[tokio::test]
    async fn the_proxy_refuses_what_policy_refuses() {
        let port = serve(|_| ok("internal")).await;
        // Network on, private addresses off: loopback is out of reach.
        let proxy = net(true, false, &[]).proxy().await.unwrap();
        for request in [
            format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\n\r\n"),
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n"),
            "CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n".to_string(),
            "CONNECT [::1]:80 HTTP/1.1\r\n\r\n".to_string(),
            "GET http://0x7f.0.0.1/ HTTP/1.1\r\n\r\n".to_string(),
            "GET file:///etc/passwd HTTP/1.1\r\n\r\n".to_string(),
            "GET /etc/passwd HTTP/1.1\r\n\r\n".to_string(),
        ] {
            let answer = through_proxy(&proxy, &request).await;
            assert!(answer.starts_with("HTTP/1.1 403"), "{request}: {answer}");
            assert!(!answer.contains("internal"), "{answer}");
        }
        assert_eq!(proxy.refused(), 7);

        // A host list applies as well.
        let listed = net(true, true, &["example.com"]).proxy().await.unwrap();
        let answer = through_proxy(
            &listed,
            &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n"),
        )
        .await;
        assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");

        // No proxy at all while the network is off, and none after a drop.
        assert!(net(false, false, &[]).proxy().await.is_err());
        let addr = proxy.url().trim_start_matches("http://").to_string();
        drop(proxy);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(TcpStream::connect(addr).await.is_err());
    }
'''

marker = '#[cfg(test)]\nmod tests {'
i = s.index(marker)
s = s[:i] + proxy.lstrip('\n') + '\n' + s[i:]
# Append tests before the final closing brace of the tests module.
j = s.rstrip().rfind('}')
s = s[:j] + tests.lstrip('\n') + '}\n'
open(p, 'w').write(s)
