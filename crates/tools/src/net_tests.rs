//! `net` tools driven through the dispatcher against loopback servers.

#![allow(clippy::disallowed_methods)]

use base64::Engine;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};

use crate::testkit::{text_of, HttpMock, Kit, Reply};

const LOCAL: &str = "allow_network = true\nallow_private_network = true";

fn ok(body: &str) -> Reply {
    (
        200,
        vec![("Content-Type".to_string(), "text/plain".to_string())],
        body.to_string(),
    )
}

#[tokio::test]
async fn http_requests_return_the_body_then_status_and_headers() {
    let server = HttpMock::start(|seen| match seen.target.as_str() {
        "/hello" => ok("hello there"),
        "/echo" => ok(&format!(
            "{} {} {}",
            seen.method,
            seen.header("x-trace").unwrap_or("-"),
            seen.body
        )),
        "/binary" => (200, Vec::new(), "\u{0}\u{1}".repeat(8)),
        "/big" => ok(&"x".repeat(300_000)),
        _ => (404, Vec::new(), "nope".to_string()),
    });
    let kit = Kit::new(&format!("{LOCAL}\nmax_output_bytes = 65536"));
    let url = |path: &str| format!("{}{path}", server.url());

    let out = kit
        .ok("net_http_request", json!({"url": url("/hello")}))
        .await;
    let text = text_of(&out);
    assert!(
        text.starts_with("hello there\n[net_http_request: GET "),
        "{text}"
    );
    assert!(
        text.contains("-> 200]") && text.contains("content-type: text/plain"),
        "{text}"
    );

    let out = kit
        .ok(
            "net_http_request",
            json!({"url": url("/echo"), "method": "POST", "body": "payload",
                   "headers": {"X-Trace": "t-1"}}),
        )
        .await;
    assert!(
        text_of(&out).starts_with("POST t-1 payload\n"),
        "{}",
        text_of(&out)
    );

    // An error status is still a response to read.
    let out = kit
        .ok("net_http_request", json!({"url": url("/missing")}))
        .await;
    assert!(text_of(&out).contains("-> 404"), "{}", text_of(&out));

    let out = kit
        .ok("net_http_request", json!({"url": url("/big")}))
        .await;
    let text = text_of(&out);
    assert!(
        text.contains("300000 bytes and was cut"),
        "{}",
        &text[text.len() - 300..]
    );
    assert!(text.len() < 80_000);

    for (args, prefix) in [
        (json!({"url": "file:///etc/passwd"}), "[invalid_arguments]"),
        (json!({"url": "/relative"}), "[invalid_arguments]"),
        (
            json!({"url": "http://user:pw@127.0.0.1/"}),
            "[invalid_arguments]",
        ),
        (
            json!({"url": url("/hello"), "method": "TRACE"}),
            "[invalid_arguments]",
        ),
    ] {
        let err = kit.err("net_http_request", args.clone()).await;
        assert!(err.starts_with(prefix), "{args}: {err}");
    }
}

#[tokio::test]
async fn destinations_follow_the_network_policy() {
    let server = HttpMock::start(|_| ok("internal"));
    let local = json!({"url": format!("{}/x", server.url())});

    // Network off: refused by the dispatcher, for every net tool.
    let kit = Kit::new("");
    for (tool, args) in [
        ("net_http_request", local.clone()),
        ("net_dns_lookup", json!({"host": "localhost"})),
        (
            "net_tcp_connect",
            json!({"host": "127.0.0.1", "port": server.port}),
        ),
        ("net_ping", json!({"host": "127.0.0.1"})),
    ] {
        let err = kit.err(tool, args).await;
        assert!(
            err.starts_with("[permission_denied]") && err.contains("allow_network"),
            "{tool}: {err}"
        );
    }

    // Network on: loopback, private and metadata addresses stay out of reach.
    kit.reconfigure("allow_network = true");
    let port = server.port;
    for (tool, args) in [
        ("net_http_request", local.clone()),
        (
            "net_http_request",
            json!({"url": "http://169.254.169.254/latest/meta-data/"}),
        ),
        ("net_http_request", json!({"url": "http://[::1]/"})),
        ("net_http_request", json!({"url": "http://0x7f.1/"})),
        (
            "net_download",
            json!({"url": local["url"], "outputPath": "got.txt"}),
        ),
        ("net_dns_lookup", json!({"host": "localhost"})),
        (
            "net_tcp_connect",
            json!({"host": "127.0.0.1", "port": port}),
        ),
        ("net_latency", json!({"host": "10.0.0.1"})),
        ("net_tls_info", json!({"host": "192.168.1.1"})),
        (
            "net_websocket",
            json!({"url": format!("ws://127.0.0.1:{port}/")}),
        ),
        ("net_ping", json!({"host": "127.0.0.1"})),
        ("net_iperf", json!({"server": "127.0.0.1"})),
        ("net_quic_probe", json!({"url": "https://127.0.0.1/"})),
    ] {
        let err = kit.err(tool, args.clone()).await;
        assert!(
            err.starts_with("[network_not_allowed]") || err.starts_with("[invalid_arguments]"),
            "{tool} {args}: {err}"
        );
    }
    assert!(server.seen().is_empty(), "something reached the server");
    assert!(!kit.exists("got.txt"));

    // A host list narrows further.
    kit.reconfigure(&format!("{LOCAL}\nallowed_hosts = [\"example.com\"]"));
    let err = kit.err("net_http_request", local).await;
    assert!(err.starts_with("[network_not_allowed]"), "{err}");
}

#[tokio::test]
async fn downloads_land_whole_or_not_at_all() {
    let server = HttpMock::start(|seen| match seen.target.as_str() {
        "/file" => ok("downloaded content"),
        "/large" => ok(&"y".repeat(5000)),
        _ => (404, Vec::new(), "missing".to_string()),
    });
    let kit = Kit::new(LOCAL);
    let url = |path: &str| format!("{}{path}", server.url());
    let leftovers = |kit: &Kit| {
        std::fs::read_dir(&kit.root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".part"))
            .count()
    };

    let done = kit
        .json(
            "net_download",
            json!({"url": url("/file"), "outputPath": "got.txt"}),
        )
        .await;
    assert_eq!(done["bytes"], 18);
    assert_eq!(done["contentType"], "text/plain");
    assert_eq!(kit.read("got.txt"), "downloaded content");

    // An existing file is kept unless overwrite is asked for.
    kit.write("keep.txt", "original");
    let err = kit
        .err(
            "net_download",
            json!({"url": url("/file"), "outputPath": "keep.txt"}),
        )
        .await;
    assert!(
        err.starts_with("[invalid_arguments]") && err.contains("overwrite"),
        "{err}"
    );
    // A failed replacement leaves the original as it was.
    for path in ["/missing", "/large"] {
        let err = kit
            .err(
                "net_download",
                json!({"url": url(path), "outputPath": "keep.txt", "overwrite": true,
                       "maxBytes": 100}),
            )
            .await;
        assert!(
            err.starts_with("[execution]") || err.starts_with("[limit_exceeded]"),
            "{path}: {err}"
        );
        assert_eq!(kit.read("keep.txt"), "original");
    }
    assert_eq!(leftovers(&kit), 0, "a partial download was left behind");
    kit.json(
        "net_download",
        json!({"url": url("/file"), "outputPath": "keep.txt", "overwrite": true}),
    )
    .await;
    assert_eq!(kit.read("keep.txt"), "downloaded content");

    // The file policy applies to the destination, before any request.
    let before = server.seen().len();
    let outside = kit.outside.join("x.txt").display().to_string();
    for (path, prefix) in [
        (outside.as_str(), "[path_not_allowed]"),
        (".env", "[permission_denied]"),
        (".git/hooks/pre-commit", "[permission_denied]"),
    ] {
        let err = kit
            .err(
                "net_download",
                json!({"url": url("/file"), "outputPath": path}),
            )
            .await;
        assert!(err.starts_with(prefix), "{path}: {err}");
    }
    assert_eq!(server.seen().len(), before);
    assert!(!kit.outside.join("x.txt").exists());
}

#[tokio::test]
async fn probes_report_reachability() {
    let server = HttpMock::start(|_| ok("x"));
    let kit = Kit::new(LOCAL);

    let found = kit
        .json("net_dns_lookup", json!({"host": "localhost"}))
        .await;
    let addresses = found["addresses"].to_string();
    assert!(
        addresses.contains("127.0.0.1") || addresses.contains("::1"),
        "{found}"
    );

    let open = kit
        .json(
            "net_tcp_connect",
            json!({"host": "127.0.0.1", "port": server.port}),
        )
        .await;
    assert_eq!(open["reachable"], true, "{open}");
    assert_eq!(open["address"], format!("127.0.0.1:{}", server.port));

    // A port nothing listens on: bind one, note it, release it.
    let free = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let closed = kit
        .json(
            "net_tcp_connect",
            json!({"host": "127.0.0.1", "port": free, "timeoutMs": 1000}),
        )
        .await;
    assert_eq!(closed["reachable"], false, "{closed}");
    assert!(closed["error"].is_string());

    let timing = kit
        .json(
            "net_latency",
            json!({"host": "127.0.0.1", "port": server.port, "count": 3}),
        )
        .await;
    assert_eq!(timing["attempts"], 3);
    assert_eq!(timing["failures"], 0);
    assert!(timing["maxMs"].as_u64().unwrap() >= timing["minMs"].as_u64().unwrap());
}

/// 0.1 panicked on every `net.tls_info` call, before connecting, because no
/// TLS provider was installed. A call must be answered: here with a
/// handshake error, since the peer does not speak TLS.
#[tokio::test]
async fn a_tls_probe_is_answered() {
    let server = HttpMock::start(|_| ok("not tls"));
    let kit = Kit::new(LOCAL);
    let err = kit
        .err(
            "net_tls_info",
            json!({"host": "127.0.0.1", "port": server.port, "timeoutMs": 3000}),
        )
        .await;
    assert!(!err.starts_with("[internal]"), "{err}");
    assert!(err.to_lowercase().contains("tls"), "{err}");
}

#[test]
fn certificates_are_described() {
    const DER: &str = "MIIB0zCCAXmgAwIBAgIUYYnRKVSy/NfWd8hGAk4X4CBjeNowCgYIKoZIzj0EAwIwJzEUMBIGA1UEAwwLbmVidWxhLnRlc3QxDzANBgNVBAoMBk5lYnVsYTAgFw0yNjExMTUwMDE2NDdaGA8yMTI2MTAyMjAwMTY0N1owJzEUMBIGA1UEAwwLbmVidWxhLnRlc3QxDzANBgNVBAoMBk5lYnVsYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABN8yX67lPLgZnvULwOZunEFgytvvc+1h5LhQ5bpXz7DhLznSumY2o09PMKWyHSS61tKM92C6R2QxP15yxsbf0tCjgYAwfjAdBgNVHQ4EFgQUc3iWFeS7alSINL+ocaQLC+v/aCUwHwYDVR0jBBgwFoAUc3iWFeS7alSINL+ocaQLC+v/aCUwDwYDVR0TAQH/BAUwAwEB/zArBgNVHREEJDAiggtuZWJ1bGEudGVzdIINKi5uZWJ1bGEudGVzdIcEfwAAATAKBggqhkjOPQQDAgNIADBFAiEAtjQkWSd//lPW1yR7GB+d0WPW7QdOlufngMdXf5Rb+CMCIC9Ajl0hyHE4w+9iN+N4IS0mGtNF9ZlO7i2ggmFGCwdC";
    let der = base64::engine::general_purpose::STANDARD
        .decode(DER)
        .unwrap();
    let described = super::certificate(&der);
    assert!(
        described["subject"]
            .as_str()
            .unwrap()
            .contains("CN=nebula.test"),
        "{described}"
    );
    assert_eq!(
        described["names"],
        json!(["nebula.test", "*.nebula.test", "127.0.0.1"])
    );
    assert_eq!(described["notBefore"], "2026-11-15T00:16:47Z");
    assert!(described["notAfter"]
        .as_str()
        .unwrap()
        .starts_with("2126-10-22"));
    assert!(described["daysLeft"].as_i64().unwrap() > 30_000);
    assert_eq!(described["sha256"].as_str().unwrap().len(), 64);

    let garbage = super::certificate(b"not a certificate");
    assert_eq!(garbage["notAfter"], Value::Null);
}

#[tokio::test]
async fn a_websocket_exchange_sends_and_collects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let _ = socket.send("welcome".into()).await;
                while let Some(Ok(message)) = socket.next().await {
                    if message.is_text() {
                        let text = message.into_text().unwrap();
                        if text.as_str() == "bye" {
                            let _ = socket.close(None).await;
                            return;
                        }
                        let _ = socket.send(format!("echo: {text}").into()).await;
                        let _ = socket.send(vec![1u8, 2, 3].into()).await;
                    }
                }
            });
        }
    });
    let kit = Kit::new(LOCAL);
    let url = format!("ws://127.0.0.1:{port}/socket");

    let got = kit
        .json(
            "net_websocket",
            json!({"url": url, "send": "hi", "readMs": 1500, "maxMessages": 3}),
        )
        .await;
    assert_eq!(
        got["messages"],
        json!([
            {"kind": "text", "data": "welcome"},
            {"kind": "text", "data": "echo: hi"},
            {"kind": "binary", "data": "AQID"},
        ])
    );
    assert_eq!(got["closedByPeer"], false);

    let got = kit
        .json(
            "net_websocket",
            json!({"url": url, "send": "bye", "readMs": 3000}),
        )
        .await;
    assert_eq!(got["closedByPeer"], true, "{got}");

    let err = kit
        .err(
            "net_websocket",
            json!({"url": format!("http://127.0.0.1:{port}/")}),
        )
        .await;
    assert!(err.starts_with("[invalid_arguments]"), "{err}");
}

#[cfg(unix)]
#[tokio::test]
async fn system_programs_get_checked_arguments() {
    let kit = Kit::new(LOCAL);
    // Capturing is elevated: the gate comes first.
    let capture = json!({"interface": "lo", "outputPath": "cap.pcap", "durationSecs": 1});
    let err = kit.err("net_packet_capture", capture.clone()).await;
    assert!(
        err.starts_with("[permission_denied]") && err.contains("allow_elevated"),
        "{err}"
    );

    kit.reconfigure(&format!("{LOCAL}\nallow_elevated = true"));
    let outside = kit.outside.join("cap.pcap").display().to_string();
    for (args, prefix) in [
        (
            json!({"interface": "-w/tmp/x", "outputPath": "cap.pcap"}),
            "[invalid_arguments]",
        ),
        (
            json!({"interface": "lo; id", "outputPath": "cap.pcap"}),
            "[invalid_arguments]",
        ),
        (
            json!({"interface": "lo", "outputPath": "cap.pcap", "filter": "port 80; touch x"}),
            "[invalid_arguments]",
        ),
        (
            json!({"interface": "lo", "outputPath": "cap.pcap", "filter": "$(id)"}),
            "[invalid_arguments]",
        ),
        (
            json!({"interface": "lo", "outputPath": outside}),
            "[path_not_allowed]",
        ),
        (
            json!({"interface": "lo", "outputPath": ".env"}),
            "[permission_denied]",
        ),
    ] {
        let err = kit.err("net_packet_capture", args.clone()).await;
        assert!(err.starts_with(prefix), "{args}: {err}");
    }
    assert!(!kit.exists("x") && !kit.outside.join("cap.pcap").exists());

    // Whatever the machine has installed, the answer is a result or a clear
    // failure, and the host was vetted first.
    for (tool, args) in [
        (
            "net_ping",
            json!({"host": "127.0.0.1", "count": 1, "timeoutSecs": 5}),
        ),
        (
            "net_quic_probe",
            json!({"url": "https://127.0.0.1:9/", "timeoutSecs": 3}),
        ),
        (
            "net_iperf",
            json!({"server": "127.0.0.1", "port": 9, "durationSecs": 1}),
        ),
    ] {
        let text = match kit.call(tool, args).await {
            Ok(out) => text_of(&out),
            Err(failure) => failure.text,
        };
        assert!(!text.starts_with("[internal]"), "{tool}: {text}");
    }
    for (tool, args) in [
        ("net_quic_probe", json!({"url": "http://example.com/"})),
        ("net_quic_probe", json!({"url": "https://-o/tmp/x"})),
        ("net_ping", json!({"host": "-c 1 127.0.0.1"})),
        ("net_iperf", json!({"server": "--logfile=/tmp/x"})),
    ] {
        let err = kit.err(tool, args.clone()).await;
        assert!(
            err.starts_with("[invalid_arguments]")
                || err.starts_with("[network_not_allowed]")
                || err.starts_with("[io]"),
            "{tool} {args}: {err}"
        );
    }
}
