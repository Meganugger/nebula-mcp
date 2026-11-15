//! Network tools.
//!
//! Connections the server makes itself (`net_http_request`, `net_download`,
//! `net_dns_lookup`, `net_tcp_connect`, `net_latency`, `net_tls_info`,
//! `net_websocket`) go through the vetted connector of `nebula-mcp-core`: the
//! address that was checked is the address connected to, and redirects are
//! checked again.
//!
//! `net_ping`, `net_iperf`, `net_quic_probe` and `net_packet_capture` run a
//! system program. The server resolves and vets the destination first and
//! hands the program the address, not the name, so the program cannot be
//! steered elsewhere by a second lookup.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use futures::{SinkExt, StreamExt};
use nebula_mcp_core::args::Args;
use nebula_mcp_core::fs::WriteMode;
use nebula_mcp_core::net::HttpRequest;
use nebula_mcp_core::policy::Access;
use nebula_mcp_core::process::{Command, Exec};
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::tool::Content;
use nebula_mcp_core::{
    Category, Effects, Gate, Platforms, Result, Tool, ToolContext, ToolError, ToolOutput,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

use crate::common::{clip, handler, spec, tool, SpecExt};
use crate::terminal::render_run;

const READ: Effects = Effects::read_only().network();
const DEFAULT_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024;
const TIMEOUT_HELP: &str = "Seconds allowed (default and ceiling set by the operator).";
const HOST_HELP: &str = "Host name or IP address.";

/// The `net` tools.
#[allow(clippy::too_many_lines)]
pub(crate) fn tools() -> Vec<Arc<dyn Tool>> {
    let c = Category::Net;
    let probe_ms = |s: ObjectSchema| {
        s.integer_range(
            "timeoutMs",
            "Milliseconds to wait (default 5000).",
            100,
            60_000,
            false,
        )
    };
    vec![
        tool(
            spec(
                "net_http_request",
                c,
                "HTTP request",
                "Send an HTTP or HTTPS request and return the response body, then the status \
                 and headers. Redirects are followed and each hop is checked against the \
                 network policy. Bodies beyond the output limit are cut.",
                ObjectSchema::new()
                    .string("url", "Absolute http:// or https:// URL.", true)
                    .string_enum(
                        "method",
                        "HTTP method (default GET).",
                        &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                        false,
                    )
                    .string_map("headers", "Request headers.", false)
                    .string("body", "Request body, sent as given.", false)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                Effects::writes().overwrites().network(),
            ),
            handler!(http_request),
        ),
        tool(
            spec(
                "net_download",
                c,
                "Download file",
                "Download a URL into a file inside an allowed directory, streaming to disk. \
                 Fails if the file exists unless `overwrite`. Nothing is kept when the server \
                 answers with an error or the size limit is passed.",
                ObjectSchema::new()
                    .string("url", "Absolute http:// or https:// URL.", true)
                    .string("outputPath", "File to write.", true)
                    .boolean("overwrite", "Replace the file if it exists.", false)
                    .integer_min(
                        "maxBytes",
                        "Largest accepted size (default 100 MiB).",
                        1,
                        false,
                    )
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                Effects::writes().overwrites().network(),
            )
            .returns(
                ObjectSchema::open()
                    .string("path", "The file written.", true)
                    .integer("bytes", "Bytes written.", true)
                    .integer("status", "HTTP status.", true)
                    .nullable_string("contentType", "Content-Type the server sent.", true)
                    .string(
                        "finalUrl",
                        "URL that produced the content, after redirects.",
                        true,
                    )
                    .build(),
            ),
            handler!(download),
        ),
        tool(
            spec(
                "net_dns_lookup",
                c,
                "Resolve host name",
                "Resolve a host name to its addresses. Names that resolve to addresses the \
                 network policy does not permit are refused.",
                ObjectSchema::new().string("host", HOST_HELP, true).build(),
                READ,
            )
            .returns(
                ObjectSchema::open()
                    .string("host", "The name looked up.", true)
                    .string_array("addresses", "IPv4 and IPv6 addresses.", true)
                    .build(),
            ),
            handler!(dns_lookup),
        ),
        tool(
            spec(
                "net_tcp_connect",
                c,
                "Test TCP port",
                "Check whether a TCP port accepts connections, and how long connecting takes. \
                 Nothing is sent.",
                probe_ms(
                    ObjectSchema::new()
                        .string("host", HOST_HELP, true)
                        .integer_range("port", "TCP port.", 1, 65_535, true),
                )
                .build(),
                READ,
            )
            .returns(
                ObjectSchema::open()
                    .boolean("reachable", "Whether the connection was accepted.", true)
                    .nullable_string("address", "Address that answered.", true)
                    .nullable_integer("elapsedMs", "Time to connect.", true)
                    .nullable_string("error", "Why it failed.", true)
                    .build(),
            ),
            handler!(tcp_connect),
        ),
        tool(
            spec(
                "net_latency",
                c,
                "Measure latency",
                "Measure how long TCP connections to a host take, over several attempts. Works \
                 where ICMP ping is blocked.",
                probe_ms(
                    ObjectSchema::new()
                        .string("host", HOST_HELP, true)
                        .integer_range("port", "TCP port (default 443).", 1, 65_535, false)
                        .integer_range("count", "Attempts (default 5).", 1, 20, false),
                )
                .build(),
                READ,
            )
            .returns(
                ObjectSchema::open()
                    .integer("attempts", "Connections attempted.", true)
                    .integer("failures", "Attempts that failed.", true)
                    .nullable_integer("minMs", "Fastest.", true)
                    .nullable_integer("avgMs", "Mean.", true)
                    .nullable_integer("maxMs", "Slowest.", true)
                    .build(),
            ),
            handler!(latency),
        ),
        tool(
            spec(
                "net_tls_info",
                c,
                "Inspect TLS",
                "Complete a verified TLS handshake and report the protocol, cipher and the \
                 certificate chain with names and validity. A certificate that is not trusted or \
                 does not match the host is an error that says why.",
                probe_ms(
                    ObjectSchema::new()
                        .string("host", HOST_HELP, true)
                        .integer_range("port", "TCP port (default 443).", 1, 65_535, false),
                )
                .build(),
                READ,
            )
            .returns(
                ObjectSchema::open()
                    .string("protocol", "TLS version.", true)
                    .string("cipherSuite", "Negotiated cipher suite.", true)
                    .nullable_string("alpn", "Negotiated application protocol.", true)
                    .string("address", "Address that answered.", true)
                    .object_array(
                        "certificates",
                        "The chain the server sent, leaf first.",
                        ObjectSchema::open()
                            .string("subject", "Subject name.", true)
                            .string("issuer", "Issuer name.", true)
                            .string_array("names", "Subject alternative names.", true)
                            .nullable_string("notBefore", "Start of validity, RFC 3339.", true)
                            .nullable_string("notAfter", "End of validity, RFC 3339.", true)
                            .nullable_integer("daysLeft", "Whole days until it expires.", true)
                            .string("sha256", "SHA-256 fingerprint of the certificate.", true),
                        true,
                    )
                    .build(),
            ),
            handler!(tls_info),
        ),
        tool(
            spec(
                "net_websocket",
                c,
                "WebSocket exchange",
                "Open a WebSocket, optionally send one text message, collect the messages that \
                 arrive within a time window, then close.",
                ObjectSchema::new()
                    .string("url", "ws:// or wss:// URL.", true)
                    .string("send", "Text message to send after connecting.", false)
                    .integer_range(
                        "readMs",
                        "How long to collect messages (default 2000).",
                        0,
                        60_000,
                        false,
                    )
                    .integer_range(
                        "maxMessages",
                        "Stop after this many messages (default 10).",
                        1,
                        100,
                        false,
                    )
                    .build(),
                Effects::writes().network(),
            )
            .returns(
                ObjectSchema::open()
                    .object_array(
                        "messages",
                        "Messages received, in order.",
                        ObjectSchema::open()
                            .string("kind", "text or binary.", true)
                            .string("data", "The text, or base64 for binary.", true),
                        true,
                    )
                    .boolean(
                        "closedByPeer",
                        "Whether the other side closed the socket.",
                        true,
                    )
                    .build(),
            ),
            handler!(websocket),
        ),
        tool(
            spec(
                "net_ping",
                c,
                "Ping",
                "Send ICMP echo requests with the system's ping and return its output. The \
                 server resolves and checks the host first.",
                ObjectSchema::new()
                    .string("host", HOST_HELP, true)
                    .integer_range("count", "Echo requests (default 4).", 1, 20, false)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                READ.exec(Exec::Programs(&["ping", "ping6"])),
            ),
            handler!(ping),
        ),
        tool(
            spec(
                "net_iperf",
                c,
                "Measure throughput",
                "Measure throughput to an iperf3 server with the system's iperf3 and return its \
                 report. Needs iperf3 installed. The project's CI does not exercise this tool.",
                ObjectSchema::new()
                    .string(
                        "server",
                        "Host name or IP address of the iperf3 server.",
                        true,
                    )
                    .integer_range("port", "Server port (default 5201).", 1, 65_535, false)
                    .integer_range("durationSecs", "Test length (default 5).", 1, 60, false)
                    .boolean("reverse", "Measure server to client instead.", false)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                Effects::writes()
                    .network()
                    .exec(Exec::Programs(&["iperf3"])),
            ),
            handler!(iperf),
        ),
        tool(
            spec(
                "net_quic_probe",
                c,
                "Probe HTTP/3",
                "Check whether an https:// URL answers over HTTP/3 (QUIC), using the system's \
                 curl, which must be built with HTTP/3. Reports the HTTP version and status.",
                ObjectSchema::new()
                    .string("url", "https:// URL.", true)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                READ.exec(Exec::Programs(&["curl"])),
            ),
            handler!(quic_probe),
        ),
        tool(
            spec(
                "net_packet_capture",
                c,
                "Capture packets",
                "Capture traffic on an interface into a pcap file with tcpdump, for a fixed \
                 time. Sees everything on that interface, needs capture privileges, and is \
                 elevated. The project's CI does not exercise this tool.",
                ObjectSchema::new()
                    .string("interface", "Interface name, for example eth0.", true)
                    .string("outputPath", "pcap file to write.", true)
                    .integer_range(
                        "durationSecs",
                        "Capture length (default 10).",
                        1,
                        300,
                        false,
                    )
                    .string(
                        "filter",
                        "Capture filter, for example `tcp port 443`.",
                        false,
                    )
                    .build(),
                Effects::writes()
                    .elevated(Gate::Always)
                    .exec(Exec::Programs(&["tcpdump"])),
            )
            .on(Platforms::UNIX),
            handler!(packet_capture),
        ),
    ]
}

fn port(a: &Args<'_>, key: &str, default: u16) -> Result<u16> {
    match a.opt_u64(key)? {
        None => Ok(default),
        Some(p) => u16::try_from(p)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| ToolError::invalid(format!("`{key}` must be between 1 and 65535"))),
    }
}

fn wait(a: &Args<'_>, ctx: &ToolContext) -> Result<Duration> {
    Ok(
        Duration::from_millis(a.u64_or("timeoutMs", 5000)?.clamp(100, 60_000))
            .min(ctx.timeout(None)),
    )
}

// ---------------------------------------------------------------------------
// Connections the server makes
// ---------------------------------------------------------------------------

/// Headers worth showing first; the rest follow in the order received.
fn render_headers(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .take(60)
        .map(|(k, v)| format!("{k}: {}", clip(v, 300)))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn http_request(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let method = a.str_or("method", "GET")?;
    let mut req = HttpRequest::new(method, a.str("url")?);
    req.headers = a.opt_string_map("headers")?;
    req.body = a.opt_str("body")?.map(|b| b.as_bytes().to_vec());
    req.timeout = ctx.timeout(a.opt_u64("timeoutSecs")?);
    req.max_body_bytes = ctx.max_output_bytes();
    let response = ctx.net()?.http(req).await?;

    let mut content = Vec::new();
    let mut note = format!(
        "[net_http_request: {} {} -> {}",
        method, response.final_url, response.status
    );
    match String::from_utf8(response.body) {
        Ok(text) if !text.is_empty() => content.push(Content::Text(text)),
        Ok(_) => {}
        Err(binary) => note.push_str(&format!(
            "; the body is {} bytes that are not text and is not shown (use net_download)",
            binary.as_bytes().len()
        )),
    }
    if response.truncated {
        note.push_str(&match response.body_bytes_total {
            Some(total) => format!("; the body is {total} bytes and was cut at the output limit"),
            None => "; the body was cut at the output limit".to_string(),
        });
    }
    if !response.redirects.is_empty() {
        note.push_str(&format!(
            "; redirected from {}",
            response.redirects.join(" -> ")
        ));
    }
    if response.scheme_downgraded {
        note.push_str("; a redirect went from https to http");
    }
    note.push_str("]\n");
    note.push_str(&render_headers(&response.headers));
    content.push(Content::Text(note));
    Ok(ToolOutput {
        content,
        structured: None,
    })
}

async fn download(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let overwrite = a.bool_or("overwrite", false)?;
    let max_bytes = a.u64_or("maxBytes", DEFAULT_DOWNLOAD_BYTES)?;
    let mut req = HttpRequest::new("GET", a.str("url")?);
    req.timeout = ctx.timeout(a.opt_u64("timeoutSecs")?);
    // Refuse a bad destination or URL before anything is created.
    let net = ctx.net()?;
    net.vet_url(&req.url, &["http", "https"]).await?;
    let dest = ctx.write_path(a.str("outputPath")?)?;
    if !overwrite && ctx.fs().try_metadata(&dest)?.is_some() {
        return Err(ToolError::invalid(format!(
            "'{}' exists; pass overwrite to replace it",
            dest.display()
        )));
    }
    // Into a sibling first, so a failed download never damages the file
    // that is being replaced and never leaves a partial one behind.
    let name = dest
        .file_name()
        .ok_or_else(|| ToolError::invalid("`outputPath` must name a file"))?;
    let parent = ctx
        .fs()
        .parent(&dest)
        .ok_or_else(|| ToolError::invalid("`outputPath` must name a file"))?;
    let partial = ctx.fs().child(
        &parent,
        &format!(".{name}.{}.part", uuid::Uuid::new_v4().simple()),
        Access::Write,
    )?;
    let mut file = ctx.fs().create(&partial, WriteMode::CreateNew)?;
    let outcome = net.http_download(req, &mut file, max_bytes).await;
    drop(file);
    let finished = match outcome {
        Ok(d) if (200..300).contains(&d.status) => {
            ctx.fs().rename(&partial, &dest, overwrite).map(|()| d)
        }
        Ok(d) => Err(ToolError::Execution(format!(
            "the server answered {} for {}; nothing was saved",
            d.status, d.final_url
        ))),
        Err(e) => Err(e),
    };
    let done = match finished {
        Ok(done) => done,
        Err(e) => {
            let _ = ctx.fs().remove_file(&partial);
            return Err(e);
        }
    };
    let content_type = done
        .headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.clone());
    Ok(ToolOutput::json(json!({
        "path": dest.display(),
        "bytes": done.bytes_written,
        "status": done.status,
        "contentType": content_type,
        "finalUrl": done.final_url,
    })))
}

async fn dns_lookup(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let host = a.str("host")?;
    let addrs = ctx.net()?.vet(host, 443).await?;
    let addresses: Vec<String> = addrs.iter().map(|a| a.ip().to_string()).collect();
    Ok(ToolOutput::json(
        json!({"host": host, "addresses": addresses}),
    ))
}

/// One connection attempt: the address and time, or why it failed. Policy
/// refusals are errors of the call, not measurements.
async fn attempt(
    ctx: &ToolContext,
    host: &str,
    port: u16,
    wait: Duration,
) -> Result<std::result::Result<(SocketAddr, u64), String>> {
    let start = Instant::now();
    match ctx.net()?.connect_tcp(host, port, wait).await {
        Ok((stream, addr)) => {
            drop(stream);
            let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            Ok(Ok((addr, elapsed)))
        }
        Err(e @ (ToolError::Io(_) | ToolError::Timeout(_))) => Ok(Err(e.to_string())),
        Err(e) => Err(e),
    }
}

async fn tcp_connect(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let result = attempt(ctx, a.str("host")?, port(&a, "port", 0)?, wait(&a, ctx)?).await?;
    Ok(ToolOutput::json(match result {
        Ok((addr, ms)) => json!({
            "reachable": true, "address": addr.to_string(), "elapsedMs": ms, "error": null,
        }),
        Err(error) => json!({
            "reachable": false, "address": null, "elapsedMs": null, "error": error,
        }),
    }))
}

async fn latency(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let (host, port, wait) = (a.str("host")?, port(&a, "port", 443)?, wait(&a, ctx)?);
    let count = a.u64_or("count", 5)?.clamp(1, 20);
    let mut samples = Vec::new();
    for _ in 0..count {
        ctx.ensure_active()?;
        if let Ok((_, ms)) = attempt(ctx, host, port, wait).await? {
            samples.push(ms);
        }
    }
    let n = samples.len() as u64;
    Ok(ToolOutput::json(json!({
        "attempts": count,
        "failures": count - n,
        "minMs": samples.iter().min(),
        "avgMs": samples.iter().sum::<u64>().checked_div(n),
        "maxMs": samples.iter().max(),
    })))
}

fn asn1_time(t: x509_parser::time::ASN1Time) -> Option<String> {
    t.to_datetime()
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn certificate(der: &[u8]) -> Value {
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::{FromDer, X509Certificate};

    let sha256 = hex::encode(Sha256::digest(der));
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return json!({
            "subject": "(could not be parsed)", "issuer": "", "names": [],
            "notBefore": null, "notAfter": null, "daysLeft": null, "sha256": sha256,
        });
    };
    let names: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(name) => Some((*name).to_string()),
                    GeneralName::IPAddress(bytes) => match bytes.len() {
                        4 => <[u8; 4]>::try_from(*bytes)
                            .ok()
                            .map(|b| IpAddr::from(b).to_string()),
                        16 => <[u8; 16]>::try_from(*bytes)
                            .ok()
                            .map(|b| IpAddr::from(b).to_string()),
                        _ => None,
                    },
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let validity = cert.validity();
    let days_left = validity.time_to_expiration().map(|left| left.whole_days());
    json!({
        "subject": cert.subject().to_string(),
        "issuer": cert.issuer().to_string(),
        "names": names,
        "notBefore": asn1_time(validity.not_before),
        "notAfter": asn1_time(validity.not_after),
        "daysLeft": days_left,
        "sha256": sha256,
    })
}

async fn tls_info(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let conn = ctx
        .net()?
        .connect_tls(a.str("host")?, port(&a, "port", 443)?, wait(&a, ctx)?)
        .await?;
    let certificates: Vec<Value> = conn
        .peer_certificates
        .iter()
        .map(|der| certificate(der))
        .collect();
    Ok(ToolOutput::json(json!({
        "protocol": conn.protocol_version,
        "cipherSuite": conn.cipher_suite,
        "alpn": conn.alpn,
        "address": conn.remote_addr.to_string(),
        "certificates": certificates,
    })))
}

/// Send, then collect what arrives until the window closes.
async fn exchange<S>(
    ctx: &ToolContext,
    stream: S,
    url: &str,
    send: Option<&str>,
    window: Duration,
    max_messages: usize,
) -> Result<ToolOutput>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let failed = |e: tokio_tungstenite::tungstenite::Error| {
        ToolError::Execution(format!("the WebSocket exchange failed: {e}"))
    };
    let limit = ctx.max_output_bytes();
    let config = WebSocketConfig::default()
        .max_message_size(Some(limit))
        .max_frame_size(Some(limit));
    let (mut socket, _) = ctx
        .deadline(ctx.timeout(None), async {
            tokio_tungstenite::client_async_with_config(url, stream, Some(config))
                .await
                .map_err(failed)
        })
        .await?;
    if let Some(text) = send {
        socket.send(Message::text(text)).await.map_err(failed)?;
    }
    let deadline = tokio::time::Instant::now() + window;
    let mut messages = Vec::new();
    let mut closed_by_peer = false;
    let mut size = 0usize;
    while messages.len() < max_messages && size < limit {
        let next = tokio::select! {
            () = ctx.cancel().cancelled() => return Err(ToolError::Cancelled),
            next = tokio::time::timeout_at(deadline, socket.next()) => next,
        };
        match next {
            Err(_) => break,
            Ok(None | Some(Ok(Message::Close(_)))) => {
                closed_by_peer = true;
                break;
            }
            Ok(Some(Ok(Message::Text(text)))) => {
                size += text.len();
                messages.push(json!({"kind": "text", "data": text.as_str()}));
            }
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                size += bytes.len();
                let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
                messages.push(json!({"kind": "binary", "data": data}));
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(e))) => return Err(failed(e)),
        }
    }
    if !closed_by_peer {
        let _ = tokio::time::timeout(Duration::from_secs(1), socket.close(None)).await;
    }
    Ok(ToolOutput::json(
        json!({"messages": messages, "closedByPeer": closed_by_peer}),
    ))
}

async fn websocket(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let url = a.str("url")?;
    let send = a.opt_str("send")?;
    let window = Duration::from_millis(a.u64_or("readMs", 2000)?.min(60_000));
    let max_messages = a.usize_or("maxMessages", 10)?.clamp(1, 100);
    let net = ctx.net()?;
    let vetted = net.vet_url(url, &["ws", "wss"]).await?;
    let connect = Duration::from_secs(10).min(ctx.timeout(None));
    // Connecting vets again and pins the connection to what it resolved.
    if vetted.url.scheme() == "wss" {
        let conn = net
            .connect_tls_http1(&vetted.host, vetted.port, connect)
            .await?;
        exchange(
            ctx,
            conn.stream,
            vetted.url.as_str(),
            send,
            window,
            max_messages,
        )
        .await
    } else {
        let (stream, _) = net.connect_tcp(&vetted.host, vetted.port, connect).await?;
        exchange(ctx, stream, vetted.url.as_str(), send, window, max_messages).await
    }
}

// ---------------------------------------------------------------------------
// System programs, given a vetted address
// ---------------------------------------------------------------------------

/// Resolve and vet `host`; prefer IPv4, which every ping understands.
async fn vetted_ip(ctx: &ToolContext, host: &str, port: u16) -> Result<IpAddr> {
    let addrs = ctx.net()?.vet(host, port).await?;
    addrs
        .iter()
        .map(SocketAddr::ip)
        .find(IpAddr::is_ipv4)
        .or_else(|| addrs.first().map(SocketAddr::ip))
        .ok_or_else(|| ToolError::NotFound(format!("'{host}' has no address")))
}

async fn ping(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let ip = vetted_ip(ctx, a.str("host")?, 7).await?;
    let count = a.u64_or("count", 4)?.clamp(1, 20).to_string();
    let program = if cfg!(target_os = "macos") && ip.is_ipv6() {
        "ping6"
    } else {
        "ping"
    };
    let count_flag = if cfg!(windows) { "-n" } else { "-c" };
    let cmd = Command::typed(program)
        .args([count_flag, count.as_str()])
        .arg(ip.to_string())
        .timeout(ctx.timeout(a.opt_u64("timeoutSecs")?))
        .timeout_is_result();
    Ok(render_run("net_ping", &ctx.run(cmd).await?))
}

async fn iperf(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let port = port(&a, "port", 5201)?;
    let ip = vetted_ip(ctx, a.str("server")?, port).await?;
    let duration = a.u64_or("durationSecs", 5)?.clamp(1, 60);
    let mut cmd = Command::typed("iperf3")
        .arg("--client")
        .arg(ip.to_string())
        .arg("--port")
        .arg(port.to_string())
        .arg("--time")
        .arg(duration.to_string());
    if a.bool_or("reverse", false)? {
        cmd = cmd.arg("--reverse");
    }
    let timeout = ctx.timeout(Some(a.opt_u64("timeoutSecs")?.unwrap_or(duration + 15)));
    let out = ctx.run(cmd.timeout(timeout).timeout_is_result()).await?;
    Ok(render_run("net_iperf", &out))
}

async fn quic_probe(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let vetted = ctx.net()?.vet_url(a.str("url")?, &["https"]).await?;
    let addr = vetted
        .addrs
        .first()
        .ok_or_else(|| ToolError::NotFound("the host has no address".to_string()))?;
    let ip = match addr.ip() {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    };
    let timeout = ctx.timeout(a.opt_u64("timeoutSecs")?);
    let cmd = Command::typed("curl")
        // First, so that no curlrc changes what is asked for.
        .arg("--disable")
        .args(["--http3-only", "--silent", "--show-error", "--head"])
        .args(["--proto", "=https", "--max-redirs", "0"])
        .args(["--output", if cfg!(windows) { "NUL" } else { "/dev/null" }])
        .args([
            "--write-out",
            "HTTP/%{http_version} %{response_code} from %{remote_ip}\n",
        ])
        .arg("--max-time")
        .arg(timeout.as_secs().max(1).to_string())
        // Pin curl to the address that was vetted.
        .arg("--resolve")
        .arg(format!("{}:{}:{ip}", vetted.host, vetted.port))
        .arg("--")
        .arg(vetted.url.as_str())
        .timeout(timeout + Duration::from_secs(2))
        .timeout_is_result();
    Ok(render_run("net_quic_probe", &ctx.run(cmd).await?))
}

async fn packet_capture(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let interface = a.str("interface")?;
    if interface.is_empty()
        || interface.len() > 64
        || interface.starts_with('-')
        || !interface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
    {
        return Err(ToolError::invalid(
            "`interface` must be an interface name such as eth0 or en0",
        ));
    }
    let filter = a.opt_str("filter")?.unwrap_or_default();
    if filter.len() > 500
        || !filter
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " .:/()[]!=<>&|-_,".contains(c))
    {
        return Err(ToolError::invalid(
            "`filter` must be a capture filter of letters, digits, spaces and . : / ( ) [ ] ! = \
             < > & | - _ ,",
        ));
    }
    let duration = Duration::from_secs(a.u64_or("durationSecs", 10)?.clamp(1, 300));
    let dest = ctx.write_path(a.str("outputPath")?)?;
    let mut cmd = Command::typed("tcpdump")
        .args(["-i", interface])
        // Names are not resolved, packets are flushed as they arrive.
        .args(["-n", "-U", "-w"])
        .arg_path(&dest)
        .arg("--");
    if !filter.is_empty() {
        cmd = cmd.arg(filter);
    }
    // tcpdump has no duration of its own: the capture is the run, ended by
    // the timeout.
    let out = ctx
        .run(
            cmd.timeout(duration.min(ctx.timeout(None)))
                .timeout_is_result(),
        )
        .await?;
    if !out.timed_out {
        return Err(ToolError::Execution(format!(
            "tcpdump stopped before the capture time was over: {}",
            clip(out.stderr.text.trim(), 1000)
        )));
    }
    let size = ctx.fs().try_metadata(&dest)?.map_or(0, |m| m.len);
    Ok(ToolOutput::text(format!(
        "[net_packet_capture: captured {}s on {interface} into {} ({size} bytes)]\n{}",
        duration.as_secs(),
        dest.display(),
        clip(out.stderr.text.trim(), 1000)
    )))
}

#[cfg(test)]
#[path = "net_tests.rs"]
mod tests;
