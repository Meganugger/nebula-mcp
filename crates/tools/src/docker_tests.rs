//! `docker` tools: argument construction, and the dispatcher's gates. A
//! Docker daemon is not required; where one is present a read-only smoke
//! test runs against it.

#![allow(clippy::disallowed_methods)]

use nebula_mcp_core::args::Args;
use serde_json::json;

use super::{assignment, container_name, image_ref, publish, run_options};
use crate::testkit::{text_of, Kit};

#[test]
fn run_options_are_built_from_checked_pieces() {
    let args = json!({
        "image": "alpine:3.20", "name": "job-1", "detach": true,
        "env": ["A=1", "B=two words"], "publish": ["8080:80", "0.0.0.0:53:53/udp"],
    });
    let a = Args::new(&args).unwrap();
    assert_eq!(
        run_options(&a, false).unwrap(),
        [
            "--detach",
            "--name=job-1",
            "--env=A=1",
            "--env=B=two words",
            "--publish=127.0.0.1:8080:80",
            "--publish=0.0.0.0:53:53/udp",
            "--network=none",
            "--pull=never",
        ]
    );
    // Not detached: removed on exit by default; with network: no isolation flags.
    let args = json!({"image": "alpine"});
    assert_eq!(
        run_options(&Args::new(&args).unwrap(), true).unwrap(),
        ["--rm"]
    );
}

#[test]
fn option_shaped_values_are_refused() {
    for bad in ["--privileged", "-v/:/host", "", "a b", "alpine;id", "$(id)"] {
        assert!(image_ref(bad, "image").is_err(), "{bad}");
        assert!(container_name(bad).is_err(), "{bad}");
    }
    assert!(image_ref("ghcr.io/owner/app@sha256:abc123", "image").is_ok());
    assert!(container_name("web_1.test-a").is_ok());
    assert!(container_name("registry/x").is_err());

    for bad in [
        "--env-file=/etc/shadow",
        "=x",
        "1A=x",
        "A",
        "A B=x",
        "A=x\ny",
    ] {
        assert!(assignment(bad, "env").is_err(), "{bad}");
    }
    assert_eq!(assignment("A=--x=y", "env").unwrap(), "A=--x=y");

    for bad in [
        "80",
        "--publish-all",
        "0:80",
        "80:0",
        "80:99999",
        "::80:80",
        "host:80:80",
        "80:80/sctp",
        "1.2.3.4:80:80:80",
    ] {
        assert!(publish(bad).is_err(), "{bad}");
    }
    assert_eq!(publish("5432:5432/tcp").unwrap(), "127.0.0.1:5432:5432/tcp");
}

#[tokio::test]
async fn the_dispatcher_checks_arguments_gates_and_paths() {
    let kit = Kit::new("");
    kit.write("app/Dockerfile", "FROM scratch\n");
    kit.write("app/compose.yaml", "services: {}\n");
    kit.write(".env", "TOKEN=1\n");
    let outside = kit.outside.display().to_string();

    for (tool, args, prefix) in [
        (
            "docker_run",
            json!({"image": "--privileged"}),
            "[invalid_arguments]",
        ),
        (
            "docker_run",
            json!({"image": "alpine", "name": "--rm"}),
            "[invalid_arguments]",
        ),
        (
            "docker_run",
            json!({"image": "alpine", "env": ["--env-file=/x"]}),
            "[invalid_arguments]",
        ),
        (
            "docker_run",
            json!({"image": "alpine", "publish": ["--publish-all"]}),
            "[invalid_arguments]",
        ),
        (
            "docker_run",
            json!({"image": "alpine", "volumes": ["/:/host"]}),
            "[invalid_arguments]",
        ),
        (
            "docker_run",
            json!({"image": "alpine", "privileged": true}),
            "[invalid_arguments]",
        ),
        (
            "docker_run",
            json!({"image": "alpine", "network": true}),
            "[permission_denied]",
        ),
        (
            "docker_exec",
            json!({"container": "-it", "command": ["sh"]}),
            "[invalid_arguments]",
        ),
        (
            "docker_exec",
            json!({"container": "web", "command": []}),
            "[invalid_arguments]",
        ),
        (
            "docker_logs",
            json!({"container": "--follow"}),
            "[invalid_arguments]",
        ),
        (
            "docker_build",
            json!({"context": outside, "tag": "x"}),
            "[path_not_allowed]",
        ),
        (
            "docker_build",
            json!({"context": "app", "tag": "--output=/x"}),
            "[invalid_arguments]",
        ),
        (
            "docker_build",
            json!({"context": "app", "tag": "x", "dockerfile": ".env"}),
            "[permission_denied]",
        ),
        (
            "docker_build",
            json!({"context": "app", "tag": "x", "buildArgs": ["--secret=id=x"]}),
            "[invalid_arguments]",
        ),
        (
            "docker_compose",
            json!({"file": ".env", "action": "config"}),
            "[permission_denied]",
        ),
        (
            "docker_compose",
            json!({"file": "app/compose.yaml", "action": "exec"}),
            "[invalid_arguments]",
        ),
        (
            "docker_compose",
            json!({"file": "app/compose.yaml", "action": "down"}),
            "[permission_denied]",
        ),
        (
            "docker_compose",
            json!({"file": "app/compose.yaml", "action": "pull"}),
            "[permission_denied]",
        ),
        (
            "docker_stop",
            json!({"container": "web"}),
            "[permission_denied]",
        ),
        (
            "docker_rm",
            json!({"container": "web", "force": true}),
            "[permission_denied]",
        ),
    ] {
        let err = kit.err(tool, args.clone()).await;
        assert!(err.starts_with(prefix), "{tool} {args}: {err}");
    }
}

/// With a daemon: listing works. Without docker: the error says so. Either
/// way the call is answered.
#[tokio::test]
async fn listing_is_answered_with_or_without_a_daemon() {
    let kit = Kit::new("");
    for tool in ["docker_ps", "docker_images"] {
        let text = match kit.call(tool, json!({})).await {
            Ok(out) => text_of(&out),
            Err(failure) => failure.text,
        };
        assert!(
            text.contains(&format!("[{tool}: ")) || text.starts_with("[program_not_found]"),
            "{tool}: {text}"
        );
    }
}
