//! Docker tools.
//!
//! Enabling this category hands the agent the Docker daemon, which is
//! root-equivalent on most hosts: a container can mount the host's
//! filesystem, and a compose file or a Dockerfile is a program. The file and
//! network policy of this server does not reach inside the daemon.
//!
//! What these tools do guarantee is narrower: every argument vector is built
//! here, caller strings never sit where docker would read an option,
//! `docker_run` and `docker_build` isolate containers from the network unless
//! network access is on, published ports bind to loopback unless an address
//! is given, paths the tools take are policy-checked, and stopping or
//! removing things needs the destructive gate.

use std::sync::Arc;

use nebula_mcp_core::args::Args;
use nebula_mcp_core::fs::{CheckedPath, Kind};
use nebula_mcp_core::policy::Access;
use nebula_mcp_core::process::{Command, Exec};
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::{Category, Effects, Gate, Result, Tool, ToolContext, ToolError, ToolOutput};
use serde_json::Value;

use crate::common::{handler, spec, tool};
use crate::terminal::render_run;

const DOCKER: &str = "docker";
const PROGRAMS: Exec = Exec::Programs(&[DOCKER]);
const READ: Effects = Effects::read_only().open_world().exec(PROGRAMS);
const WRITE: Effects = Effects::writes().overwrites().open_world().exec(PROGRAMS);
const TIMEOUT_HELP: &str =
    "Seconds before docker is stopped (default and ceiling set by the operator).";
const CONTAINER_HELP: &str = "Container name or id.";

/// The `docker` tools.
#[allow(clippy::too_many_lines)]
pub(crate) fn tools() -> Vec<Arc<dyn Tool>> {
    let c = Category::Docker;
    let container = || ObjectSchema::new().string("container", CONTAINER_HELP, true);
    vec![
        tool(
            spec(
                "docker_ps",
                c,
                "List containers",
                "Containers on this Docker host: id, image, status, names and ports.",
                ObjectSchema::new()
                    .boolean("all", "Include stopped containers.", false)
                    .build(),
                READ,
            ),
            handler!(ps),
        ),
        tool(
            spec(
                "docker_images",
                c,
                "List images",
                "Images stored on this Docker host: repository, tag, id and size.",
                ObjectSchema::new().build(),
                READ,
            ),
            handler!(images),
        ),
        tool(
            spec(
                "docker_logs",
                c,
                "Container logs",
                "The last lines a container wrote to its standard output and error.",
                container()
                    .integer_range(
                        "tail",
                        "Lines from the end (default 200).",
                        1,
                        10_000,
                        false,
                    )
                    .build(),
                READ,
            ),
            handler!(logs),
        ),
        tool(
            spec(
                "docker_run",
                c,
                "Run container",
                "Start a container from an image and return its output, or with `detach` leave \
                 it running. The container has no network unless `network` is set and the \
                 operator allows network access; then a missing image is pulled. Host \
                 directories are not mounted.",
                ObjectSchema::new()
                    .string("image", "Image reference, for example alpine:3.20.", true)
                    .string_array_max(
                        "command",
                        "Command and arguments to run in the container.",
                        200,
                        false,
                    )
                    .string_array_max("env", "Environment variables as NAME=value.", 100, false)
                    .string_array_max(
                        "publish",
                        "Ports as hostPort:containerPort, bound to 127.0.0.1 unless an address \
                         is given (address:hostPort:containerPort).",
                        20,
                        false,
                    )
                    .string("name", "Name for the container.", false)
                    .boolean("detach", "Leave it running and return its id.", false)
                    .boolean(
                        "rm",
                        "Remove the container when it exits (default true).",
                        false,
                    )
                    .boolean("network", "Give the container network access.", false)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                WRITE,
            ),
            handler!(run),
        ),
        tool(
            spec(
                "docker_exec",
                c,
                "Run in container",
                "Run a command inside a running container and return its output.",
                container()
                    .string_array_max("command", "Command and arguments.", 200, true)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                WRITE,
            ),
            handler!(exec),
        ),
        tool(
            spec(
                "docker_build",
                c,
                "Build image",
                "Build an image from a directory inside the allowed directories. Build steps \
                 have no network unless the operator allows network access.",
                ObjectSchema::new()
                    .string("context", "Directory to build from.", true)
                    .string("tag", "Name for the image, for example myapp:dev.", true)
                    .string(
                        "dockerfile",
                        "Dockerfile to use (default: Dockerfile in the context).",
                        false,
                    )
                    .string_array_max("buildArgs", "Build arguments as NAME=value.", 100, false)
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                WRITE,
            ),
            handler!(build),
        ),
        tool(
            spec(
                "docker_stop",
                c,
                "Stop container",
                "Stop a running container. Destructive: whatever it was doing ends.",
                container().build(),
                WRITE.destructive(Gate::Always),
            ),
            handler!(stop),
        ),
        tool(
            spec(
                "docker_rm",
                c,
                "Remove container",
                "Remove a container and its writable layer. `force` removes a running one.",
                container()
                    .boolean("force", "Stop it first if it is running.", false)
                    .build(),
                WRITE.destructive(Gate::Always),
            ),
            handler!(rm),
        ),
        tool(
            spec(
                "docker_compose",
                c,
                "Docker Compose",
                "Run a Docker Compose action for a compose file inside the allowed directories. \
                 A compose file can mount host directories and start privileged containers: it \
                 is a program run as the Docker daemon. `down` and `stop` are destructive.",
                ObjectSchema::new()
                    .string("file", "The compose file.", true)
                    .string_enum(
                        "action",
                        "What to do.",
                        &[
                            "up", "down", "stop", "restart", "ps", "logs", "build", "pull",
                            "config",
                        ],
                        true,
                    )
                    .integer_min("timeoutSecs", TIMEOUT_HELP, 1, false)
                    .build(),
                WRITE.destructive(Gate::Sometimes),
            ),
            handler!(compose),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Argument checks: nothing a caller sends may be read as an option
// ---------------------------------------------------------------------------

fn name_like(value: &str, what: &str, extra: &[char], max: usize) -> Result<String> {
    let mut chars = value.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && value.len() <= max
        && chars.all(|c| c.is_ascii_alphanumeric() || extra.contains(&c));
    if ok {
        Ok(value.to_string())
    } else {
        Err(ToolError::invalid(format!(
            "`{what}` is not valid: it must start with a letter or digit and contain only \
             letters, digits and {}",
            extra
                .iter()
                .map(|c| format!("'{c}'"))
                .collect::<Vec<_>>()
                .join(" ")
        )))
    }
}

fn container_name(value: &str) -> Result<String> {
    name_like(value, "container", &['_', '.', '-'], 128)
}

fn image_ref(value: &str, what: &str) -> Result<String> {
    name_like(value, what, &['_', '.', '-', '/', ':', '@'], 255)
}

/// `NAME=value` with a variable-shaped name.
fn assignment(value: &str, what: &str) -> Result<String> {
    let valid = value.split_once('=').is_some_and(|(name, rest)| {
        let mut chars = name.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !rest.contains(['\0', '\n', '\r'])
    });
    if valid {
        Ok(value.to_string())
    } else {
        Err(ToolError::invalid(format!(
            "`{what}` entries must look like NAME=value"
        )))
    }
}

/// A published port, bound to loopback unless the caller names an address.
fn publish(value: &str) -> Result<String> {
    let bad = || {
        ToolError::invalid(
            "`publish` entries must be hostPort:containerPort or address:hostPort:containerPort, \
             optionally followed by /tcp or /udp",
        )
    };
    let (ports, proto) = match value.rsplit_once('/') {
        Some((ports, proto @ ("tcp" | "udp"))) => (ports, Some(proto)),
        Some(_) => return Err(bad()),
        None => (value, None),
    };
    let parts: Vec<&str> = ports.split(':').collect();
    let port = |p: &str| p.parse::<u16>().ok().filter(|p| *p != 0);
    let (address, host, inner) = match parts.as_slice() {
        [host, inner] => ("127.0.0.1", *host, *inner),
        [address, host, inner] if address.parse::<std::net::Ipv4Addr>().is_ok() => {
            (*address, *host, *inner)
        }
        _ => return Err(bad()),
    };
    let (Some(host), Some(inner)) = (port(host), port(inner)) else {
        return Err(bad());
    };
    Ok(match proto {
        Some(proto) => format!("{address}:{host}:{inner}/{proto}"),
        None => format!("{address}:{host}:{inner}"),
    })
}

/// The options of `docker run`, before the image.
fn run_options(a: &Args<'_>, network: bool) -> Result<Vec<String>> {
    let detach = a.bool_or("detach", false)?;
    let mut options = Vec::new();
    if detach {
        options.push("--detach".to_string());
    }
    if a.bool_or("rm", !detach)? {
        options.push("--rm".to_string());
    }
    if let Some(name) = a.opt_str("name")? {
        options.push(format!("--name={}", container_name(name)?));
    }
    for entry in a.opt_str_array("env")? {
        options.push(format!("--env={}", assignment(&entry, "env")?));
    }
    for entry in a.opt_str_array("publish")? {
        options.push(format!("--publish={}", publish(&entry)?));
    }
    if !network {
        // No route out, and no reaching for a registry either.
        options.push("--network=none".to_string());
        options.push("--pull=never".to_string());
    }
    Ok(options)
}

/// Whether the call asks for network access, which policy must then allow.
fn wants_network(ctx: &ToolContext, a: &Args<'_>) -> Result<bool> {
    let wanted = a.bool_or("network", false)?;
    if wanted {
        ctx.policy().require_network()?;
    }
    Ok(wanted)
}

async fn checked(ctx: &ToolContext, input: &str, kind: Kind) -> Result<CheckedPath> {
    let input = input.to_string();
    ctx.fs()
        .blocking(move |fs| {
            let path = fs.resolve(&input, Access::Read)?;
            if fs.metadata(&path)?.kind == kind {
                Ok(path)
            } else {
                Err(ToolError::invalid(format!(
                    "'{}' is not a {}",
                    path.display(),
                    if kind == Kind::Dir {
                        "directory"
                    } else {
                        "file"
                    }
                )))
            }
        })
        .await
}

fn docker() -> Command {
    Command::typed(DOCKER).pass_env("DOCKER_HOST")
}

async fn finish(ctx: &ToolContext, tool: &str, a: &Args<'_>, cmd: Command) -> Result<ToolOutput> {
    let out = ctx
        .run(
            cmd.timeout(ctx.timeout(a.opt_u64("timeoutSecs")?))
                .timeout_is_result(),
        )
        .await?;
    Ok(render_run(tool, &out))
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

async fn ps(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let mut cmd = docker().args([
        "ps",
        "--format",
        "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}\t{{.Ports}}",
    ]);
    if a.bool_or("all", false)? {
        cmd = cmd.arg("--all");
    }
    finish(ctx, "docker_ps", &a, cmd).await
}

async fn images(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let cmd = docker().args([
        "images",
        "--format",
        "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}",
    ]);
    finish(ctx, "docker_images", &a, cmd).await
}

async fn logs(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let cmd = docker()
        .arg("logs")
        .arg(format!(
            "--tail={}",
            a.u64_or("tail", 200)?.clamp(1, 10_000)
        ))
        .arg(container_name(a.str("container")?)?);
    finish(ctx, "docker_logs", &a, cmd).await
}

async fn run(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let network = wants_network(ctx, &a)?;
    let cmd = docker()
        .arg("run")
        .args(run_options(&a, network)?)
        .arg(image_ref(a.str("image")?, "image")?)
        // Everything after the image belongs to the container.
        .args(a.opt_str_array("command")?);
    finish(ctx, "docker_run", &a, cmd).await
}

async fn exec(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let command = a.str_array("command")?;
    if command.is_empty() {
        return Err(ToolError::invalid("`command` must not be empty"));
    }
    let cmd = docker()
        .arg("exec")
        .arg(container_name(a.str("container")?)?)
        .args(command);
    finish(ctx, "docker_exec", &a, cmd).await
}

async fn build(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let context = checked(ctx, a.str("context")?, Kind::Dir).await?;
    let mut cmd = docker()
        .arg("build")
        .arg(format!("--tag={}", image_ref(a.str("tag")?, "tag")?));
    if let Some(dockerfile) = a.opt_str("dockerfile")? {
        cmd = cmd.arg_prefixed_path("--file=", &checked(ctx, dockerfile, Kind::File).await?);
    }
    for entry in a.opt_str_array("buildArgs")? {
        cmd = cmd.arg(format!("--build-arg={}", assignment(&entry, "buildArgs")?));
    }
    if !ctx.policy().net().enabled() {
        cmd = cmd.args(["--network=none", "--pull=false"]);
    }
    finish(ctx, "docker_build", &a, cmd.arg_path(&context)).await
}

async fn stop(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let cmd = docker()
        .arg("stop")
        .arg(container_name(a.str("container")?)?);
    finish(ctx, "docker_stop", &a, cmd).await
}

async fn rm(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let mut cmd = docker().arg("rm");
    if a.bool_or("force", false)? {
        cmd = cmd.arg("--force");
    }
    let cmd = cmd.arg(container_name(a.str("container")?)?);
    finish(ctx, "docker_rm", &a, cmd).await
}

async fn compose(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let action = a.str("action")?;
    let file = checked(ctx, a.str("file")?, Kind::File).await?;
    let tail: &[&str] = match action {
        "up" => &["up", "--detach"],
        "down" | "stop" => {
            ctx.require_destructive("stopping a compose project")?;
            if action == "down" {
                &["down"]
            } else {
                &["stop"]
            }
        }
        "restart" => &["restart"],
        "ps" => &["ps"],
        "logs" => &["logs", "--tail=200", "--no-color"],
        "build" => &["build"],
        "pull" => {
            ctx.policy().require_network()?;
            &["pull"]
        }
        "config" => &["config"],
        other => {
            return Err(ToolError::invalid(format!(
                "unknown compose action '{other}'"
            )))
        }
    };
    let cmd = docker()
        .arg("compose")
        .arg_prefixed_path("--file=", &file)
        .args(tail.iter().copied());
    finish(ctx, "docker_compose", &a, cmd).await
}

#[cfg(test)]
#[path = "docker_tests.rs"]
mod tests;
