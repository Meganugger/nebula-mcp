//! The command line.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use nebula_mcp_core::config::Config;
use nebula_mcp_core::store::Overlay;
use nebula_mcp_core::telemetry;

use crate::app::App;

/// Time the runtime gets to drop what is left once the transports are done.
const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(3);

/// Name of the configuration file `init` writes and `run` looks for.
pub const DEFAULT_CONFIG_FILE: &str = "nebula-mcp.toml";

/// A Model Context Protocol server that gives an AI agent policy-checked
/// control of this machine.
#[derive(Debug, Parser)]
#[command(name = "nebula-mcp", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Configuration file. Without it, ./nebula-mcp.toml is used when it
    /// exists; otherwise the server starts with nothing allowed.
    #[arg(short, long, global = true, env = "NEBULA_MCP_CONFIG")]
    config: Option<PathBuf>,

    /// Directory relative paths resolve against (default: current directory).
    #[arg(short, long, global = true, env = "NEBULA_MCP_WORKDIR")]
    workdir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve MCP on stdin/stdout (the default).
    Run,
    /// Write a starter configuration file.
    Init {
        /// Where to write it.
        #[arg(long, default_value = DEFAULT_CONFIG_FILE)]
        path: PathBuf,
        /// Replace an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Check the configuration and report problems and warnings.
    ValidateConfig,
    /// Print the effective configuration, with secrets removed.
    PrintConfig,
    /// List the tools the configuration exposes on this machine.
    ListTools {
        /// Include tools that are not enabled or not available here.
        #[arg(long)]
        all: bool,
        /// Print the definitions as JSON, as a client would receive them.
        #[arg(long)]
        json: bool,
    },
}

/// Parse the command line and run. Returns the process exit code.
#[must_use]
pub fn main() -> i32 {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("nebula-mcp: {message}");
            1
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let workdir = match &cli.workdir {
        Some(dir) => dir.clone(),
        None => std::env::current_dir().map_err(|e| format!("current directory: {e}"))?,
    };
    let config_path = resolve_config_path(cli.config.as_deref(), &workdir)?;
    match cli.command.unwrap_or(Command::Run) {
        Command::Init { path, force } => init(&path, force, &workdir),
        Command::ValidateConfig => {
            let (_, warnings) = load(config_path.as_deref(), workdir)?;
            for w in &warnings {
                println!("warning: {w}");
            }
            println!("configuration is valid ({} warnings)", warnings.len());
            Ok(())
        }
        Command::PrintConfig => {
            let (app, _) = load(config_path.as_deref(), workdir)?;
            let text = redacted(&app.store().snapshot().config)?;
            print!("{text}");
            Ok(())
        }
        Command::ListTools { all, json } => {
            let (app, _) = load(config_path.as_deref(), workdir)?;
            list_tools(&app, all, json)
        }
        Command::Run => serve(config_path.as_deref(), workdir),
    }
}

/// The configuration file to use: the one named, else `./nebula-mcp.toml`
/// when present.
fn resolve_config_path(explicit: Option<&Path>, workdir: &Path) -> Result<Option<PathBuf>, String> {
    if let Some(path) = explicit {
        if !path.is_file() {
            return Err(format!(
                "configuration file '{}' does not exist. Create one with `nebula-mcp init`.",
                path.display()
            ));
        }
        return Ok(Some(path.to_path_buf()));
    }
    let default = workdir.join(DEFAULT_CONFIG_FILE);
    Ok(default.is_file().then_some(default))
}

fn load(config: Option<&Path>, workdir: PathBuf) -> Result<(Arc<App>, Vec<String>), String> {
    let overlay: Option<Overlay> = None;
    App::load(config, overlay, workdir).map_err(|e| e.to_string())
}

fn serve(config: Option<&Path>, workdir: PathBuf) -> Result<(), String> {
    let (app, warnings) = load(config, workdir)?;
    let loaded = app.store().snapshot();
    let (_telemetry, _log_control) =
        telemetry::init(&loaded.config.logging).map_err(|e| e.to_string())?;
    match config {
        Some(path) => tracing::info!(config = %path.display(), "configuration loaded"),
        None => tracing::warn!(
            "no configuration file: nothing is allowed. Create one with `nebula-mcp init`."
        ),
    }
    for w in &warnings {
        tracing::warn!("{w}");
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("starting the async runtime: {e}"))?;
    let result = runtime.block_on(async {
        app.start();
        let _reload = match app.store().source_path() {
            Some(_) => match nebula_mcp_core::hotreload::watch(app.store().clone()) {
                Ok(handle) => Some(handle),
                Err(e) => {
                    tracing::warn!("configuration changes will not be picked up: {e}");
                    None
                }
            },
            None => None,
        };
        let mut transport = tokio::spawn(crate::stdio::serve(app.clone()));
        let result = tokio::select! {
            joined = &mut transport => joined.unwrap_or_else(|e| Err(format!("transport task: {e}"))),
            () = shutdown_signal() => {
                tracing::info!("shutdown requested");
                app.shutdown().cancel();
                let _ = tokio::time::timeout(crate::stdio::SHUTDOWN_GRACE, &mut transport).await;
                Ok(())
            }
        };
        // Calls that are still running kill what they started; then
        // sessions and jobs are stopped.
        app.stop(crate::stdio::SHUTDOWN_GRACE).await;
        result
    });
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
    tracing::info!("stopped");
    result
}

/// Resolves on SIGINT or SIGTERM (Ctrl-C or Ctrl-Break on Windows).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).ok();
        let mut int = signal(SignalKind::interrupt()).ok();
        tokio::select! {
            _ = async { match &mut term { Some(s) => s.recv().await, None => std::future::pending().await } } => {}
            _ = async { match &mut int { Some(s) => s.recv().await, None => std::future::pending().await } } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn init(path: &Path, force: bool, workdir: &Path) -> Result<(), String> {
    if path.exists() && !force {
        return Err(format!(
            "'{}' already exists; pass --force to replace it",
            path.display()
        ));
    }
    let dir = std::fs::canonicalize(workdir).unwrap_or_else(|_| workdir.to_path_buf());
    let dir = nebula_mcp_core::policy::slash_string(&nebula_mcp_core::policy::simplify(&dir));
    let text = STARTER_CONFIG.replace("{WORKDIR}", &dir);
    Config::from_toml_str(&text)
        .map_err(|e| format!("internal error in the starter config: {e}"))?;
    std::fs::write(path, text).map_err(|e| format!("writing '{}': {e}", path.display()))?;
    println!(
        "wrote {}. Edit it, then check it with `nebula-mcp validate-config`.",
        path.display()
    );
    Ok(())
}

/// The file `init` writes. `{WORKDIR}` is replaced with the working directory.
pub const STARTER_CONFIG: &str = r#"# Nebula MCP configuration. Nothing is allowed unless this file allows it.
# The server reloads this file when it changes; an edit with a mistake in it
# is ignored and logged. Tools can never read or write this file.

[server]
# Tool categories offered to clients. Available: fs, git, github, terminal,
# process, net, docker, browser, scheduler, powershell, windows, diagnostics,
# security. `nebula-mcp list-tools --all` shows what each contains.
categories = ["fs", "git"]

[security]
# Directories tools may work in. Each entry covers everything beneath it.
allowed_paths = ["{WORKDIR}"]

# Programs the terminal, scheduler and powershell tools may run: names found
# on PATH or absolute paths. Whatever is listed here runs with your full
# privileges and can do anything you can; "*" allows every program.
allowed_commands = []

# Outbound network access for tools.
allow_network = false

# Deleting, replacing and force operations.
allow_destructive = false

# Operations that need administrator or root rights.
allow_elevated = false
"#;

/// The configuration as TOML with every secret replaced.
fn redacted(config: &Config) -> Result<String, String> {
    let mut copy = config.clone();
    for token in &mut copy.transport.http.auth_tokens {
        *token = "<redacted>".to_string();
    }
    if let Some(secret) = &mut copy.transport.http.oauth.approval_secret {
        *secret = "<redacted>".to_string();
    }
    copy.to_toml_string().map_err(|e| e.to_string())
}

fn list_tools(app: &App, all: bool, json: bool) -> Result<(), String> {
    let loaded = app.store().snapshot();
    let registry = app.dispatcher().registry();
    let mut rows = Vec::new();
    for tool in registry.all() {
        let spec = tool.spec();
        let available = spec.platforms.includes_current();
        let enabled = loaded
            .config
            .is_tool_enabled(spec.category.as_str(), spec.name);
        if all || (available && enabled) {
            rows.push((spec, available, enabled));
        }
    }
    if json {
        let tools: Vec<serde_json::Value> = rows
            .iter()
            .map(|(spec, available, enabled)| {
                let a = spec.annotations();
                serde_json::json!({
                    "name": spec.name,
                    "category": spec.category.as_str(),
                    "title": spec.title,
                    "description": spec.description,
                    "inputSchema": spec.input,
                    "outputSchema": spec.output,
                    "annotations": {
                        "readOnlyHint": a.read_only,
                        "destructiveHint": a.destructive,
                        "idempotentHint": a.idempotent,
                        "openWorldHint": a.open_world,
                    },
                    "availableOnThisPlatform": available,
                    "enabled": enabled,
                })
            })
            .collect();
        let text = serde_json::to_string_pretty(&tools).map_err(|e| e.to_string())?;
        println!("{text}");
        return Ok(());
    }
    for (spec, available, enabled) in &rows {
        let state = match (available, enabled) {
            (false, _) => "  (not on this platform)",
            (true, false) => "  (not enabled)",
            (true, true) => "",
        };
        println!("{:<28} {}{state}", spec.name, spec.title);
    }
    let exposed = rows.iter().filter(|(_, a, e)| *a && *e).count();
    println!(
        "{exposed} tools exposed; {} in this build ({} categories)",
        registry.len(),
        registry.catalog().categories.len()
    );
    Ok(())
}
