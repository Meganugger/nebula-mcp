//! PowerShell tools, and the helpers the Windows tools use to run fixed
//! scripts.
//!
//! `powershell_run` runs a script the caller wrote. Like the terminal tools
//! this is arbitrary execution with the server user's privileges; enabling
//! the category is the grant. When the server itself runs elevated the
//! script would too, so the elevated gate then applies.
//!
//! The typed Windows tools never put caller text into a script. Their
//! scripts are constants, and every value travels in an environment variable
//! that the script reads as data.

use std::sync::{Arc, OnceLock};

use base64::Engine;
use nebula_mcp_core::args::Args;
use nebula_mcp_core::process::{Command, Exec};
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::{
    Category, Effects, Gate, Platforms, Result, Tool, ToolContext, ToolError, ToolOutput,
};
use serde_json::Value;

use crate::common::{handler, spec, tool, SpecExt};
use crate::terminal::render_run;

/// Windows PowerShell 5.1, part of every Windows installation.
pub(crate) const WINDOWS_POWERSHELL: &str = "powershell";
/// PowerShell 7, on every platform.
pub(crate) const PWSH: &str = "pwsh";
/// Both shells, for tool metadata.
pub(crate) const SHELLS: Exec = Exec::Programs(&[WINDOWS_POWERSHELL, PWSH]);

/// Runs before every script: no progress records in the output, and UTF-8.
const PRELUDE: &str = "$ProgressPreference='SilentlyContinue';\
                       [Console]::OutputEncoding=[Text.Encoding]::UTF8;";

/// For the server's own scripts: an error ends the script with a failure
/// instead of being printed and passed over.
pub(crate) const STOP_ON_ERROR: &str = "$ErrorActionPreference='Stop';";

const IS_ELEVATED: &str = "if ($IsLinux -or $IsMacOS) { (id -u) -eq 0 } else { \
     ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())\
     .IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }";

/// The shell a typed tool uses on this platform.
pub(crate) fn platform_shell() -> &'static str {
    if cfg!(windows) {
        WINDOWS_POWERSHELL
    } else {
        PWSH
    }
}

/// A command that runs `script` in `shell`. The script is passed encoded, so
/// no quoting rule of the command line applies to it.
pub(crate) fn script(shell: &'static str, script: &str) -> Command {
    let text = format!("{PRELUDE}{script}");
    let utf16: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    Command::typed(shell)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"])
        .arg(base64::engine::general_purpose::STANDARD.encode(utf16))
}

/// Whether the server, and so every script it starts, runs with
/// administrator (or root) rights. Asked once.
pub(crate) async fn elevated(ctx: &ToolContext, shell: &'static str) -> Result<bool> {
    static ELEVATED: OnceLock<bool> = OnceLock::new();
    if let Some(known) = ELEVATED.get() {
        return Ok(*known);
    }
    let out = ctx
        .run(script(shell, IS_ELEVATED).timeout(ctx.timeout(None)))
        .await?
        .check("checking for administrator rights")?;
    let answer = out.stdout.text.trim().eq_ignore_ascii_case("true");
    Ok(*ELEVATED.get_or_init(|| answer))
}

/// The `powershell` tools.
pub(crate) fn tools() -> Vec<Arc<dyn Tool>> {
    let c = Category::Powershell;
    let run_effects = Effects::writes()
        .overwrites()
        .open_world()
        .elevated(Gate::Sometimes)
        .exec(SHELLS);
    vec![
        tool(
            spec(
                "powershell_run",
                c,
                "Run PowerShell",
                "Run a PowerShell script and return its output and exit code. The script runs \
                 with the server user's privileges and is not confined by the file or network \
                 policy. `shell` picks Windows PowerShell 5.1 (`powershell`, Windows only) or \
                 PowerShell 7 (`pwsh`).",
                ObjectSchema::new()
                    .string("script", "The script text.", true)
                    .string_enum(
                        "shell",
                        "Which PowerShell (default: powershell on Windows, pwsh elsewhere).",
                        &[WINDOWS_POWERSHELL, PWSH],
                        false,
                    )
                    .integer_min(
                        "timeoutSecs",
                        "Seconds before the script and everything it started are stopped.",
                        1,
                        false,
                    )
                    .build(),
                run_effects,
            ),
            handler!(run),
        ),
        tool(
            spec(
                "powershell_remote",
                c,
                "Run PowerShell remotely",
                "Run a script on another Windows computer over PowerShell remoting (WinRM), as \
                 the server's user. The computer is checked against the network policy. The \
                 project's CI does not exercise this tool.",
                ObjectSchema::new()
                    .string("computer", "Host name or address of the remote computer.", true)
                    .string("script", "The script text to run there.", true)
                    .integer_min(
                        "timeoutSecs",
                        "Seconds before the call is abandoned.",
                        1,
                        false,
                    )
                    .build(),
                run_effects.network(),
            )
            .on(Platforms::WINDOWS),
            handler!(remote),
        ),
    ]
}

async fn run(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let shell = match a.opt_enum("shell", &[WINDOWS_POWERSHELL, PWSH])? {
        Some(PWSH) => PWSH,
        Some(_) if cfg!(windows) => WINDOWS_POWERSHELL,
        Some(_) => {
            return Err(ToolError::PlatformUnsupported(
                "Windows PowerShell exists only on Windows; use shell \"pwsh\"".to_string(),
            ))
        }
        None => platform_shell(),
    };
    if elevated(ctx, shell).await? {
        ctx.require_elevated("running a script while the server has administrator rights")?;
    }
    let cmd = script(shell, a.str("script")?)
        .timeout(ctx.timeout(a.opt_u64("timeoutSecs")?))
        .timeout_is_result();
    Ok(render_run("powershell_run", &ctx.run(cmd).await?))
}

async fn remote(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    const REMOTE: &str = "Invoke-Command -ComputerName $env:NB_COMPUTER \
                          -ScriptBlock ([scriptblock]::Create($env:NB_SCRIPT))";
    let a = Args::new(&args)?;
    let computer = a.str("computer")?;
    // WinRM over HTTP; 5986 is the TLS port of the same service.
    ctx.net()?.vet(computer, 5985).await?;
    if elevated(ctx, WINDOWS_POWERSHELL).await? {
        ctx.require_elevated("running a script while the server has administrator rights")?;
    }
    let cmd = script(WINDOWS_POWERSHELL, REMOTE)
        .env("NB_COMPUTER", computer)
        .env("NB_SCRIPT", a.str("script")?)
        .timeout(ctx.timeout(a.opt_u64("timeoutSecs")?))
        .timeout_is_result();
    Ok(render_run("powershell_remote", &ctx.run(cmd).await?))
}

#[cfg(test)]
#[path = "powershell_tests.rs"]
mod tests;
