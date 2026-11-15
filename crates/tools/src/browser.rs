//! Browser tools: load a page in headless Chromium through Playwright.
//!
//! The browser is driven by a constant Node.js script; what the caller sends
//! reaches it as a JSON document, never as code. The browser is started with
//! the server's own forward proxy as its only way out, so every connection a
//! page makes (the navigation, redirects, scripts, fetches, WebSockets) is
//! vetted against the network policy and pinned, like a connection of the
//! server itself. Only http and https pages are loaded.
//!
//! Playwright is taken from Node's global module directory (or `NODE_PATH`
//! when the operator passes it through), never from a directory the client
//! can write.

use std::sync::Arc;

use nebula_mcp_core::args::Args;
use nebula_mcp_core::fs::CheckedPath;
use nebula_mcp_core::policy::Access;
use nebula_mcp_core::process::{Command, Exec};
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::{Category, Effects, Result, Tool, ToolContext, ToolError, ToolOutput};
use serde_json::{json, Value};

use crate::common::{clip, handler, spec, tool, SpecExt};

const EFFECTS: Effects = Effects::writes()
    .overwrites()
    .network()
    .exec(Exec::Programs(&["node"]));
const WAIT_UNTIL: [&str; 4] = ["load", "domcontentloaded", "networkidle", "commit"];
const MAX_TEXT: usize = 200_000;

/// Exit codes of the driver that are not page failures.
const NO_PLAYWRIGHT: i32 = 3;
const NO_BROWSER: i32 = 4;

/// The driver. `process.argv[1]` is the JSON configuration.
const DRIVER: &str = r#"
const path = require('path');
const cfg = JSON.parse(process.argv[1]);
function load() {
  const exe = path.dirname(process.execPath);
  const dirs = [path.join(exe, '..', 'lib', 'node_modules'), path.join(exe, 'node_modules')];
  if (process.env.APPDATA) dirs.push(path.join(process.env.APPDATA, 'npm', 'node_modules'));
  for (const d of (process.env.NODE_PATH || '').split(path.delimiter)) if (d) dirs.push(d);
  const tried = [];
  for (const d of dirs) for (const name of ['playwright', 'playwright-core']) {
    const p = path.resolve(d, name);
    const low = p.toLowerCase();
    if (cfg.writable.some(r => low.startsWith(r.toLowerCase()))) continue;
    try { return require(p); } catch (e) { tried.push(p); }
  }
  process.stderr.write(tried.join(', '));
  process.exit(3);
}
(async () => {
  const pw = load();
  const launch = {
    headless: true,
    proxy: { server: cfg.proxy, bypass: '<-loopback>' },
    args: ['--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-quic'],
  };
  let browser = null, why = '';
  for (const channel of [undefined, 'chrome', 'msedge']) {
    try { browser = await pw.chromium.launch(channel ? { ...launch, channel } : launch); break; }
    catch (e) { why = String(e && e.message || e).split('\n')[0]; }
  }
  if (!browser) { process.stderr.write(why); process.exit(4); }
  const out = { console: [], requests: [], blocked: 0 };
  try {
    const context = await browser.newContext({ acceptDownloads: false, serviceWorkers: 'block' });
    await context.route('**/*', route => {
      if (/^(https?|data|blob|about):/i.test(route.request().url())) return route.continue();
      out.blocked++;
      return route.abort('blockedbyclient');
    });
    const page = await context.newPage();
    if (cfg.collectConsole) page.on('console', m => {
      if (out.console.length < 200) out.console.push({ type: m.type(), text: m.text().slice(0, 2000) });
    });
    const note = (r, status, failure) => {
      if (cfg.collectNetwork && out.requests.length < 300) out.requests.push({
        url: r.url().slice(0, 2000), method: r.method(), type: r.resourceType(), status, failure,
      });
    };
    page.on('response', r => note(r.request(), r.status(), null));
    page.on('requestfailed', r => note(r, null, (r.failure() || {}).errorText || 'failed'));
    const response = await page.goto(cfg.url, { waitUntil: cfg.waitUntil, timeout: cfg.timeoutMs });
    if (cfg.waitMs) await page.waitForTimeout(cfg.waitMs);
    out.status = response ? response.status() : null;
    out.finalUrl = page.url();
    out.title = await page.title();
    if (cfg.text) {
      const text = await page.evaluate(() => document.body ? document.body.innerText : '');
      out.text = text.slice(0, cfg.maxText);
      out.textTruncated = text.length > cfg.maxText;
    }
    if (cfg.screenshot) await page.screenshot({ path: cfg.screenshot, fullPage: !!cfg.fullPage, type: 'png' });
    if (cfg.pdf) await page.pdf({ path: cfg.pdf });
  } catch (e) {
    out.error = String(e && e.message || e).split('\n')[0];
  } finally {
    await browser.close().catch(() => {});
  }
  process.stdout.write(JSON.stringify(out));
})();
"#;

fn page_schema() -> ObjectSchema {
    ObjectSchema::new()
        .string("url", "http:// or https:// address of the page.", true)
        .string_enum(
            "waitUntil",
            "When the page counts as loaded (default load).",
            &WAIT_UNTIL,
            false,
        )
        .boolean("fullPage", "Capture the whole scrollable page, not just the viewport.", false)
        .boolean("overwrite", "Replace output files that exist.", false)
        .integer_min(
            "timeoutSecs",
            "Seconds before the browser is stopped (default and ceiling set by the operator).",
            1,
            false,
        )
}

/// The `browser` tools.
pub(crate) fn tools() -> Vec<Arc<dyn Tool>> {
    let c = Category::Browser;
    vec![
        tool(
            spec(
                "browser_screenshot",
                c,
                "Screenshot page",
                "Load a web page in headless Chromium and save a PNG screenshot inside an \
                 allowed directory. Everything the page requests is subject to the network \
                 policy. Needs Node.js with Playwright installed globally.",
                page_schema()
                    .string("outputPath", "PNG file to write.", true)
                    .build(),
                EFFECTS,
            )
            .returns(
                ObjectSchema::open()
                    .string("path", "The screenshot.", true)
                    .nullable_integer("status", "HTTP status of the page.", true)
                    .string("finalUrl", "Address after redirects.", true)
                    .string("title", "Page title.", true)
                    .integer("blockedRequests", "Requests the network policy refused.", true)
                    .build(),
            ),
            handler!(screenshot),
        ),
        tool(
            spec(
                "browser_capture",
                c,
                "Capture page",
                "Load a web page in headless Chromium and return its title, visible text and \
                 optionally its console messages and network requests; can also save a \
                 screenshot and a PDF. Use it for pages that need JavaScript to render. \
                 Everything the page requests is subject to the network policy.",
                page_schema()
                    .integer_range("waitMs", "Extra milliseconds to wait after loading.", 0, 30_000, false)
                    .boolean("collectConsole", "Return console messages.", false)
                    .boolean("collectNetwork", "Return the requests the page made.", false)
                    .string("screenshotPath", "Also save a PNG screenshot here.", false)
                    .string("pdfPath", "Also save the page as PDF here.", false)
                    .build(),
                EFFECTS,
            )
            .returns(
                ObjectSchema::open()
                    .nullable_integer("status", "HTTP status of the page.", true)
                    .string("finalUrl", "Address after redirects.", true)
                    .string("title", "Page title.", true)
                    .string("text", "Visible text of the page.", true)
                    .boolean("textTruncated", "Whether the text was cut.", true)
                    .integer("blockedRequests", "Requests the network policy refused.", true)
                    .object_array(
                        "console",
                        "Console messages, when asked for.",
                        ObjectSchema::open()
                            .string("type", "log, warning, error, ...", true)
                            .string("text", "The message.", true),
                        true,
                    )
                    .object_array(
                        "requests",
                        "Requests the page made, when asked for.",
                        ObjectSchema::open()
                            .string("url", "Requested address.", true)
                            .string("method", "HTTP method.", true)
                            .string("type", "Resource type.", true)
                            .nullable_integer("status", "HTTP status, when answered.", true)
                            .nullable_string("failure", "Why it failed, when it did.", true),
                        true,
                    )
                    .nullable_string("screenshotPath", "The screenshot, when saved.", true)
                    .nullable_string("pdfPath", "The PDF, when saved.", true)
                    .build(),
            ),
            handler!(capture),
        ),
    ]
}

/// A file the browser writes: it goes to a sibling first and is moved into
/// place by the server, under the file policy.
struct Output {
    dest: CheckedPath,
    partial: CheckedPath,
}

fn output(ctx: &ToolContext, input: &str, overwrite: bool) -> Result<Output> {
    let dest = ctx.write_path(input)?;
    if !overwrite && ctx.fs().try_metadata(&dest)?.is_some() {
        return Err(ToolError::invalid(format!(
            "'{}' exists; pass overwrite to replace it",
            dest.display()
        )));
    }
    let not_a_file = || ToolError::invalid(format!("'{input}' does not name a file"));
    let name = dest.file_name().ok_or_else(not_a_file)?;
    let parent = ctx.fs().parent(&dest).ok_or_else(not_a_file)?;
    let partial = ctx.fs().child(
        &parent,
        &format!(".{name}.{}.part", uuid::Uuid::new_v4().simple()),
        Access::Write,
    )?;
    Ok(Output { dest, partial })
}

/// Run the driver for `a`, with the extra settings in `config`.
async fn drive(
    ctx: &ToolContext,
    a: &Args<'_>,
    mut config: Value,
    outputs: &[&Output],
) -> Result<(Value, u64)> {
    let net = ctx.net()?;
    let url = a.str("url")?;
    // A clear answer for the page itself; the proxy covers the rest.
    let vetted = net.vet_url(url, &["http", "https"]).await?;
    let proxy = net.proxy().await?;
    let timeout = ctx.timeout(a.opt_u64("timeoutSecs")?);
    let navigation = timeout.saturating_sub(std::time::Duration::from_secs(5));
    let writable: Vec<String> = ctx
        .policy()
        .paths()
        .roots()
        .iter()
        .map(|r| r.path().display().to_string())
        .collect();
    config["url"] = json!(vetted.url.as_str());
    config["proxy"] = json!(proxy.url());
    config["waitUntil"] = json!(a.opt_enum("waitUntil", &WAIT_UNTIL)?.unwrap_or("load"));
    config["fullPage"] = json!(a.bool_or("fullPage", false)?);
    config["timeoutMs"] = json!(u64::try_from(navigation.as_millis().max(1000)).unwrap_or(u64::MAX));
    config["writable"] = json!(writable);
    let cmd = Command::typed("node")
        .arg("-e")
        .arg(DRIVER)
        .arg(config.to_string())
        .pass_env("NODE_PATH")
        .pass_env("PLAYWRIGHT_BROWSERS_PATH")
        .timeout(timeout);
    let ran = ctx.run(cmd).await;
    let refused = proxy.refused();
    drop(proxy);
    let finished = ran.and_then(|out| match out.code {
        Some(0) => serde_json::from_str::<Value>(&out.stdout.text).map_err(|e| {
            ToolError::Execution(format!("the browser driver sent an unreadable result: {e}"))
        }),
        Some(NO_PLAYWRIGHT) => Err(ToolError::ProgramNotFound(format!(
            "Playwright is not installed where the server looks for it ({}). The operator can \
             install it with: npm install -g playwright && npx playwright install chromium",
            clip(out.stderr.text.trim(), 600)
        ))),
        Some(NO_BROWSER) => Err(ToolError::ProgramNotFound(format!(
            "Playwright found no browser to start ({}). The operator can install one with: npx \
             playwright install chromium",
            clip(out.stderr.text.trim(), 300)
        ))),
        _ => Err(ToolError::Execution(format!(
            "the browser driver failed: {}",
            clip(out.stderr.text.trim(), 1000)
        ))),
    });
    let result = finished.and_then(|result| match result.get("error").and_then(Value::as_str) {
        Some(error) if refused > 0 => Err(ToolError::NetworkNotAllowed(format!(
            "the page could not be loaded and {refused} connection(s) were refused by the \
             network policy ({})",
            clip(error, 300)
        ))),
        Some(error) => Err(ToolError::Execution(format!(
            "the page could not be loaded: {}",
            clip(error, 500)
        ))),
        None => Ok(result),
    });
    let result = match result {
        Ok(result) => result,
        Err(e) => {
            for o in outputs {
                let _ = ctx.fs().remove_file(&o.partial);
            }
            return Err(e);
        }
    };
    let overwrite = a.bool_or("overwrite", false)?;
    for o in outputs {
        ctx.fs().rename(&o.partial, &o.dest, overwrite)?;
    }
    let blocked = refused + result.get("blocked").and_then(Value::as_u64).unwrap_or(0);
    Ok((result, blocked))
}

fn text_field(result: &Value, key: &str) -> String {
    result
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

async fn screenshot(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let shot = output(ctx, a.str("outputPath")?, a.bool_or("overwrite", false)?)?;
    let config = json!({"screenshot": shot.partial.display()});
    let (result, blocked) = drive(ctx, &a, config, &[&shot]).await?;
    Ok(ToolOutput::json(json!({
        "path": shot.dest.display(),
        "status": result.get("status").cloned().unwrap_or(Value::Null),
        "finalUrl": text_field(&result, "finalUrl"),
        "title": text_field(&result, "title"),
        "blockedRequests": blocked,
    })))
}

async fn capture(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let overwrite = a.bool_or("overwrite", false)?;
    let shot = match a.opt_str("screenshotPath")? {
        Some(p) => Some(output(ctx, p, overwrite)?),
        None => None,
    };
    let pdf = match a.opt_str("pdfPath")? {
        Some(p) => Some(output(ctx, p, overwrite)?),
        None => None,
    };
    let config = json!({
        "text": true,
        "maxText": MAX_TEXT.min(ctx.max_output_bytes()),
        "waitMs": a.u64_or("waitMs", 0)?.min(30_000),
        "collectConsole": a.bool_or("collectConsole", false)?,
        "collectNetwork": a.bool_or("collectNetwork", false)?,
        "screenshot": shot.as_ref().map(|o| o.partial.display()),
        "pdf": pdf.as_ref().map(|o| o.partial.display()),
    });
    let outputs: Vec<&Output> = shot.iter().chain(pdf.iter()).collect();
    let (result, blocked) = drive(ctx, &a, config, &outputs).await?;
    let list = |key: &str| result.get(key).cloned().unwrap_or_else(|| json!([]));
    Ok(ToolOutput::json(json!({
        "status": result.get("status").cloned().unwrap_or(Value::Null),
        "finalUrl": text_field(&result, "finalUrl"),
        "title": text_field(&result, "title"),
        "text": text_field(&result, "text"),
        "textTruncated": result.get("textTruncated").and_then(Value::as_bool).unwrap_or(false),
        "blockedRequests": blocked,
        "console": list("console"),
        "requests": list("requests"),
        "screenshotPath": shot.map(|o| o.dest.display()),
        "pdfPath": pdf.map(|o| o.dest.display()),
    })))
}

#[cfg(test)]
#[path = "browser_tests.rs"]
mod tests;
