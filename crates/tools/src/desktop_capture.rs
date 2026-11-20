//! Governed Windows desktop capture.
//!
//! Capture is intentionally implemented through a fixed PowerShell/GDI
//! compatibility adapter for this desktop slice. It captures the interactive
//! user's visible screen, never claims to bypass secure desktops or DRM, and
//! returns explicit warnings for occluded/minimized windows and DPI limits.

use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use image::ImageEncoder;
use nebula_mcp_core::{Result, Tool, ToolContext, ToolError};
use nebula_mcp_protocol::mcp::ToolAnnotations;
use nebula_mcp_protocol::CallToolResult;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::common::output::json_value_result;
use crate::common::platform::{ensure_windows, run_powershell, POWERSHELL};
use crate::common::{Args, ObjectSchema};

const CATEGORY: &str = "desktop";
const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;
const POWERSHELL_CAPTURE: &str = r#"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NebulaCaptureNative {
  [StructLayout(LayoutKind.Sequential)]
  public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern uint GetDpiForSystem();
}
'@

$cfg = ([Text.Encoding]::UTF8.GetString(
  [Convert]::FromBase64String('__CONFIG__')
)) | ConvertFrom-Json
$screens = @([System.Windows.Forms.Screen]::AllScreens)
if ($screens.Count -eq 0) { throw 'no interactive displays are available' }

$originX = 0
$originY = 0
$right = 0
$bottom = 0
$displayId = $null
$windowId = $null
$warnings = [System.Collections.Generic.List[string]]::new()
$dpiScale = 1.0

if ($cfg.source -eq 'all_displays') {
  $originX = [int]::MaxValue
  $originY = [int]::MaxValue
  $right = [int]::MinValue
  $bottom = [int]::MinValue
  foreach ($screen in $screens) {
    $b = $screen.Bounds
    $originX = [Math]::Min($originX, $b.Left)
    $originY = [Math]::Min($originY, $b.Top)
    $right = [Math]::Max($right, $b.Right)
    $bottom = [Math]::Max($bottom, $b.Bottom)
  }
  $warnings.Add('gdi_compatibility_fallback')
  $warnings.Add('secure_desktop_drm_and_protected_surfaces_are_not_captured')
} elseif ($cfg.source -eq 'display') {
  $wanted = [string]$cfg.displayId
  $screen = $screens | Where-Object {
    $_.DeviceName -eq $wanted -or
    $_.DeviceName.EndsWith($wanted) -or
    $_.DeviceName.TrimStart('\','.') -eq $wanted
  } | Select-Object -First 1
  if ($null -eq $screen -and $wanted -match '^DISPLAY([0-9]+)$') {
    $index = [int]$Matches[1] - 1
    if ($index -ge 0 -and $index -lt $screens.Count) { $screen = $screens[$index] }
  }
  if ($null -eq $screen) { throw "display '$wanted' is unavailable" }
  $b = $screen.Bounds
  $originX = $b.Left; $originY = $b.Top; $right = $b.Right; $bottom = $b.Bottom
  $displayId = $screen.DeviceName.TrimStart('\','.')
  $dpi = [NebulaCaptureNative]::GetDpiForSystem()
  if ($dpi -gt 0) { $dpiScale = [double]$dpi / 96.0 }
  $warnings.Add('gdi_compatibility_fallback')
  $warnings.Add('per_monitor_dpi_is_reported_as_system_dpi')
  $warnings.Add('secure_desktop_drm_and_protected_surfaces_are_not_captured')
} elseif ($cfg.source -eq 'window') {
  $raw = ([string]$cfg.windowId).Trim()
  if ($raw -notmatch '^(0x)?[0-9a-fA-F]+$') { throw 'windowId must be a hexadecimal native handle' }
  $hex = $raw -replace '^0x','' -replace '^0X',''
  $handle = [IntPtr]::new([Convert]::ToInt64($hex, 16))
  if (![NebulaCaptureNative]::IsWindow($handle)) { throw 'stale window handle' }
  $rect = [NebulaCaptureNative+RECT]::new()
  if (![NebulaCaptureNative]::GetWindowRect($handle, [ref]$rect)) { throw 'GetWindowRect failed' }
  $originX = $rect.Left; $originY = $rect.Top
  $right = $rect.Right; $bottom = $rect.Bottom
  $windowId = ('0x{0:X}' -f $handle.ToInt64())
  $dpi = [NebulaCaptureNative]::GetDpiForWindow($handle)
  if ($dpi -gt 0) { $dpiScale = [double]$dpi / 96.0 }
  if ([NebulaCaptureNative]::IsIconic($handle)) { $warnings.Add('window_is_minimized') }
  $warnings.Add('gdi_compatibility_fallback')
  $warnings.Add('occluded_windows_may_be_incomplete')
  $warnings.Add('secure_desktop_drm_and_protected_surfaces_are_not_captured')
} else {
  throw "unsupported capture source '$($cfg.source)'"
}

$width = $right - $originX
$height = $bottom - $originY
if ($width -le 0 -or $height -le 0) { throw 'capture region is empty' }

$bitmap = [Drawing.Bitmap]::new($width, $height, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
try {
  $graphics.CopyFromScreen(
    $originX, $originY, 0, 0,
    [Drawing.Size]::new($width, $height),
    [Drawing.CopyPixelOperation]::SourceCopy
  )
  $cursorInfo = $null
  if ([bool]$cfg.includeCursor) {
    $pos = [Windows.Forms.Cursor]::Position
    $visible = $pos.X -ge $originX -and $pos.X -lt $right -and
      $pos.Y -ge $originY -and $pos.Y -lt $bottom
    if ($visible) {
      $cursor = [Windows.Forms.Cursor]::Current
      if ($null -eq $cursor) { $cursor = [Windows.Forms.Cursors]::Default }
      $cursor.Draw($graphics, [Drawing.Rectangle]::new(
        $pos.X - $originX, $pos.Y - $originY, 32, 32
      ))
    }
    $cursorInfo = [pscustomobject]@{ x = $pos.X; y = $pos.Y; visible = $visible }
  }
  $bitmap.Save([string]$cfg.outputPath, [Drawing.Imaging.ImageFormat]::Png)
  [pscustomobject]@{
    source = [string]$cfg.source
    displayId = $displayId
    windowId = $windowId
    physicalWidth = $width
    physicalHeight = $height
    dpiScale = $dpiScale
    cursor = $cursorInfo
    warnings = @($warnings)
  } | ConvertTo-Json -Compress -Depth 4
} finally {
  $graphics.Dispose()
  $bitmap.Dispose()
}
"#;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaptureMeta {
    source: String,
    #[serde(default)]
    display_id: Option<String>,
    #[serde(default)]
    window_id: Option<String>,
    physical_width: u32,
    physical_height: u32,
    #[serde(default = "one")]
    dpi_scale: f64,
    #[serde(default)]
    cursor: Option<Value>,
    #[serde(default)]
    warnings: Vec<String>,
}

fn one() -> f64 {
    1.0
}

/// Build the desktop screenshot tool.
#[must_use]
pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(DesktopScreenshot)]
}

struct DesktopScreenshot;

#[async_trait]
impl Tool for DesktopScreenshot {
    fn name(&self) -> &str {
        "desktop.screenshot"
    }

    fn category(&self) -> &str {
        CATEGORY
    }

    fn description(&self) -> &str {
        "Capture an interactive Windows display or window with bounded PNG, JPEG, or WebP output."
    }

    fn input_schema(&self) -> Value {
        ObjectSchema::new()
            .enumerated(
                "source",
                "Capture source.",
                &["all_displays", "display", "window"],
                true,
            )
            .string("displayId", "Display identifier such as DISPLAY1.", false)
            .string("windowId", "Hexadecimal native window handle.", false)
            .enumerated("format", "Image format.", &["png", "jpeg", "webp"], false)
            .integer("quality", "Lossy image quality from 1 to 100.", false)
            .boolean("includeCursor", "Draw the cursor and return its position.", false)
            .prop(
                "scale",
                json!({"type": "number", "minimum": 0.1, "maximum": 2.0}),
                false,
            )
            .integer("maxBytes", "Maximum encoded output size.", false)
            .enumerated("output", "Return mode.", &["inline", "file"], false)
            .string("outputPath", "Policy-checked destination when output=file.", false)
            .build()
    }

    fn annotations(&self) -> Option<ToolAnnotations> {
        Some(ToolAnnotations {
            read_only_hint: Some(true),
            ..Default::default()
        })
    }

    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<CallToolResult> {
        ensure_windows(self.name())?;
        ctx.ensure_active()?;
        let a = Args::new(&args)?;
        let source = a.str_or("source", "all_displays")?;
        let display_id = a.opt_str("displayId")?;
        let window_id = a.opt_str("windowId")?;
        match source {
            "all_displays" if display_id.is_some() || window_id.is_some() => {
                return Err(ToolError::InvalidArguments(
                    "displayId/windowId are not valid for all_displays".into(),
                ));
            }
            "display" if display_id.is_none() || window_id.is_some() => {
                return Err(ToolError::InvalidArguments(
                    "display capture requires displayId and no windowId".into(),
                ));
            }
            "window" if window_id.is_none() || display_id.is_some() => {
                return Err(ToolError::InvalidArguments(
                    "window capture requires windowId and no displayId".into(),
                ));
            }
            "all_displays" | "display" | "window" => {}
            other => {
                return Err(ToolError::InvalidArguments(format!(
                    "unsupported capture source '{other}'"
                )));
            }
        }
        let format = a.str_or("format", "png")?;
        if !matches!(format, "png" | "jpeg" | "webp") {
            return Err(ToolError::InvalidArguments(format!(
                "unsupported image format '{format}'"
            )));
        }
        let quality = a.u64_or("quality", 80)?;
        if matches!(format, "jpeg" | "webp") && !(1..=100).contains(&quality) {
            return Err(ToolError::InvalidArguments(
                "quality must be between 1 and 100 for lossy formats".into(),
            ));
        }
        let scale = match a.opt_value("scale") {
            None => 1.0,
            Some(value) => value.as_f64().ok_or_else(|| {
                ToolError::InvalidArguments("field 'scale' must be a number".into())
            })?,
        };
        if !scale.is_finite() || !(0.1..=2.0).contains(&scale) {
            return Err(ToolError::InvalidArguments(
                "scale must be between 0.1 and 2.0".into(),
            ));
        }
        let max_bytes = a.u64_or("maxBytes", DEFAULT_MAX_BYTES)?;
        let policy_limit = ctx.policy.max_output_bytes() as u64;
        if max_bytes == 0 || max_bytes > policy_limit {
            return Err(ToolError::InvalidArguments(format!(
                "maxBytes must be between 1 and the policy limit ({policy_limit})"
            )));
        }
        let output = a.str_or("output", "inline")?;
        if !matches!(output, "inline" | "file") {
            return Err(ToolError::InvalidArguments(
                "output must be inline or file".into(),
            ));
        }
        let output_path = match output {
            "file" => Some(ctx.resolve_path(a.str("outputPath")?)?),
            _ => None,
        };

        let capture_path = ctx.resolve_path(&format!(
            ".nebula-capture-{}.png",
            Uuid::new_v4()
        ))?;
        if let Some(parent) = capture_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let config = json!({
            "source": source,
            "displayId": display_id,
            "windowId": window_id,
            "includeCursor": a.bool_or("includeCursor", false)?,
            "outputPath": capture_path.display().to_string(),
        });
        let encoded_config = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&config)?);
        let script = POWERSHELL_CAPTURE.replace("__CONFIG__", &encoded_config);
        let result = ctx
            .guarded(ctx.timeout(None), run_powershell(ctx, POWERSHELL, &script, None))
            .await;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                let _ = tokio::fs::remove_file(&capture_path).await;
                return Err(error);
            }
        };
        if !result.success() {
            let _ = tokio::fs::remove_file(&capture_path).await;
            let detail = if result.stderr.trim().is_empty() {
                result.stdout.trim()
            } else {
                result.stderr.trim()
            };
            if detail.contains("stale window handle") {
                return Err(ToolError::StaleHandle(detail.to_string()));
            }
            return Err(ToolError::Execution(format!(
                "desktop screenshot failed: {detail}"
            )));
        }
        let meta: CaptureMeta = serde_json::from_str(result.stdout.trim()).map_err(|e| {
            ToolError::Execution(format!("invalid screenshot metadata: {e}"))
        })?;
        let raw = tokio::fs::read(&capture_path).await?;
        let _ = tokio::fs::remove_file(&capture_path).await;
        ctx.ensure_active()?;
        let (encoded, width, height, mut warnings) =
            encode_image(&raw, scale, format, quality)?;
        if encoded.len() as u64 > max_bytes {
            return Err(ToolError::OutputTooLarge {
                limit: max_bytes as usize,
            });
        }
        if format == "webp" {
            warnings.push("webp_encoder_is_lossless".into());
        }
        let hash = hex::encode(Sha256::digest(&encoded));
        if let Some(path) = output_path.as_ref() {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&path, &encoded).await?;
        }
        Ok(json_value_result(json!({
            "captureId": Uuid::new_v4().to_string(),
            "source": meta.source,
            "displayId": meta.display_id,
            "windowId": meta.window_id,
            "width": width,
            "height": height,
            "physicalWidth": meta.physical_width,
            "physicalHeight": meta.physical_height,
            "dpiScale": meta.dpi_scale,
            "format": format,
            "byteLength": encoded.len(),
            "sha256": hash,
            "content": if output == "inline" {
                Value::String(base64::engine::general_purpose::STANDARD.encode(&encoded))
            } else {
                Value::Null
            },
            "path": output_path.as_ref().map(|path| path.display().to_string()),
            "cursor": meta.cursor,
            "warnings": meta.warnings.into_iter().chain(warnings).collect::<Vec<_>>(),
        })))
    }
}

fn encode_image(
    raw: &[u8],
    scale: f64,
    format: &str,
    quality: u64,
) -> Result<(Vec<u8>, u32, u32, Vec<String>)> {
    let image = image::load_from_memory(raw)
        .map_err(|e| ToolError::Execution(format!("decode captured image: {e}")))?;
    let image = if (scale - 1.0).abs() > f64::EPSILON {
        let width = ((image.width() as f64) * scale).round().max(1.0) as u32;
        let height = ((image.height() as f64) * scale).round().max(1.0) as u32;
        image.resize_exact(width, height, image::imageops::FilterType::Lanczos3)
    } else {
        image
    };
    let width = image.width();
    let height = image.height();
    let mut output = Cursor::new(Vec::new());
    match format {
        "jpeg" => {
            let rgb = image.to_rgb8();
            let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
                &mut output,
                quality as u8,
            );
            encoder
                .write_image(
                    rgb.as_raw(),
                    rgb.width(),
                    rgb.height(),
                    image::ExtendedColorType::Rgb8,
                )
                .map_err(|e| ToolError::Execution(format!("encode JPEG: {e}")))?;
        }
        "png" => image
            .write_to(&mut output, image::ImageFormat::Png)
            .map_err(|e| ToolError::Execution(format!("encode PNG: {e}")))?,
        "webp" => image
            .write_to(&mut output, image::ImageFormat::WebP)
            .map_err(|e| ToolError::Execution(format!("encode WebP: {e}")))?,
        _ => unreachable!("format is validated before encoding"),
    }
    Ok((output.into_inner(), width, height, Vec::new()))
}