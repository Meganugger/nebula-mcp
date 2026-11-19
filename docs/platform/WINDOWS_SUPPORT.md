# Windows support

The existing Windows wrappers compile on supported targets and return
`platform_unsupported` elsewhere. The desktop slice requires an interactive
Windows user session; Windows Server Session 0 and locked/secure desktops must
return an explicit unavailable or denied error rather than fabricated data.

The current desktop adapters expose:

- display-mode discovery through Windows PowerShell;
- cursor discovery through `GetCursorPos`;
- visible application discovery through `Get-Process`;
- bounded mouse/keyboard dispatch through a fixed `SendInput` helper;
- window mutation through graceful PowerShell operations, with force-close
  separately gated as destructive.

Per-monitor DPI conversion, Graphics Capture/Desktop Duplication, UI
Automation, RDP/multiple-monitor integration tests, and a dedicated agent are
not yet supported by this slice.