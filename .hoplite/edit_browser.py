p = 'crates/tools/src/browser.rs'
s = open(p).read()
old_start = s.index("  let browser = null, why = '';")
old_end = s.index("  const out = { console: [], requests: [], blocked: 0 };")
new = """  // An operator-chosen browser first, then Playwright's own, then the
  // system's Chrome or Edge.
  const tries = [{}, { channel: 'chrome' }, { channel: 'msedge' }];
  if (process.env.CHROME_PATH) tries.unshift({ executablePath: process.env.CHROME_PATH });
  let browser = null;
  const why = [];
  for (const extra of tries) {
    try { browser = await pw.chromium.launch({ ...launch, ...extra }); break; }
    catch (e) { why.push(String(e && e.message || e).split('\\n')[0]); }
  }
  if (!browser) { process.stderr.write(why.join(' | ')); process.exit(4); }
"""
s = s[:old_start] + new + s[old_end:]
s = s.replace('''        .pass_env("PLAYWRIGHT_BROWSERS_PATH")''', '''        .pass_env("PLAYWRIGHT_BROWSERS_PATH")
        .pass_env("CHROME_PATH")''')
s = s.replace('''             playwright install chromium",
            clip(out.stderr.text.trim(), 300)''', '''             playwright install chromium, or point CHROME_PATH at a Chrome or Chromium binary",
            clip(out.stderr.text.trim(), 600)''')
s = s.replace('''//! Playwright is taken from Node's global module directory (or `NODE_PATH`
//! when the operator passes it through), never from a directory the client
//! can write.''', '''//! Playwright is taken from Node's global module directory (or `NODE_PATH`
//! when the operator passes it through), never from a directory the client
//! can write. The browser is the one Playwright installed, or the system's
//! Chrome or Edge, or the binary the operator names in `CHROME_PATH`.''')
open(p, 'w').write(s)
