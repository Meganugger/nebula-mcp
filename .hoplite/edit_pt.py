p = 'crates/tools/src/powershell_tests.rs'
s = open(p).read()
s = s.replace('''    let elevated = super::elevated_for_tests(&strict).await;
''', '''    let elevated = is_elevated();
''')
s = s.replace('''/// A kit in which scripts may run''', '''/// Whether this process has administrator or root rights, asked the way the
/// tool asks.
fn is_elevated() -> bool {
    let out = std::process::Command::new("pwsh")
        .args(["-NoLogo", "-NoProfile", "-Command", super::IS_ELEVATED])
        .output()
        .expect("pwsh runs");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .eq_ignore_ascii_case("true")
}

/// A kit in which scripts may run''')
open(p, 'w').write(s)
