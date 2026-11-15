p = 'crates/tools/src/powershell.rs'
s = open(p).read()
s = s.replace('''/// Runs before every script: quiet progress records, UTF-8 output, and
/// errors that end the script instead of being printed and ignored.
const PRELUDE: &str = "$ProgressPreference='SilentlyContinue';\\
                       $ErrorActionPreference='Stop';\\
                       [Console]::OutputEncoding=[Text.Encoding]::UTF8;";
''', '''/// Runs before every script: no progress records in the output, and UTF-8.
const PRELUDE: &str = "$ProgressPreference='SilentlyContinue';\\
                       [Console]::OutputEncoding=[Text.Encoding]::UTF8;";

/// For the server's own scripts: an error ends the script with a failure
/// instead of being printed and passed over.
pub(crate) const STOP_ON_ERROR: &str = "$ErrorActionPreference='Stop';";
''')
open(p, 'w').write(s)

p = 'crates/tools/src/windows.rs'
s = open(p).read()
s = s.replace('''use crate::powershell::{platform_shell, script, SHELLS};

const READ: Effects = Effects::read_only().exec(SHELLS);
const STRICT: &str = "Set-StrictMode -Version 2;";
''', '''use crate::powershell::{platform_shell, script, SHELLS, STOP_ON_ERROR};

const READ: Effects = Effects::read_only().exec(SHELLS);
''')
s = s.replace('''    let mut cmd = script(platform_shell(), &format!("{STRICT}{body}"));''',
              '''    let mut cmd = script(platform_shell(), &format!("{STOP_ON_ERROR}{body}"));''')
s = s.replace('''/// A fixed script with its values in the environment.
fn typed(''', '''/// A fixed script with its values in the environment.
pub(crate) fn typed(''')
s = s.replace('''fn failure(what: &str, out: &Output) -> ToolError {''', '''pub(crate) fn failure(what: &str, out: &Output) -> ToolError {''')
s = s.replace('''/// Run and return what the script printed.
async fn answer(''', '''/// Run and return what the script printed.
pub(crate) async fn answer(''')
open(p, 'w').write(s)

p = 'crates/tools/src/process.rs'
s = open(p).read()
s = s.replace('''fn describe(pid: Pid, process: &sysinfo::Process''', '''/// Whether `pid` runs inside one of the caller's terminal sessions.
pub(crate) async fn in_my_sessions(ctx: &ToolContext, sessions: &Sessions, pid: u32) -> Result<bool> {
    let system = snapshot(ctx).await?;
    Ok(mine(ctx, sessions, &system)
        .await
        .contains(&Pid::from_u32(pid)))
}

fn describe(pid: Pid, process: &sysinfo::Process''')
open(p, 'w').write(s)

p = 'crates/tools/src/lib.rs'
s = open(p).read()
s = s.replace('mod common;\n', 'mod common;\nmod diagnostics;\n')
s = s.replace('mod net;\n', 'mod net;\nmod powershell;\n')
s = s.replace('mod terminal;\n', 'mod terminal;\nmod windows;\n')
s = s.replace('''        .chain(security::tools(&state.link));''', '''        .chain(security::tools(&state.link))
        .chain(powershell::tools())
        .chain(windows::tools())
        .chain(diagnostics::tools(&state.sessions));''')
open(p, 'w').write(s)
