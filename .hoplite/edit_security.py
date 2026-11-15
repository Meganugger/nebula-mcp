import sys

p = 'crates/tools/src/security.rs'
s = open(p).read()
s = s.replace('''use nebula_mcp_core::{
    Category, Dispatcher, Effects, Gate, Result, Tool, ToolContext, ToolError, ToolOutput,
};''', '''use futures::future::BoxFuture;
use nebula_mcp_core::policy::{expand_home, paths_equal};
use nebula_mcp_core::{
    Category, Dispatcher, Effects, Result, Tool, ToolContext, ToolError, ToolOutput,
};''')
s = s.replace('''// `Gate` documents intent for readers of the effects above; nothing here is
// gated because nothing here acts.
const _: Gate = Gate::Never;

''', '')
old_start = s.index('    let bind = |f: fn(&ToolContext, &Dispatcher, Value) -> Result<ToolOutput>| {')
old_end = s.index('    vec![', old_start)
s = s[:old_start] + '    let bind = |f: Inspector| bound(link, f);\n' + s[old_end:]
s = s.replace('''/// The `security` tools.
pub(crate) fn tools(''', '''type Inspector = fn(&ToolContext, &Dispatcher, Value) -> Result<ToolOutput>;

/// A handler that runs `f` against the running dispatcher.
fn bound(
    link: &Arc<Link>,
    f: Inspector,
) -> impl for<'a> Fn(&'a ToolContext, Value) -> BoxFuture<'a, Result<ToolOutput>> + Send + Sync + 'static
{
    let link = link.clone();
    move |ctx, args| {
        let link = link.clone();
        Box::pin(async move { f(ctx, &*link.get()?, args) })
    }
}

/// The `security` tools.
pub(crate) fn tools(''')
s = s.replace('''        let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
        if path.components().count() <= 1 || home.is_some_and(|h| path == std::path::Path::new(&h))
        {''', '''        if path.components().count() <= 2 || paths_equal(path, &expand_home("~")) {''')
open(p, 'w').write(s)

p = 'crates/tools/src/lib.rs'
s = open(p).read()
s = s.replace('mod jobs;\n', 'mod jobs;\nmod process;\n')
s = s.replace('mod scheduler;\n', 'mod scheduler;\nmod security;\n')
s = s.replace('''    sessions: Arc<sessions::Sessions>,
    jobs: Arc<jobs::Jobs>,
}''', '''    sessions: Arc<sessions::Sessions>,
    jobs: Arc<jobs::Jobs>,
    link: Arc<security::Link>,
}''')
s = s.replace('''        self.jobs.attach(dispatcher);''', '''        self.jobs.attach(dispatcher);
        self.link.attach(dispatcher);''')
s = s.replace('''        .chain(scheduler::tools(&state.jobs));''', '''        .chain(scheduler::tools(&state.jobs))
        .chain(process::tools(&state.sessions))
        .chain(security::tools(&state.link));''')
open(p, 'w').write(s)
