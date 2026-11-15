//! Shared plumbing for tool definitions.

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use futures::future::BoxFuture;
use nebula_mcp_core::{
    Category, Effects, Platforms, Result, Tool, ToolContext, ToolOutput, ToolSpec,
};
use serde_json::Value;

type Handler =
    dyn for<'a> Fn(&'a ToolContext, Value) -> BoxFuture<'a, Result<ToolOutput>> + Send + Sync;

struct FnTool {
    spec: ToolSpec,
    handler: Box<Handler>,
}

#[async_trait]
impl Tool for FnTool {
    fn spec(&self) -> &ToolSpec {
        &self.spec
    }

    async fn call(&self, ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
        (self.handler)(ctx, args).await
    }
}

/// A tool made of a spec and an async function.
pub(crate) fn tool<F>(spec: ToolSpec, handler: F) -> Arc<dyn Tool>
where
    F: for<'a> Fn(&'a ToolContext, Value) -> BoxFuture<'a, Result<ToolOutput>>
        + Send
        + Sync
        + 'static,
{
    Arc::new(FnTool {
        spec,
        handler: Box::new(handler),
    })
}

/// Adapt `async fn(&ToolContext, Value) -> Result<ToolOutput>` to [`tool`].
macro_rules! handler {
    ($f:path) => {
        |ctx, args| Box::pin($f(ctx, args))
    };
}
pub(crate) use handler;

/// A spec for a tool that runs on every platform and returns text.
pub(crate) fn spec(
    name: &'static str,
    category: Category,
    title: &'static str,
    description: &'static str,
    input: Value,
    effects: Effects,
) -> ToolSpec {
    ToolSpec {
        name,
        category,
        title,
        description,
        input,
        output: None,
        effects,
        platforms: Platforms::ALL,
    }
}

/// Builder-style additions to [`ToolSpec`].
pub(crate) trait SpecExt {
    /// Declare the schema of the structured result.
    fn returns(self, output: Value) -> Self;
    /// Restrict the platforms the tool is offered on.
    #[allow(dead_code)] // used once the platform-specific categories are ported
    fn on(self, platforms: Platforms) -> Self;
}

impl SpecExt for ToolSpec {
    fn returns(mut self, output: Value) -> Self {
        self.output = Some(output);
        self
    }

    fn on(mut self, platforms: Platforms) -> Self {
        self.platforms = platforms;
        self
    }
}

/// A timestamp as RFC 3339 in UTC, or `None` when it cannot be represented.
pub(crate) fn rfc3339(t: SystemTime) -> Option<String> {
    time::OffsetDateTime::from(t)
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// Cut `s` to at most `max` characters, marking the cut.
pub(crate) fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}
