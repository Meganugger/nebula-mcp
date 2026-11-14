//! The MCP face of the engine: an rmcp [`ServerHandler`] over [`App`].
//!
//! One handler exists per connection: per process on stdio, per session on
//! the legacy HTTP path, per request on the stateless path. It carries the
//! owner of long-lived state and nothing else; everything shared lives in
//! [`App`].

use std::sync::Arc;

use nebula_mcp_core::tool::{Content, ToolSpec};
use nebula_mcp_core::{Call, OwnerId, ProgressSink, ToolOutput};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ProgressNotificationParam, ProtocolVersion,
    ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::Value;

use crate::app::{App, DEFAULT_INSTRUCTIONS, SERVER_VERSION};

/// First revision with tool annotations.
const REV_ANNOTATIONS: &str = "2025-03-26";
/// First revision with titles, output schemas and structured results.
const REV_STRUCTURED: &str = "2025-06-18";

/// A connection's view of the server.
#[derive(Clone)]
pub struct Handler {
    app: Arc<App>,
    owner: OwnerId,
}

impl Handler {
    /// A handler whose long-lived state belongs to `owner`.
    #[must_use]
    pub fn new(app: Arc<App>, owner: OwnerId) -> Self {
        Self { app, owner }
    }
}

/// The revision a request is served under. A request that names none is a
/// legacy client that has not finished initialising; it gets the oldest
/// behaviour.
fn revision(context: &RequestContext<RoleServer>) -> String {
    context
        .protocol_version()
        .map_or_else(|| ProtocolVersion::V_2024_11_05.to_string(), |v| v.to_string())
}

fn at_least(revision: &str, floor: &str) -> bool {
    // Revisions are ISO dates, which order as text.
    revision >= floor
}

fn schema_object(schema: &Value) -> Arc<serde_json::Map<String, Value>> {
    Arc::new(schema.as_object().cloned().unwrap_or_default())
}

/// A tool definition as the given revision describes one.
fn describe(spec: &ToolSpec, revision: &str) -> Tool {
    let mut tool = Tool::new(spec.name, spec.description, schema_object(&spec.input));
    if at_least(revision, REV_ANNOTATIONS) {
        let a = spec.annotations();
        tool = tool.with_annotations(
            ToolAnnotations::new()
                .read_only(a.read_only)
                .destructive(a.destructive)
                .idempotent(a.idempotent)
                .open_world(a.open_world),
        );
    }
    if at_least(revision, REV_STRUCTURED) {
        tool = tool.with_title(spec.title);
        if let Some(output) = &spec.output {
            tool = tool.with_raw_output_schema(schema_object(output));
        }
    }
    tool
}

fn blocks(output: &ToolOutput) -> Vec<ContentBlock> {
    output
        .content
        .iter()
        .map(|c| match c {
            Content::Text(text) => ContentBlock::text(text.clone()),
            Content::Image { data, mime_type } => {
                ContentBlock::image(data.clone(), mime_type.clone())
            }
        })
        .collect()
}

impl ServerHandler for Handler {
    fn get_info(&self) -> ServerConfig {
        let loaded = self.app.store().snapshot();
        let config = &loaded.config;
        let instructions = config
            .server
            .instructions
            .clone()
            .unwrap_or_else(|| DEFAULT_INSTRUCTIONS.to_string());
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                config.server.name.clone(),
                SERVER_VERSION,
            ))
            .with_instructions(instructions)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let revision = revision(&context);
        let tools = self
            .app
            .dispatcher()
            .exposed()
            .iter()
            .map(|t| describe(t.spec(), &revision))
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let revision = revision(&context);
        let arguments = request
            .arguments
            .map_or(Value::Null, Value::Object);

        // Progress goes to the requester for as long as the call runs and
        // stops with it, whatever ends the call.
        let (progress, forwarder) = match context.meta.get_progress_token() {
            Some(token) => {
                let (sink, mut updates) = ProgressSink::channel();
                let peer = context.peer.clone();
                let task = tokio::spawn(async move {
                    while let Some(update) = updates.recv().await {
                        let mut param =
                            ProgressNotificationParam::new(token.clone(), update.progress);
                        if let Some(total) = update.total {
                            param = param.with_total(total);
                        }
                        if let Some(message) = update.message {
                            param = param.with_message(message);
                        }
                        if peer.notify_progress(param).await.is_err() {
                            break;
                        }
                    }
                });
                (Some(sink), Some(AbortOnDrop(task)))
            }
            None => (None, None),
        };

        let outcome = self
            .app
            .dispatcher()
            .call(Call {
                name: request.name.to_string(),
                arguments,
                owner: self.owner.clone(),
                request_id: context.id.to_string(),
                cancel: context.ct.clone(),
                progress,
            })
            .await;
        drop(forwarder);

        let result = match outcome {
            // An unknown or unavailable tool is a protocol error.
            Err(unknown) => return Err(McpError::invalid_params(unknown.message, None)),
            Ok(Ok(output)) => {
                let mut result = CallToolResult::success(blocks(&output));
                if at_least(&revision, REV_STRUCTURED) {
                    result.structured_content = output.structured;
                }
                result
            }
            // A failed call is a result the model can read and act on.
            Ok(Err(failure)) => CallToolResult::error(vec![ContentBlock::text(failure.text)]),
        };
        Ok(CallToolResponse::Complete(result))
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
