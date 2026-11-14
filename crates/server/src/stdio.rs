//! The stdio transport: one client, newline-delimited JSON-RPC on stdin and
//! stdout. Logs go to stderr; stdout carries only protocol messages.

use std::sync::Arc;
use std::time::Duration;

use nebula_mcp_core::OwnerId;
use rmcp::ServiceExt;

use crate::app::App;
use crate::handler::Handler;

/// How long running calls get to stop once the server is told to exit.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Serve one client on stdin/stdout until it disconnects or the server is
/// told to stop.
pub async fn serve(app: Arc<App>) -> Result<(), String> {
    let handler = Handler::new(app.clone(), OwnerId::stdio());
    let service = handler
        .serve_with_ct(rmcp::transport::stdio(), app.shutdown().child_token())
        .await
        .map_err(|e| format!("starting the stdio transport: {e}"))?;
    let reason = service.waiting().await;
    tracing::info!(?reason, "stdio transport closed");
    // The client is gone (or shutdown was requested): stop every call.
    app.shutdown().cancel();
    Ok(())
}
