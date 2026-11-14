//! # nebula-mcp-server
//!
//! Library surface of the Nebula MCP server: the [`server::Server`] dispatch
//! engine plus the stdio and [`http`] transports. The `nebula-mcp` binary is a
//! thin CLI wrapper around this.

#![warn(missing_docs)]

pub mod http;
pub mod metrics_endpoint;
pub mod prompts;
pub mod resources;
pub mod server;

pub use server::Server;
