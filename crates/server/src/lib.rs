//! # nebula-mcp-server
//!
//! The Nebula MCP server: the engine ([`app`]), its MCP face ([`handler`]),
//! the transports and the command line.

#![warn(missing_docs)]

pub mod app;
pub mod cli;
pub mod handler;
pub mod http;
pub mod stdio;
