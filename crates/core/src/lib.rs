//! # nebula-mcp-core
//!
//! The runtime foundation shared by every tool and the server binary. This
//! crate owns every enforcement point, so a tool cannot reach the filesystem,
//! a process or the network except through an API that applies the policy.

#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod policy;

pub use error::{Result, ToolError};
