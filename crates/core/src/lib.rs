//! # nebula-mcp-core
//!
//! The runtime foundation shared by every tool and the server binary. This
//! crate owns every enforcement point, so a tool cannot reach the filesystem,
//! a process or the network except through an API that applies the policy:
//!
//! * [`config`], [`store`], [`hotreload`]: strict TOML configuration held as
//!   atomically swapped snapshots.
//! * [`policy`]: what a call may touch.
//! * [`fs`], [`process`], [`net`]: the capabilities that apply the policy.
//! * [`schema`], [`args`]: argument schemas, validation and typed access.
//! * [`tool`], [`context`], [`dispatch`]: tool metadata, the per-call context
//!   and the dispatcher every call passes through.
//! * [`metrics`], [`telemetry`], [`error`].

#![warn(missing_docs)]

pub mod args;
pub mod config;
pub mod context;
pub mod dispatch;
pub mod error;
pub mod fs;
pub mod hotreload;
pub mod metrics;
pub mod net;
pub mod policy;
pub mod process;
pub mod schema;
pub mod store;
pub mod telemetry;
pub mod tool;

pub use context::{OwnerId, ProgressSink, ProgressUpdate, ToolContext};
pub use dispatch::{Call, CallFailure, Dispatcher, UnknownTool};
pub use error::{Result, ToolError};
pub use metrics::{Metrics, Outcome};
pub use store::ConfigStore;
pub use tool::{Category, Content, Effects, Gate, Platforms, Tool, ToolOutput, ToolRegistry, ToolSpec};
