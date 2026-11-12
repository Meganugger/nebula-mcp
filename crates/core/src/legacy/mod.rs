//! The pre-overhaul tool API, kept only until every tool category has been
//! ported to [`crate::tool`]. Nothing new may be written against this module.

pub mod context;
pub mod security;
pub mod tool;

pub use crate::config;
pub use crate::error::{Result, ToolError};
pub use crate::metrics::{Metrics, Outcome};
pub use context::{ProgressSink, ProgressUpdate, ToolContext};
pub use tool::{Tool, ToolRegistry};
