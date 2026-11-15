//! Error taxonomy shared by the core runtime and every tool.
//!
//! Tools return [`ToolError`]. The server turns it into an `isError` tool
//! result whose text starts with the stable category, so the model can read
//! the failure and correct its next call.

use std::time::Duration;

/// The result type used throughout the runtime.
pub type Result<T> = std::result::Result<T, ToolError>;

/// A structured, categorised tool error.
///
/// Messages are written for the model that will read them: say what was
/// wrong and, where it helps, what a valid call looks like.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ToolError {
    /// The caller supplied invalid or missing arguments.
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),

    /// A security policy denied the operation.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The requested path is outside every allowed root.
    #[error("path '{path}' is not inside an allowed root")]
    PathNotAllowed {
        /// The offending path as the caller wrote it.
        path: String,
    },

    /// A command or executable is not on the allowlist.
    #[error("command '{0}' is not permitted by policy")]
    CommandNotAllowed(String),

    /// A network destination is not permitted by policy.
    #[error("network destination not permitted: {0}")]
    NetworkNotAllowed(String),

    /// The operation exceeded its timeout.
    #[error("operation timed out after {0:?}")]
    Timeout(Duration),

    /// The operation was cancelled by the client or by shutdown.
    #[error("operation cancelled")]
    Cancelled,

    /// A configured limit (sessions, jobs, queue, size) was reached.
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),

    /// A file, directory, session, job or other named thing does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// A required external program (git, docker, node, ...) is not installed.
    #[error("required program not found: {0}")]
    ProgramNotFound(String),

    /// The feature needs a platform this build is not running on.
    #[error("not supported on this platform: {0}")]
    PlatformUnsupported(String),

    /// An underlying I/O error.
    #[error("I/O error: {0}")]
    Io(String),

    /// The operation ran and reported failure (non-zero exit, HTTP error).
    #[error("execution failed: {0}")]
    Execution(String),

    /// An unexpected internal error. Always a bug in the server.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ToolError {
    /// A short, stable category label used in results, logs and metrics.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            ToolError::InvalidArguments(_) => "invalid_arguments",
            ToolError::PermissionDenied(_) => "permission_denied",
            ToolError::PathNotAllowed { .. } => "path_not_allowed",
            ToolError::CommandNotAllowed(_) => "command_not_allowed",
            ToolError::NetworkNotAllowed(_) => "network_not_allowed",
            ToolError::Timeout(_) => "timeout",
            ToolError::Cancelled => "cancelled",
            ToolError::LimitExceeded(_) => "limit_exceeded",
            ToolError::NotFound(_) => "not_found",
            ToolError::ProgramNotFound(_) => "program_not_found",
            ToolError::PlatformUnsupported(_) => "platform_unsupported",
            ToolError::Io(_) => "io",
            ToolError::Execution(_) => "execution",
            ToolError::Internal(_) => "internal",
        }
    }

    /// Whether the error is a policy refusal (as opposed to a failure).
    #[must_use]
    pub fn is_denial(&self) -> bool {
        matches!(
            self,
            ToolError::PermissionDenied(_)
                | ToolError::PathNotAllowed { .. }
                | ToolError::CommandNotAllowed(_)
                | ToolError::NetworkNotAllowed(_)
        )
    }

    /// Shorthand for an [`ToolError::InvalidArguments`] error.
    pub fn invalid(msg: impl Into<String>) -> Self {
        ToolError::InvalidArguments(msg.into())
    }

    /// Shorthand for a [`ToolError::PermissionDenied`] error.
    pub fn denied(msg: impl Into<String>) -> Self {
        ToolError::PermissionDenied(msg.into())
    }

    /// Map an I/O error for `what`, keeping "not found" distinguishable.
    pub fn from_io(what: &str, e: &std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => ToolError::NotFound(what.to_string()),
            std::io::ErrorKind::PermissionDenied => {
                ToolError::Io(format!("{what}: the operating system denied access"))
            }
            _ => ToolError::Io(format!("{what}: {e}")),
        }
    }
}

impl From<std::io::Error> for ToolError {
    fn from(e: std::io::Error) -> Self {
        ToolError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for ToolError {
    fn from(e: serde_json::Error) -> Self {
        ToolError::InvalidArguments(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_are_stable() {
        assert_eq!(
            ToolError::PathNotAllowed { path: "x".into() }.category(),
            "path_not_allowed"
        );
        assert_eq!(
            ToolError::Timeout(Duration::from_secs(1)).category(),
            "timeout"
        );
        assert_eq!(
            ToolError::ProgramNotFound("git".into()).category(),
            "program_not_found"
        );
    }

    #[test]
    fn denials_are_distinguished_from_failures() {
        assert!(ToolError::CommandNotAllowed("rm".into()).is_denial());
        assert!(!ToolError::Execution("exit 1".into()).is_denial());
    }

    #[test]
    fn io_not_found_maps_to_not_found() {
        let e = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(matches!(
            ToolError::from_io("a.txt", &e),
            ToolError::NotFound(_)
        ));
    }
}
