//! # nebula-mcp-tools
//!
//! The tools of the Nebula MCP server. A tool is a [`ToolSpec`] and an async
//! function. It reaches files, processes and the network only through the
//! capabilities of its [`ToolContext`]; `clippy.toml` in this crate bans the
//! standard-library and tokio routes around them.
//!
//! [`ToolSpec`]: nebula_mcp_core::ToolSpec
//! [`ToolContext`]: nebula_mcp_core::ToolContext

#![warn(missing_docs)]

use nebula_mcp_core::ToolRegistry;

mod common;
mod fs;
#[cfg(test)]
mod testkit;

/// Register every tool. An error names a malformed definition, which is a
/// bug in this crate (the tests register everything).
pub fn register_all(registry: &mut ToolRegistry) -> Result<(), String> {
    for tool in fs::tools() {
        registry.register(tool)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_definition_is_accepted_by_the_registry() {
        let mut registry = ToolRegistry::new();
        register_all(&mut registry).unwrap();
        assert!(!registry.is_empty());
    }

    #[test]
    fn descriptions_and_titles_are_reasonably_sized() {
        let mut registry = ToolRegistry::new();
        register_all(&mut registry).unwrap();
        for tool in registry.all() {
            let spec = tool.spec();
            assert!(spec.title.len() <= 40, "{}: title too long", spec.name);
            assert!(
                spec.description.len() <= 600,
                "{}: description is {} bytes; keep tools/list small",
                spec.name,
                spec.description.len()
            );
        }
    }
}
