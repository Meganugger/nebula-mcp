//! Command rules: which programs may be executed.
//!
//! The allowlist is matched against the executable that will actually run. A
//! bare name is resolved on the search path the server started with, and the
//! resolved absolute path is what gets spawned, so neither a path to a
//! look-alike binary nor a caller-supplied `PATH` can substitute a different
//! program for an allowed name.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::ToolError;

/// Compiled command allowlist for one tool.
#[derive(Debug, Clone)]
pub struct CommandRules {
    allow_all: bool,
    names: Vec<String>,
    paths: Vec<PathBuf>,
    search_path: Option<OsString>,
}

/// A program that has passed the allowlist, resolved to the file that will be
/// executed. Only [`CommandRules::resolve`] creates one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedCommand {
    program: PathBuf,
    name: String,
}

impl CheckedCommand {
    /// Absolute path of the executable to spawn.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The name the caller asked for (for display and logs).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl CommandRules {
    /// Compile an allowlist. `search_path` is the trusted `PATH` used to
    /// resolve bare names.
    #[must_use]
    pub fn build(entries: &[String], search_path: Option<OsString>) -> Self {
        let mut allow_all = false;
        let mut names = Vec::new();
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.trim();
            if entry == "*" {
                allow_all = true;
            } else if is_path_like(entry) {
                paths.push(PathBuf::from(entry));
            } else if !entry.is_empty() {
                names.push(command_key(entry, cfg!(windows)));
            }
        }
        Self {
            allow_all,
            names,
            paths,
            search_path,
        }
    }

    /// Whether the standalone `"*"` entry is present.
    #[must_use]
    pub fn allows_everything(&self) -> bool {
        self.allow_all
    }

    /// Whether nothing at all may be executed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.allow_all && self.names.is_empty() && self.paths.is_empty()
    }

    /// The allowed entries, normalised (for diagnostics).
    #[must_use]
    pub fn entries(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if self.allow_all {
            out.push("*".to_string());
        }
        out.extend(self.names.iter().cloned());
        out.extend(self.paths.iter().map(|p| p.display().to_string()));
        out
    }

    /// Check `program` against the allowlist and resolve it to the executable
    /// that will run. Relative paths are taken relative to `cwd`.
    pub fn resolve(&self, program: &str, cwd: &Path) -> Result<CheckedCommand, ToolError> {
        let program = program.trim();
        if program.is_empty() {
            return Err(ToolError::InvalidArguments("program is empty".to_string()));
        }
        if self.is_empty() {
            return Err(ToolError::CommandNotAllowed(format!(
                "{program} (no allowed_commands are configured)"
            )));
        }
        let key = command_key(program, cfg!(windows));
        let checked = |path: PathBuf| CheckedCommand {
            program: path,
            name: program.to_string(),
        };

        if is_path_like(program) {
            let found = self.locate(program, cwd)?;
            let found_real = real(&found);
            if self.allow_all || self.paths.iter().any(|p| real(p) == found_real) {
                return Ok(checked(found));
            }
            if self.names.contains(&key) {
                // An allowed name permits a path only when it is the very
                // file that name resolves to on the trusted search path.
                if let Ok(trusted) = self.locate(&file_name(program), cwd) {
                    if real(&trusted) == found_real {
                        return Ok(checked(found));
                    }
                    return Err(ToolError::CommandNotAllowed(format!(
                        "{program} (it is not the '{}' on the server's PATH, which is {}; \
                         the operator can allow this exact path in allowed_commands)",
                        file_name(program),
                        trusted.display()
                    )));
                }
            }
            return Err(ToolError::CommandNotAllowed(program.to_string()));
        }

        let named = self.allow_all || self.names.contains(&key);
        match self.locate(program, cwd) {
            Ok(found) => {
                if named || self.paths.iter().any(|p| real(p) == real(&found)) {
                    Ok(checked(found))
                } else {
                    Err(ToolError::CommandNotAllowed(program.to_string()))
                }
            }
            Err(not_found) => {
                // Not on PATH: an absolute allowlist entry with this name
                // still identifies it.
                if let Some(path) = self
                    .paths
                    .iter()
                    .find(|p| command_key(&p.to_string_lossy(), cfg!(windows)) == key)
                {
                    return self.locate(&path.to_string_lossy(), cwd).map(checked);
                }
                if named {
                    Err(not_found)
                } else {
                    Err(ToolError::CommandNotAllowed(program.to_string()))
                }
            }
        }
    }

    /// Find the executable file for a name or path using the trusted search
    /// path (and `PATHEXT` on Windows).
    fn locate(&self, program: &str, cwd: &Path) -> Result<PathBuf, ToolError> {
        which::which_in(program, self.search_path.clone(), cwd)
            .map_err(|_| ToolError::ToolNotFound(program.to_string()))
    }
}

fn real(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn is_path_like(program: &str) -> bool {
    program.contains('/') || program.contains('\\') || Path::new(program).is_absolute()
}

fn file_name(program: &str) -> String {
    let trimmed = program.trim_end_matches(['/', '\\']);
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(trimmed)
        .to_string()
}

/// Reduce a program name or path to the key the allowlist compares. On
/// Windows names are case-insensitive and the executable extension is
/// optional.
fn command_key(program: &str, windows: bool) -> String {
    let base = file_name(program);
    if !windows {
        return base;
    }
    let lower = base.to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".bat", ".com"] {
        if let Some(stem) = lower.strip_suffix(ext) {
            if !stem.is_empty() {
                return stem.to_string();
            }
        }
    }
    lower
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(entries: &[&str]) -> CommandRules {
        let entries: Vec<String> = entries.iter().map(|s| (*s).to_string()).collect();
        CommandRules::build(&entries, std::env::var_os("PATH"))
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let r = rules(&[]);
        let cwd = std::env::temp_dir();
        assert!(matches!(
            r.resolve("git", &cwd),
            Err(ToolError::CommandNotAllowed(_))
        ));
    }

    #[test]
    fn keys_ignore_case_and_extension_only_on_windows() {
        assert_eq!(command_key("C:\\Tools\\Git.EXE", true), "git");
        assert_eq!(command_key("NPM.cmd", true), "npm");
        assert_eq!(command_key("GIT.EXE", true), "git");
        assert_eq!(command_key("/usr/bin/git", false), "git");
        assert_eq!(command_key("Git.exe", false), "Git.exe");
        assert_eq!(command_key(".exe", true), ".exe");
    }

    #[cfg(unix)]
    #[test]
    fn an_allowed_name_resolves_to_an_absolute_path() {
        let r = rules(&["sh"]);
        let cwd = std::env::temp_dir();
        let c = r.resolve("sh", &cwd).unwrap();
        assert!(c.program().is_absolute());
        assert_eq!(c.name(), "sh");
        assert!(matches!(
            r.resolve("ls", &cwd),
            Err(ToolError::CommandNotAllowed(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_look_alike_binary_elsewhere_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let planted = dir.path().join("sh");
        std::fs::write(&planted, "#!/bin/sh\necho planted\n").unwrap();
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).unwrap();

        let r = rules(&["sh"]);
        let err = r.resolve(planted.to_str().unwrap(), dir.path()).unwrap_err();
        assert!(matches!(err, ToolError::CommandNotAllowed(_)), "{err:?}");
        // The same file by a relative path from its own directory.
        let err = r.resolve("./sh", dir.path()).unwrap_err();
        assert!(matches!(err, ToolError::CommandNotAllowed(_)), "{err:?}");
        // The genuine one by its full path is fine.
        let genuine = r.resolve("sh", dir.path()).unwrap();
        assert!(r
            .resolve(genuine.program().to_str().unwrap(), dir.path())
            .is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn an_absolute_entry_allows_exactly_that_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("mytool");
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        let other = dir.path().join("sub");
        std::fs::create_dir(&other).unwrap();
        let twin = other.join("mytool");
        std::fs::write(&twin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&twin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let r = rules(&[tool.to_str().unwrap()]);
        assert!(r.resolve(tool.to_str().unwrap(), dir.path()).is_ok());
        // By bare name, although it is not on PATH.
        assert_eq!(r.resolve("mytool", dir.path()).unwrap().program(), tool);
        assert!(r.resolve(twin.to_str().unwrap(), dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn star_allows_any_program_that_exists() {
        let r = rules(&["*"]);
        let cwd = std::env::temp_dir();
        assert!(r.allows_everything());
        assert!(r.resolve("sh", &cwd).is_ok());
        assert!(matches!(
            r.resolve("definitely-not-a-real-binary-xyz", &cwd),
            Err(ToolError::ToolNotFound(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_allowed_program_reports_not_found() {
        let r = rules(&["definitely-not-a-real-binary-xyz"]);
        assert!(matches!(
            r.resolve("definitely-not-a-real-binary-xyz", &std::env::temp_dir()),
            Err(ToolError::ToolNotFound(_))
        ));
    }
}
