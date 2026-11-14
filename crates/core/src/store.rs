//! The live configuration.
//!
//! A [`ConfigStore`] holds the current [`Loaded`] snapshot: the parsed config
//! and the policies compiled from it. Readers take a cheap `Arc`; a reload
//! swaps the snapshot atomically, so a call resolves everything it needs from
//! one consistent configuration. A reload that fails to parse, validate or
//! compile leaves the previous snapshot in place.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::config::{Catalog, Config, ConfigError};
use crate::policy::PolicySet;

/// One consistent configuration: the document and its compiled policies.
#[derive(Debug)]
pub struct Loaded {
    /// The configuration document, after overlays.
    pub config: Arc<Config>,
    /// Policies compiled from it.
    pub policies: PolicySet,
    /// Incremented on every successful reload.
    pub generation: u64,
}

/// Adjusts a freshly loaded config (command-line and environment overrides)
/// so they survive reloads.
pub type Overlay = Arc<dyn Fn(&mut Config) + Send + Sync>;

struct Inner {
    current: RwLock<Arc<Loaded>>,
    source: Option<PathBuf>,
    overlay: Option<Overlay>,
    catalog: Option<Catalog>,
    generation: AtomicU64,
    changed: tokio::sync::watch::Sender<u64>,
}

/// Holder of the active configuration.
#[derive(Clone)]
pub struct ConfigStore {
    inner: Arc<Inner>,
}

impl ConfigStore {
    /// Load the configuration from `source` (or use the defaults), apply
    /// `overlay`, validate against `catalog` and compile the policies.
    /// Returns the store and warnings for the operator.
    pub fn load(
        source: Option<&Path>,
        overlay: Option<Overlay>,
        catalog: Catalog,
    ) -> Result<(Self, Vec<String>), ConfigError> {
        let (loaded, warnings) =
            build(source, overlay.as_ref(), Some(&catalog), 0)?;
        let (changed, _) = tokio::sync::watch::channel(0);
        Ok((
            Self {
                inner: Arc::new(Inner {
                    current: RwLock::new(Arc::new(loaded)),
                    source: source.map(Path::to_path_buf),
                    overlay,
                    catalog: Some(catalog),
                    generation: AtomicU64::new(0),
                    changed,
                }),
            },
            warnings,
        ))
    }

    /// A store over an in-memory config with no name validation. For tests
    /// and embedding.
    pub fn from_config(config: Config) -> Result<Self, ConfigError> {
        let policies = PolicySet::compile(&config, &protected_paths(&config, None))?;
        let (changed, _) = tokio::sync::watch::channel(0);
        Ok(Self {
            inner: Arc::new(Inner {
                current: RwLock::new(Arc::new(Loaded {
                    config: Arc::new(config),
                    policies,
                    generation: 0,
                })),
                source: None,
                overlay: None,
                catalog: None,
                generation: AtomicU64::new(0),
                changed,
            }),
        })
    }

    /// The current snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Loaded> {
        self.inner.current.read().clone()
    }

    /// The file this store was loaded from, if any.
    #[must_use]
    pub fn source_path(&self) -> Option<&Path> {
        self.inner.source.as_deref()
    }

    /// Replace the configuration with an in-memory document (tests).
    pub fn replace(&self, config: Config) -> Result<(), ConfigError> {
        let policies = PolicySet::compile(
            &config,
            &protected_paths(&config, self.inner.source.as_deref()),
        )?;
        let generation = self.inner.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.inner.current.write() = Arc::new(Loaded {
            config: Arc::new(config),
            policies,
            generation,
        });
        let _ = self.inner.changed.send(generation);
        Ok(())
    }

    /// Re-read the source file. On any error the active configuration is
    /// unchanged. Returns warnings for the operator.
    pub fn reload(&self) -> Result<Vec<String>, ConfigError> {
        let Some(source) = self.inner.source.as_deref() else {
            return Err(ConfigError(
                "this configuration was not loaded from a file".to_string(),
            ));
        };
        let generation = self.inner.generation.load(Ordering::SeqCst) + 1;
        let (loaded, warnings) = build(
            Some(source),
            self.inner.overlay.as_ref(),
            self.inner.catalog.as_ref(),
            generation,
        )?;
        self.inner.generation.store(generation, Ordering::SeqCst);
        *self.inner.current.write() = Arc::new(loaded);
        let _ = self.inner.changed.send(generation);
        Ok(warnings)
    }

    /// A receiver that observes the generation number after each change.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.changed.subscribe()
    }
}

fn build(
    source: Option<&Path>,
    overlay: Option<&Overlay>,
    catalog: Option<&Catalog>,
    generation: u64,
) -> Result<(Loaded, Vec<String>), ConfigError> {
    let mut config = match source {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };
    if let Some(overlay) = overlay {
        overlay(&mut config);
    }
    let mut warnings = match catalog {
        Some(catalog) => config.validate(catalog)?,
        None => Vec::new(),
    };
    let policies = PolicySet::compile(&config, &protected_paths(&config, source))?;
    warnings.extend(policies.warnings().iter().cloned());
    Ok((
        Loaded {
            config: Arc::new(config),
            policies,
            generation,
        },
        warnings,
    ))
}

/// Files and directories that belong to the server and that no tool may
/// read or write: they hold credentials or decide the policy itself.
fn protected_paths(config: &Config, source: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(source) = source {
        paths.push(absolute(source));
    }
    if let Some(dir) = &config.logging.directory {
        paths.push(absolute(dir));
    }
    if let Some(state) = &config.transport.http.oauth.state_file {
        paths.push(absolute(state));
    }
    paths
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{simplify, Access};

    fn catalog() -> Catalog {
        Catalog {
            categories: vec!["fs".into()],
            tools: vec!["fs_read".into()],
        }
    }

    #[test]
    fn a_bad_reload_keeps_the_last_good_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, "[server]\nname = \"one\"\ncategories = [\"fs\"]\n").unwrap();
        let (store, _) = ConfigStore::load(Some(&path), None, catalog()).unwrap();
        assert_eq!(store.snapshot().config.server.name, "one");

        std::fs::write(&path, "[server]\nnmae = \"typo\"\n").unwrap();
        assert!(store.reload().is_err());
        std::fs::write(&path, "[server]\ncategories = [\"nope\"]\n").unwrap();
        assert!(store.reload().is_err());
        assert_eq!(store.snapshot().config.server.name, "one");
        assert_eq!(store.snapshot().generation, 0);

        std::fs::write(&path, "[server]\nname = \"two\"\n").unwrap();
        store.reload().unwrap();
        assert_eq!(store.snapshot().config.server.name, "two");
        assert_eq!(store.snapshot().generation, 1);
    }

    #[test]
    fn overlays_survive_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, "").unwrap();
        let overlay: Overlay = Arc::new(|c| c.transport.http.enabled = true);
        let (store, _) = ConfigStore::load(Some(&path), Some(overlay), catalog()).unwrap();
        assert!(store.snapshot().config.transport.http.enabled);
        std::fs::write(&path, "[server]\nname = \"x\"\n").unwrap();
        store.reload().unwrap();
        assert!(store.snapshot().config.transport.http.enabled);
    }

    #[test]
    fn the_config_file_is_protected_from_tools() {
        let dir = tempfile::tempdir().unwrap();
        let root = simplify(&std::fs::canonicalize(dir.path()).unwrap());
        let path = root.join("nebula.toml");
        std::fs::write(
            &path,
            format!("[security]\nallowed_paths = [\"{}\"]\n", root.display())
                .replace('\\', "/"),
        )
        .unwrap();
        let (store, _) = ConfigStore::load(Some(&path), None, catalog()).unwrap();
        let policy = store.snapshot().policies.for_tool("fs_read");
        assert!(policy.paths().denied(&path, Access::Read).is_some());
        assert!(policy.paths().denied(&path, Access::Write).is_some());
        assert!(policy.paths().denied(&root.join("other.txt"), Access::Write).is_none());
    }

    #[test]
    fn subscribers_see_changes() {
        let store = ConfigStore::from_config(Config::default()).unwrap();
        let rx = store.subscribe();
        store.replace(Config::default()).unwrap();
        assert_eq!(*rx.borrow(), 1);
    }
}
