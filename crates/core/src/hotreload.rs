//! Configuration hot reload.
//!
//! Watches the config file (debounced) and reloads the [`ConfigStore`] on
//! change. A bad edit is logged and ignored: the last good configuration
//! stays live.

use std::path::Path;
use std::time::Duration;

use notify::RecursiveMode;
use notify_debouncer_mini::{new_debouncer, DebounceEventResult, Debouncer};

use crate::config::ConfigError;
use crate::store::ConfigStore;

/// Keeps the file watcher alive. Drop to stop watching.
pub struct ReloadHandle {
    _debouncer: Debouncer<notify::RecommendedWatcher>,
}

/// Begin watching the store's backing file.
pub fn watch(store: ConfigStore) -> Result<ReloadHandle, ConfigError> {
    let path = store
        .source_path()
        .ok_or_else(|| ConfigError("the configuration has no file to watch".into()))?
        .to_path_buf();

    let watched = path.clone();
    let mut debouncer = new_debouncer(
        Duration::from_millis(400),
        move |res: DebounceEventResult| match res {
            // The directory is watched, so ignore changes to its other files.
            Ok(events)
                if !events
                    .iter()
                    .any(|e| e.path.file_name() == watched.file_name()) => {}
            Ok(_) => match store.reload() {
                Ok(warnings) => {
                    tracing::info!(path = %watched.display(), "configuration reloaded");
                    for w in warnings {
                        tracing::warn!(warning = %w, "configuration warning");
                    }
                }
                Err(e) => tracing::error!(
                    path = %watched.display(),
                    error = %e,
                    "configuration reload failed; keeping the previous configuration"
                ),
            },
            Err(e) => tracing::warn!(error = ?e, "configuration watch error"),
        },
    )
    .map_err(|e| ConfigError(format!("creating the configuration watcher: {e}")))?;

    // Watch the directory so editors that save by rename are still seen.
    let target = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    debouncer
        .watcher()
        .watch(target, RecursiveMode::NonRecursive)
        .map_err(|e| ConfigError(format!("watching {}: {e}", target.display())))?;
    Ok(ReloadHandle {
        _debouncer: debouncer,
    })
}
