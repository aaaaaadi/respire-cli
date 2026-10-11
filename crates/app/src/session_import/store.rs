//! Seal converted entries and import them through the runtime store.
//!
//! Extract is a raw ingester: it does not judge or place memories. Entries land
//! exactly as the converter wrote them (roots unless `--parent` was given), and a
//! later AI-driven tidy attaches them. Mirrors `service::import_json`'s write
//! path (seal each entry with BGE, batch import, one auto-sync) with a per-entry
//! progress callback.

use anyhow::Result;

use crate::memory::model::MemoryEntry;
use crate::memory::MemoryEngine;
use crate::service::App;
use crate::transport::MemoryTransport;

/// Seal each entry and import it (duplicates skipped), then auto-sync once.
///
/// `parent_spec` (id / 8-char prefix / tree or anchor title) is an optional
/// pre-attach: when non-empty it is resolved and applied to entries that have no
/// parent. When empty, entries stay as-is (roots) for a later tidy.
/// `progress(done, total)` runs after each entry is sealed. Returns the number
/// actually written; a stable session id that already exists is skipped rather
/// than failing the whole import.
pub fn import_entries<F: FnMut(usize, usize)>(
    entries: &mut [MemoryEntry],
    parent_spec: &str,
    mut progress: F,
) -> Result<usize> {
    if entries.is_empty() {
        return Ok(0);
    }
    let app = App::open()?;
    let spec = parent_spec.trim();
    if !spec.is_empty() {
        let all = app.store.all(false)?;
        let parent = crate::service::resolve_prefix(&all, spec)?;
        for entry in entries.iter_mut() {
            if entry.parent_id.is_empty() {
                entry.parent_id = parent.clone();
            }
        }
    }
    let total = entries.len();
    let mut imported = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let sealed = MemoryEngine::seal(&app.keys, &app.embedder, entry, &entry.user)?;
        if app.store.put(&sealed)? {
            imported += 1;
        }
        progress(index + 1, total);
    }
    app.auto_sync();
    Ok(imported)
}
