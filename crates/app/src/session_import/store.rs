//! Seal converted entries and import them through the runtime store.
//!
//! Extract is a raw ingester: it does not judge or place memories. Entries land
//! exactly as the converter wrote them (roots unless `--parent` was given), and a
//! later AI-driven tidy attaches them. Mirrors `service::import_json`'s write
//! path (seal each entry with BGE, batch import, one auto-sync) with a per-entry
//! progress callback.

use std::collections::HashMap;

use anyhow::Result;

use crate::memory::model::{MemoryEntry, StoredMemory};
use crate::memory::MemoryEngine;
use crate::service::App;
use crate::transport::MemoryTransport;

/// Entries written per committed chunk, so a long import yields the SQLite write
/// lock periodically instead of holding it for the whole batch.
const IMPORT_CHUNK: usize = 25;

/// Import result: rows written, and per input entry whether it is done (written,
/// or intentionally skipped because the stored row is deleted).
pub struct ImportOutcome {
    pub imported: usize,
    pub completed: Vec<bool>,
}

/// Seal every entry, then import them in committed chunks, then auto-sync once.
///
/// `parent_spec` (id / 8-char prefix / tree or anchor title) is an optional
/// pre-attach: when non-empty it is resolved and applied to entries that have no
/// parent. When empty, entries stay as-is (roots) for a later tidy.
///
/// `progress(done, total)` runs as each entry is sealed (the slow embedding step,
/// performed with no database lock held) and the count is reused for the writes.
/// `on_commit(start, completed)` runs after each chunk commits, so the caller can
/// persist its import cursor between chunks — a failure then resumes from the last
/// committed chunk instead of re-importing from the start.
///
/// Re-import never clobbers user work: a session whose row was deleted is skipped
/// (never resurrected), and an existing row keeps its tidy parent and any edited
/// title. The last-write-wins path also refuses to overwrite a row with unpushed
/// local edits, and that entry is reported as not completed.
pub fn import_entries<F, G>(
    entries: &mut [MemoryEntry],
    parent_spec: &str,
    mut progress: F,
    mut on_commit: G,
) -> Result<ImportOutcome>
where
    F: FnMut(usize, usize),
    G: FnMut(usize, &[bool]) -> Result<()>,
{
    if entries.is_empty() {
        return Ok(ImportOutcome { imported: 0, completed: Vec::new() });
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
    // Phase 1: seal every entry with no database write, so the slow embedding does
    // not hold the SQLite write lock.
    let existing: HashMap<String, StoredMemory> =
        app.store.all(true)?.into_iter().map(|memory| (memory.id.clone(), memory)).collect();
    let total = entries.len();
    let mut completed = vec![false; total];
    let mut sealed: Vec<Option<StoredMemory>> = Vec::with_capacity(total);
    for (index, entry) in entries.iter_mut().enumerate() {
        if let Some(previous) = existing.get(&entry.id) {
            if previous.deleted {
                completed[index] = true;
                sealed.push(None);
                progress(index + 1, total);
                continue;
            }
            if entry.parent_id.is_empty() {
                entry.parent_id = previous.local_parent_id.clone();
            }
            entry.title = previous.local_title.clone();
        }
        let stored = MemoryEngine::seal(&app.keys, &app.embedder, entry, &entry.user)?;
        sealed.push(Some(stored));
        progress(index + 1, total);
    }
    // Phase 2: write in committed chunks, so the write lock is held only briefly
    // per chunk and other writers can interleave between chunks.
    let mut imported = 0usize;
    let mut start = 0usize;
    while start < total {
        let end = (start + IMPORT_CHUNK).min(total);
        let flags = app.store.write_transaction(|| {
            let mut flags = vec![false; end - start];
            for (offset, plan) in sealed[start..end].iter().enumerate() {
                if let Some(stored) = plan {
                    flags[offset] = app.store.put(stored)?;
                }
            }
            Ok(flags)
        })?;
        for (offset, wrote) in flags.iter().enumerate() {
            if *wrote {
                completed[start + offset] = true;
                imported += 1;
            }
        }
        if let Err(error) = on_commit(start, &completed[start..end]) {
            // Committed chunks above still need a sync notification even if the
            // caller's cursor write failed; mirrors the success path's auto_sync.
            app.auto_sync();
            return Err(error);
        }
        start = end;
    }
    app.auto_sync();
    Ok(ImportOutcome { imported, completed })
}
