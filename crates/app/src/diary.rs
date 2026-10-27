//! Explicit, bounded diary retrieval. Diary matches never enter normal recall.
//! Only derived opaque Core artifacts are persisted; original encrypted records stay intact.
use crate::core_sdk::{self, search::Embedder, Snapshot};
use crate::transport::local::LocalStore;
use crate::{MemoryEngine, MemoryEntry, MemoryQuery, MemoryTransport, SessionKeys, StoredMemory};
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[path = "diary_fragments.rs"]
mod fragments;
const LIMIT_MAX: usize = 20;
const BUDGET_MAX: usize = 12000;
const CACHE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS diary_sources(id TEXT PRIMARY KEY, source TEXT NOT NULL); CREATE TABLE IF NOT EXISTS diary_artifacts(id TEXT PRIMARY KEY, source_id TEXT NOT NULL, generation TEXT NOT NULL, artifact BLOB NOT NULL)";

#[derive(Clone, Serialize)]
pub struct Fragment {
    pub source_kind: &'static str,
    pub evidence_state: &'static str,
    pub source_id: String,
    pub fragment_id: String,
    pub source_version: String,
    pub date: String,
    pub title: String,
    pub project: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
    /// Ranking only, not credibility or factual confidence.
    pub score: f32,
    pub truncated: bool,
    #[serde(skip)]
    anchor: usize,
}

#[derive(Serialize)]
pub struct FragmentResult {
    pub items: Vec<Fragment>,
    pub semantic_ready: bool,
    pub pending_fragments: usize,
    pub truncated: bool,
    pub max_chars: usize,
    pub offset_unit: &'static str,
}

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
fn cache_path() -> std::path::PathBuf {
    crate::service::data_dir().join("diary-fragments-v1.db")
}
fn cache(readonly: bool) -> Result<Option<Connection>> {
    let path = cache_path();
    if readonly && !path.is_file() {
        return Ok(None);
    }
    let db = Connection::open_with_flags(
        path,
        if readonly {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        },
    )?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    if !readonly {
        db.execute_batch(CACHE_SCHEMA)?;
    }
    Ok(Some(db))
}
fn diaries(store: &LocalStore) -> Result<Vec<StoredMemory>> {
    Ok(store
        .all(false)?
        .into_iter()
        .filter(|m| m.local_importance == "trivial")
        .collect())
}
fn version(m: &StoredMemory) -> String {
    digest(&format!("{}:{}", m.nonce, m.ciphertext))
}
fn day(entry: &MemoryEntry) -> String {
    chrono::DateTime::parse_from_rfc3339(&entry.created_at)
        .map(|date| {
            date.with_timezone(&chrono::Local)
                .format("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_else(|_| entry.created_at.chars().take(10).collect())
}
fn split(entry: &MemoryEntry, source_version: &str) -> Vec<Fragment> {
    let chars: Vec<char> = entry.content.chars().collect();
    fragments::ranges(&entry.content)
        .into_iter()
        .map(|(start, end)| {
            let text: String = chars[start..end].iter().collect();
            let key = digest(&format!(
                "{}:{start}:{text}:{}:{}:{:?}:{}:{:?}",
                entry.id, entry.title, entry.project, entry.tags, entry.computer, entry.kind
            ));
            Fragment {
                source_kind: "diary",
                evidence_state: "reference",
                source_id: entry.id.clone(),
                fragment_id: key[..32].to_owned(),
                source_version: source_version.into(),
                date: day(entry),
                title: entry.title.chars().take(80).collect(),
                project: entry.project.chars().take(80).collect(),
                start,
                end,
                text,
                score: 0.0,
                truncated: false,
                anchor: 0,
            }
        })
        .collect()
}
fn indexed_entry(source: &MemoryEntry, fragment: &Fragment) -> MemoryEntry {
    let mut entry = source.clone();
    // A derived locator, never an ID written to the user's memory table.
    entry.id = format!("diary-fragment:{}", fragment.fragment_id);
    entry.content = fragment.text.clone();
    entry.parent_id.clear();
    entry.supersedes.clear();
    entry.superseded_by.clear();
    entry.see_also.clear();
    entry
}

pub fn needs_rebuild(store: &LocalStore) -> Result<bool> {
    let sources = diaries(store)?;
    let Some(db) = cache(true)? else {
        return Ok(!sources.is_empty());
    };
    if db.query_row("SELECT count(*) FROM diary_sources", [], |r| {
        r.get::<_, usize>(0)
    })? != sources.len()
    {
        return Ok(true);
    }
    let generation = core_sdk::generation_key("m3")?;
    let artifacts = {
        let mut stmt = db.prepare("SELECT generation, artifact FROM diary_artifacts")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    if artifacts.iter().any(|(key, _)| key != &generation) {
        return Ok(true);
    }
    if !artifacts.is_empty()
        && !core_sdk::index_ready(&artifacts.into_iter().map(|(_, a)| a).collect::<Vec<_>>())?
    {
        return Ok(true);
    }
    for source in sources {
        let old: Option<String> = db
            .query_row(
                "SELECT source FROM diary_sources WHERE id=?1",
                [&source.id],
                |r| r.get(0),
            )
            .optional()?;
        if old.as_deref() != Some(version(&source).as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Called by the existing account-aware background index worker, with its cancellation/yield callback.
pub fn rebuild<E: Embedder>(
    store: &LocalStore,
    keys: &SessionKeys,
    provider: &E,
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    let sources = diaries(store)?;
    let Some(mut db) = cache(false)? else {
        bail!("diary index unavailable");
    };
    let generation = core_sdk::generation_key(provider.model_name())?;
    let mut live_sources = HashSet::new();
    for source in sources {
        check()?;
        live_sources.insert(source.id.clone());
        let current_version = version(&source);
        let entry = MemoryEngine::open(keys, &source)
            .with_context(|| format!("cannot decode diary {}", source.id))?;
        let cached = {
            let mut stmt = db.prepare(
                "SELECT id, artifact FROM diary_artifacts WHERE source_id=?1 AND generation=?2",
            )?;
            let rows = stmt
                .query_map(params![source.id, generation], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })?
                .collect::<rusqlite::Result<HashMap<_, _>>>()?;
            rows
        };
        let cache_ready = cached.is_empty()
            || core_sdk::index_ready(&cached.values().cloned().collect::<Vec<_>>())?;
        let mut live = HashSet::new();
        for fragment in split(&entry, &current_version) {
            check()?;
            live.insert(fragment.fragment_id.clone());
            if !(cache_ready && cached.contains_key(&fragment.fragment_id)) {
                let prepared = provider.prepare(&indexed_entry(&entry, &fragment))?;
                db.execute("INSERT OR REPLACE INTO diary_artifacts(id,source_id,generation,artifact) VALUES(?1,?2,?3,?4)", params![fragment.fragment_id, source.id, generation, prepared.artifact])?;
            }
        }
        check()?;
        let fresh = store.all(false)?.into_iter().find(|m| m.id == source.id);
        if fresh.as_ref().map(version).as_deref() != Some(current_version.as_str()) {
            bail!("diary source changed while indexing; background index must retry");
        }
        let tx = db.transaction()?;
        let ids = {
            let mut stmt = tx.prepare("SELECT id FROM diary_artifacts WHERE source_id=?1")?;
            let rows = stmt
                .query_map([&source.id], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for id in ids {
            if !live.contains(&id) {
                tx.execute("DELETE FROM diary_artifacts WHERE id=?1", [id])?;
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO diary_sources(id,source) VALUES(?1,?2)",
            params![source.id, current_version],
        )?;
        tx.commit()?;
    }
    check()?;
    let ids = {
        let mut stmt =
            db.prepare("SELECT id FROM diary_sources UNION SELECT source_id FROM diary_artifacts")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for id in ids {
        if !live_sources.contains(&id) {
            let tx = db.transaction()?;
            tx.execute("DELETE FROM diary_artifacts WHERE source_id=?1", [&id])?;
            tx.execute("DELETE FROM diary_sources WHERE id=?1", [&id])?;
            tx.commit()?;
        }
    }
    Ok(())
}

fn budget(
    mut matches: Vec<Fragment>,
    limit: usize,
    max_chars: usize,
    ready: bool,
    pending: usize,
) -> Result<FragmentResult> {
    anyhow::ensure!((1..=LIMIT_MAX).contains(&limit), "limit must be 1..=20");
    anyhow::ensure!(
        (512..=BUDGET_MAX).contains(&max_chars),
        "max-chars must be 512..=12000 (Unicode characters, not tokens)"
    );
    let mut out = FragmentResult {
        items: Vec::new(),
        semantic_ready: ready,
        pending_fragments: pending,
        truncated: matches.len() > limit,
        max_chars,
        offset_unit: "unicode_scalar",
    };
    matches.truncate(limit);
    for mut hit in matches {
        let used = serde_json::to_string(&out)?.chars().count();
        let overhead = {
            let mut empty = hit.clone();
            empty.text.clear();
            serde_json::to_string(&empty)?.chars().count() + 2
        };
        if used + overhead >= max_chars {
            out.truncated = true;
            break;
        }
        let remaining = max_chars - used - overhead;
        if hit.text.chars().count() > remaining {
            let window = hit.anchor.saturating_sub(remaining / 3);
            hit.text = hit.text.chars().skip(window).take(remaining).collect();
            hit.start += window;
            hit.end = hit.start + hit.text.chars().count();
            hit.truncated = true;
            out.truncated = true;
        }
        // JSON escaping can require more space than the raw text.
        out.items.push(hit);
        while serde_json::to_string(&out)?.chars().count() > max_chars {
            let last = out.items.last_mut().unwrap();
            if last.text.pop().is_none() {
                out.items.pop();
                break;
            }
            last.end = last.start + last.text.chars().count();
            last.truncated = true;
            out.truncated = true;
        }
    }
    Ok(out)
}

/// Explicit diary search. Queries never prepare a whole year's embeddings on the foreground path.
pub fn search(
    store: &LocalStore,
    keys: &SessionKeys,
    query: &str,
    limit: usize,
    max_chars: usize,
    hybrid: bool,
) -> Result<FragmentResult> {
    anyhow::ensure!(
        !query.trim().is_empty() && query.chars().count() <= 500,
        "query must contain 1..=500 characters"
    );
    anyhow::ensure!((1..=LIMIT_MAX).contains(&limit), "limit must be 1..=20");
    anyhow::ensure!(
        (512..=BUDGET_MAX).contains(&max_chars),
        "max-chars must be 512..=12000"
    );
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    let db = cache(true)?;
    let mut all = HashMap::new();
    let mut snapshots = Vec::new();
    let mut pending = 0;
    let mut generation = None;
    if hybrid && db.is_some() {
        generation = Some(core_sdk::generation_key("m3")?);
    }
    for source in diaries(store)? {
        let entry = MemoryEngine::open(keys, &source)
            .with_context(|| format!("cannot decode diary {}", source.id))?;
        for mut hit in split(&entry, &version(&source)) {
            let text = format!("{}\n{}\n{}", hit.title, hit.project, hit.text).to_lowercase();
            if terms.iter().all(|term| text.contains(term)) {
                hit.score = 2.0;
                if let Some(byte) = terms
                    .iter()
                    .filter_map(|term| hit.text.to_lowercase().find(term))
                    .min()
                {
                    let mut folded = 0;
                    hit.anchor = hit
                        .text
                        .chars()
                        .take_while(|ch| {
                            let before = folded;
                            folded += ch.to_lowercase().map(char::len_utf8).sum::<usize>();
                            before < byte
                        })
                        .count();
                }
            }
            let indexed = indexed_entry(&entry, &hit);
            if hybrid {
                let artifact = if let (Some(db), Some(generation)) = (&db, &generation) {
                    db.query_row(
                        "SELECT artifact FROM diary_artifacts WHERE id=?1 AND generation=?2",
                        params![hit.fragment_id, generation],
                        |r| r.get::<_, Vec<u8>>(0),
                    )
                    .optional()?
                } else {
                    None
                };
                if let Some(artifact) = artifact.filter(|value| !value.is_empty()) {
                    snapshots.push(Snapshot {
                        id: indexed.id.clone(),
                        deleted: false,
                        updated_at: indexed.updated_at.clone(),
                        kind: source.local_kind.clone(),
                        tags: source.local_tags.clone(),
                        title: indexed.title.clone(),
                        project: indexed.project.clone(),
                        computer: indexed.computer.clone(),
                        parent_id: String::new(),
                        created_at: indexed.created_at.clone(),
                        content_head: indexed.content.clone(),
                        recall_count: 0,
                        importance: indexed.importance.clone(),
                        entry: Some(indexed.clone()),
                        features: Some(core_sdk::Prepared { artifact }),
                    });
                } else {
                    pending += 1;
                }
            }
            all.insert(indexed.id, hit);
        }
    }
    if !snapshots.is_empty()
        && !core_sdk::index_ready(
            &snapshots
                .iter()
                .filter_map(|s| s.features.as_ref().map(|f| f.artifact.clone()))
                .collect::<Vec<_>>(),
        )?
    {
        pending += snapshots.len();
        snapshots.clear();
    }
    let ready = hybrid && pending == 0;
    if hybrid && !snapshots.is_empty() {
        let provider = crate::memory::bge::BgeEmbedder::load_model("m3")?;
        let results: Vec<(f32, MemoryEntry)> = core_sdk::query(
            &provider,
            &snapshots,
            &MemoryQuery::new(query).limit(LIMIT_MAX),
            "scored",
        )?;
        for (score, entry) in results {
            if let Some(hit) = all.get_mut(&entry.id) {
                hit.score += score.clamp(0.0, 1.0);
            }
        }
    }
    let mut hits: Vec<_> = all.into_values().filter(|hit| hit.score > 0.0).collect();
    hits.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| b.date.cmp(&a.date))
            .then_with(|| a.source_id.cmp(&b.source_id))
            .then_with(|| a.start.cmp(&b.start))
    });
    // Overlap windows only contribute one hit unless genuinely disjoint.
    let mut selected: Vec<Fragment> = Vec::new();
    for hit in hits {
        if !selected.iter().any(|other| {
            other.source_id == hit.source_id && hit.start < other.end && other.start < hit.end
        }) {
            selected.push(hit);
        }
    }
    budget(selected, limit, max_chars, ready, pending)
}

pub fn read_fragment(
    store: &LocalStore,
    keys: &SessionKeys,
    source_id: &str,
    fragment_id: &str,
    neighbors: usize,
    max_chars: usize,
) -> Result<FragmentResult> {
    anyhow::ensure!(neighbors <= 1, "neighbors must be 0 or 1");
    let source = diaries(store)?
        .into_iter()
        .find(|m| m.id == source_id)
        .context("diary source not found or no longer active")?;
    let entry = MemoryEngine::open(keys, &source)?;
    let pieces = split(&entry, &version(&source));
    let index = pieces
        .iter()
        .position(|f| f.fragment_id == fragment_id)
        .context("stale or unknown fragment; search again before reading")?;
    // The requested locator owns the budget. Context must never displace it.
    let mut selected = vec![pieces[index].clone()];
    if neighbors == 1 {
        if index > 0 {
            selected.push(pieces[index - 1].clone());
        }
        if index + 1 < pieces.len() {
            selected.push(pieces[index + 1].clone());
        }
    }
    let mut result = budget(selected, 3, max_chars, false, 0)?;
    // Restore source order only after allocating the target's text budget.
    result.items.sort_by_key(|item| item.start);
    Ok(result)
}
