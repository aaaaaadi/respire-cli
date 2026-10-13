//! Actual client-only commands against a fresh synthetic runtime and local library.
//! No real account, keyring, model download, or remote memory service is used.
use anyhow::Context;
use respire::{MemoryEngine, MemoryEntry, MemoryTransport, SessionKeys, StoredMemory};
use respire::memory::{crypto, search::HashingEmbedder};
use respire::transport::local::LocalStore;
use serde_json::{json, Value};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

struct Fixture {
    home: tempfile::TempDir,
    port: u16,
    secret: String,
    keys: SessionKeys,
    child: Option<Child>,
}

impl Fixture {
    fn new() -> anyhow::Result<Self> {
        let home = tempfile::tempdir()?;
        std::fs::create_dir(home.path().join("data"))?;
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
        let secret = format!("A3-{}", "07".repeat(18));
        let salt = "08".repeat(16);
        let urk = [9; 32];
        let kek = crypto::derive_rsrs_kek(&secret, &salt)?;
        let (nonce, wrapped) = crypto::wrap_key(&urk, &kek)?;
        std::fs::write(home.path().join("data/session.json"), serde_json::to_vec(&json!({
            "user":"synthetic-diary", "pass":"synthetic-unused", "vault_version":4,
            "kdf_salt":salt, "wrapped_urk":format!("{}{wrapped}", crypto::RSRS_PREFIX),
            "urk_nonce":nonce
        }))?)?;
        std::fs::write(home.path().join("data/agent.json"), br#"{"diary_mode":"concise"}"#)?;
        Ok(Self { home, port, secret, keys:SessionKeys::from_urk(urk)?, child:None })
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rsrs"));
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(|name| name.starts_with("RSRS_")
                || name.starts_with("ONEMEMORY_") || name.starts_with("RESPIRE_")) {
                command.env_remove(name);
            }
        }
        command.args(args).current_dir(self.home.path())
            .env("HOME", self.home.path()).env("USERPROFILE", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join("config"))
            .env("XDG_DATA_HOME", self.home.path().join("share"))
            .env("RSRS_DATA_DIR", self.home.path().join("data"))
            .env("RSRS_RPC_PORT", self.port.to_string())
            .env("RSRS_USER", "synthetic-diary").env("RSRS_SUPER", &self.secret)
            .env("RSRS_NO_AUTOSYNC", "1").env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_CORE_TEST_MODE", "1").env("RSRS_RPC_PARALLELISM", "2")
            .env("RSRS_LANG", "en").env("TZ", "UTC")
            // Refuse background model downloads at a loopback-only destination.
            .env("RSRS_MIRROR", "http://127.0.0.1:9")
            .env("RSRS_CPU_ORT_MIRROR", "http://127.0.0.1:9");
        command
    }

    fn start(&mut self) -> anyhow::Result<()> {
        self.child = Some(self.command(&["--runtime-internal"])
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn()?);
        for _ in 0..100 {
            if let Some(status) = self.child.as_mut().context("synthetic runtime child missing")?.try_wait()? {
                anyhow::bail!("synthetic runtime exited: {status}");
            }
            if self.owns_runtime()? { return Ok(()); }
            std::thread::sleep(Duration::from_millis(50));
        }
        anyhow::bail!("synthetic runtime did not become ready")
    }

    fn owns_runtime(&self) -> anyhow::Result<bool> {
        let Some(child) = self.child.as_ref() else { return Ok(false); };
        let Ok(response) = ureq::get(&format!("http://127.0.0.1:{}/api/health", self.port))
            .timeout(Duration::from_millis(100)).call() else { return Ok(false); };
        let health: Value = response.into_json()?;
        anyhow::ensure!(health["pid"].as_u64() == Some(u64::from(child.id()))
            && health["data_dir"].as_str() == self.home.path().join("data").to_str(),
            "fixture port belongs to a different process or profile; no command submitted");
        Ok(true)
    }

    fn run(&self, args: &[&str]) -> anyhow::Result<Value> {
        anyhow::ensure!(self.owns_runtime()?, "synthetic runtime is not ready");
        let mut all = vec!["--client-only", "--json"];
        all.extend_from_slice(args);
        Self::result(self.command(&all).output()?)
    }

    fn result(output: Output) -> anyhow::Result<Value> {
        let value: Value = serde_json::from_slice(&output.stdout)?;
        anyhow::ensure!(output.status.success(), "synthetic command failed: {value}; {}",
            String::from_utf8_lossy(&output.stderr));
        Ok(value)
    }

    fn remember(&self, content: &str) -> anyhow::Result<Value> {
        self.run(&["remember", content, "--importance", "trivial"])
    }

    fn show(&self, id: &str) -> anyhow::Result<Value> {
        Ok(self.run(&["show", id])?["details"]["entry"].clone())
    }

    fn store(&self) -> anyhow::Result<LocalStore> {
        LocalStore::open(&self.home.path().join("data/rsrs.db"))
    }

    fn seed(&self, entry: &MemoryEntry, deleted: bool) -> anyhow::Result<StoredMemory> {
        self.seed_with_owner(entry, deleted, &entry.user)
    }

    fn seed_with_owner(&self, entry: &MemoryEntry, deleted: bool, wire_user: &str) -> anyhow::Result<StoredMemory> {
        let _defer = respire::core_sdk::defer_indexing();
        let mut stored = MemoryEngine::seal(&self.keys, &HashingEmbedder::default(), entry, wire_user)?;
        stored.deleted = deleted;
        anyhow::ensure!(self.store()?.put(&stored)?, "fixture seed was not stored");
        Ok(stored)
    }

    fn stop(&mut self) {
        let owned = self.owns_runtime().unwrap_or(false);
        if let Some(mut child) = self.child.take() {
            if owned {
                let _ = self.command(&["--runtime-internal", "--stop"]).output();
            }
            for _ in 0..100 {
                if child.try_wait().ok().flatten().is_some() { return; }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Drop for Fixture { fn drop(&mut self) { self.stop(); } }

fn day() -> String {
    // Child TZ=UTC applies on Unix; Windows uses the OS local timezone.
    #[cfg(windows)]
    let now = chrono::Local::now();
    #[cfg(not(windows))]
    let now = chrono::Utc::now();
    now.format("%Y-%m-%d").to_string()
}
fn track_id(user: &str, day: &str) -> String {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL,
        format!("activity-track/{user}/{day}").as_bytes()).to_string()
}
fn entry(id: &str, user: &str, title: &str, content: &str) -> MemoryEntry {
    MemoryEntry {
        id:id.into(), user:user.into(), title:title.into(), content:content.into(),
        supersedes:String::new(), superseded_by:String::new(), see_also:Vec::new(),
        kind:respire::Kind::Context, tags:vec!["preserve-tag".into()],
        computer:"fixture-computer".into(), project:"fixture-project".into(),
        created_at:"2026-01-01T00:00:00.000Z".into(),
        updated_at:"2026-01-01T00:00:00.000Z".into(), emotion:0.75,
        parent_id:"fixture-parent".into(), importance:"normal".into(),
        device:"fixture-device".into(), modified_by:"fixture-device".into(),
    }
}

#[test]
fn public_title_edit_and_blank_title_still_append_without_changing_metadata() -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    fixture.start()?;
    let first = fixture.remember("event-original")?;
    let id = first["summary"]["id"].as_str().context("synthetic response string missing")?;
    fixture.run(&["update", id, "--title", "Renamed synthetic diary", "--tags", "keep,edited",
        "--kind", "context", "--importance", "important"])?;
    let before = fixture.show(id)?;
    let appended = fixture.remember("event-after-title-edit")?;
    assert_eq!(appended["summary"]["id"], id);
    assert_eq!(appended["summary"]["title"], "Renamed synthetic diary");
    let after = fixture.show(id)?;
    for (field, value) in before.as_object().context("synthetic entry is not an object")? {
        if !["content", "updated_at", "modified_by"].contains(&field.as_str()) {
            assert_eq!(&after[field], value, "metadata {field} changed");
        }
    }
    let content = after["content"].as_str().context("synthetic response string missing")?;
    assert_eq!(content.matches("event-original").count(), 1);
    assert_eq!(content.matches("event-after-title-edit").count(), 1);
    fixture.run(&["update", id, "--title", ""])?;
    fixture.remember("event-after-blank-title")?;
    let blank = fixture.show(id)?;
    assert_eq!(blank["title"], "");
    assert!(blank["content"].as_str().context("synthetic response string missing")?.contains("event-after-blank-title"));
    Ok(())
}

#[test]
fn canonical_identity_merges_legacy_tracks_without_touching_other_users_or_days() -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    let day = day();
    let title = format!("活动轨迹 {day}");
    let id = track_id("synthetic-diary", &day);
    let canonical = entry(&id, "synthetic-diary", "Renamed canonical", "canonical-event");
    fixture.seed_with_owner(&canonical, false, "server-routing-owner")?;
    fixture.seed_with_owner(&entry("legacy-today", "synthetic-diary", &title, "legacy-event"), false, "server-routing-owner")?;
    let foreign = fixture.seed_with_owner(&entry(&track_id("another-user", &day), "another-user", &title, "foreign-event"), false, "server-routing-owner")?;
    let previous = fixture.seed(&entry(&track_id("synthetic-diary", "2000-01-01"), "synthetic-diary", "活动轨迹 2000-01-01", "previous-day-event"), false)?;
    fixture.start()?;
    let result = fixture.remember("fresh-event")?;
    assert_eq!(result["summary"]["id"], id);
    let saved = fixture.show(&id)?;
    assert_eq!(saved["title"], canonical.title);
    assert_eq!(saved["tags"], json!(canonical.tags));
    assert_eq!(saved["importance"], "normal");
    assert_eq!(saved["emotion"], 0.75);
    assert_eq!(saved["parent_id"], canonical.parent_id);
    assert_eq!(saved["device"], canonical.device);
    for marker in ["canonical-event", "legacy-event", "fresh-event"] {
        assert_eq!(saved["content"].as_str().context("synthetic response string missing")?.matches(marker).count(), 1);
    }
    fixture.stop();
    let rows = fixture.store()?.all(true)?;
    assert_eq!(rows.iter().find(|row| row.id == id).context("canonical row missing")?.user, "server-routing-owner");
    assert!(rows.iter().find(|row| row.id == "legacy-today").context("legacy row missing")?.deleted);
    for original in [foreign, previous] {
        let after = rows.iter().find(|row| row.id == original.id).context("unrelated row missing")?;
        assert_eq!(after.ciphertext, original.ciphertext);
        assert!(!after.deleted);
    }
    Ok(())
}

#[test]
fn deleted_stable_track_uses_legacy_fallback_and_deleted_history_is_not_resurrected() -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    let day = day();
    let id = track_id("synthetic-diary", &day);
    let title = format!("活动轨迹 {day}");
    fixture.seed(&entry(&id, "synthetic-diary", "deleted renamed track", "deleted-event"), true)?;
    fixture.seed(&entry("legacy-live", "synthetic-diary", &title, "legacy-live-event"), false)?;
    fixture.start()?;
    let result = fixture.remember("append-to-legacy")?;
    assert_eq!(result["summary"]["id"], "legacy-live");
    let saved = fixture.show("legacy-live")?;
    assert!(saved["content"].as_str().context("synthetic response string missing")?.contains("legacy-live-event"));
    assert!(!saved["content"].as_str().context("synthetic response string missing")?.contains("deleted-event"));
    fixture.run(&["forget", "legacy-live"])?;
    let recreated = fixture.remember("only-new-event")?;
    assert_eq!(recreated["summary"]["id"], id);
    let saved = fixture.show(&id)?;
    let content = saved["content"].as_str().context("synthetic response string missing")?;
    assert!(content.contains("only-new-event"));
    assert!(!content.contains("deleted-event") && !content.contains("legacy-live-event"));
    Ok(())
}

#[test]
fn concurrent_same_day_client_commands_preserve_each_successful_addition_once() -> anyhow::Result<()> {
    let mut fixture = Fixture::new()?;
    fixture.start()?;
    let mut ids = Vec::new();
    for pair in 0..5 {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut workers = Vec::new();
        for index in 0..2 {
            let marker = format!("pair-{pair}-event-{index}");
            let mut command = fixture.command(&["--client-only", "--json", "remember", &marker, "--importance", "trivial"]);
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                command.output()
            }));
        }
        for worker in workers {
            let value = Fixture::result(worker.join().map_err(|_| anyhow::anyhow!("synthetic client panicked"))??)?;
            ids.push(value["summary"]["id"].as_str().context("synthetic response string missing")?.to_owned());
        }
    }
    assert!(ids.iter().all(|id| id == &ids[0]));
    let saved = fixture.show(&ids[0])?;
    let content = saved["content"].as_str().context("synthetic response string missing")?;
    for pair in 0..5 { for index in 0..2 {
        assert_eq!(content.matches(&format!("pair-{pair}-event-{index}")).count(), 1);
    }}
    Ok(())
}
