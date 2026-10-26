//! One host lifecycle owner. A durable maintenance marker fences queued/direct
//! requests until the replacement store has been verified; failure stays paused.
use super::{
    control_path, disabled_status, hash, identity, manager, private_write, read_registration,
    AutostartCommand, Platform, Registration, RuntimeCommand, ENVIRONMENT,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};
use std::time::{Duration, Instant};

static MANAGED_ID: OnceLock<String> = OnceLock::new();
thread_local! { static ACTIVE: RefCell<Option<String>> = const { RefCell::new(None) }; }

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum Phase {
    Paused,
    Starting,
    Verified,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: u32,
    id: String,
    token: String,
    phase: Phase,
    expected_profile: Option<PathBuf>,
    expected_version: String,
}

fn marker_path(root: &Path) -> PathBuf {
    control_path(root).with_file_name("maintenance.json")
}
fn marker(root: &Path) -> Result<Option<Marker>> {
    let path = marker_path(root);
    let meta = match fs::symlink_metadata(&path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    anyhow::ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 4096,
        "invalid runtime maintenance marker"
    );
    let value: Marker = serde_json::from_slice(&fs::read(path)?)?;
    anyhow::ensure!(
        value.schema == 1 && uuid::Uuid::parse_str(&value.token).is_ok(),
        "invalid runtime maintenance marker"
    );
    Ok(Some(value))
}

fn save(config: &mut Registration) -> Result<()> {
    let path = control_path(&config.installation);
    let bytes = serde_json::to_vec_pretty(config)?;
    let result = private_write(&path, &bytes, config.digest.as_deref());
    // Namespace fsync can fail after publication. Preserve the observed identity
    // while propagating that error; the separate maintenance marker stays put.
    if fs::read(&path).is_ok_and(|actual| actual == bytes) {
        config.digest = Some(hash(&bytes));
    }
    result
}

fn owned(config: &Registration) -> Result<()> {
    anyhow::ensure!(
        config.owner == manager::owner()?,
        "runtime registration belongs to another OS user"
    );
    let bin = config
        .environment
        .get("RSRS_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| config.installation.join("bin"));
    let expected = bin.join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" });
    anyhow::ensure!(
        config.executable == expected,
        "runtime registration has an unexpected executable"
    );
    Ok(())
}

pub(crate) fn managed_id() -> Option<&'static str> {
    MANAGED_ID.get().map(String::as_str)
}
pub(crate) fn current_boot_token() -> Option<String> {
    ACTIVE.with(|v| v.borrow().clone())
}

pub(crate) fn check_direct_access() -> Result<()> {
    let root = respire::service::main_data_dir();
    if let Some(value) = marker(&root)? {
        anyhow::ensure!(ACTIVE.with(|v|v.borrow().as_deref()==Some(value.token.as_str())),
            "runtime maintenance is incomplete; use the host runtime restart or the indicated snapshot/login recovery before accessing the library");
    }
    Ok(())
}

pub(crate) fn check_managed_request() -> Result<()> {
    if crate::rpc::worker_active() {
        check_direct_access()?;
    }
    Ok(())
}

pub(crate) fn verify_managed_boot() -> Result<()> {
    let root = respire::service::main_data_dir();
    let config = read_registration(&root)?;
    if let Some(id) = managed_id() {
        let config = config
            .as_ref()
            .context("managed runtime registration disappeared")?;
        anyhow::ensure!(
            config.id == id && config.enabled && !config.manually_stopped,
            "managed runtime startup is disabled or manually stopped"
        );
    }
    if let Some(value) = marker(&root)? {
        let token = std::env::var("RSRS_RUNTIME_BOOT_TOKEN").ok();
        let permitted = managed_id() == Some(value.id.as_str())
            || token.as_deref() == Some(value.token.as_str());
        anyhow::ensure!(
            permitted && matches!(value.phase, Phase::Starting | Phase::Verified),
            "runtime maintenance has not authorized a replacement process"
        );
        anyhow::ensure!(
            value.expected_version == env!("CARGO_PKG_VERSION")
                && value.expected_profile.as_deref()
                    == Some(respire::service::data_dir().canonicalize()?.as_path()),
            "replacement runtime version/profile differs from maintenance plan"
        );
    }
    Ok(())
}

pub(crate) struct Maintenance {
    config: Option<Registration>,
    marker: Option<Marker>,
    marker_digest: Option<String>,
    completed: bool,
}

impl Maintenance {
    fn inactive() -> Self {
        Self {
            config: None,
            marker: None,
            marker_digest: None,
            completed: true,
        }
    }

    fn begin(mut config: Registration, recover: bool) -> Result<Self> {
        owned(&config)?;
        let registration = manager::inspect(&config)?;
        anyhow::ensure!(
            !registration.registered || config.artifact_hashes.contains_key("service"),
            "unknown existing startup registration; no lifecycle action taken"
        );
        let previous = marker(&config.installation)?;
        anyhow::ensure!(
            previous.is_none() || recover,
            "interrupted runtime maintenance; use runtime restart on the host"
        );
        let previous_digest = if previous.is_some() {
            Some(hash(&fs::read(marker_path(&config.installation))?))
        } else {
            None
        };
        let value = Marker {
            schema: 1,
            id: config.id.clone(),
            token: uuid::Uuid::new_v4().to_string(),
            phase: Phase::Paused,
            expected_profile: None,
            expected_version: env!("CARGO_PKG_VERSION").into(),
        };
        if let Some(previous) = previous {
            anyhow::ensure!(
                previous.id == config.id,
                "maintenance belongs to another runtime registration"
            );
        }
        let bytes = serde_json::to_vec(&value)?;
        private_write(
            &marker_path(&config.installation),
            &bytes,
            previous_digest.as_deref(),
        )?;
        config.maintenance = true;
        save(&mut config)?;
        ACTIVE.with(|slot| *slot.borrow_mut() = Some(value.token.clone()));
        Ok(Self {
            config: Some(config),
            marker: Some(value),
            marker_digest: Some(hash(&bytes)),
            completed: false,
        })
    }

    fn mark(&mut self, phase: Phase) -> Result<()> {
        let Some(config) = self.config.as_ref() else {
            return Ok(());
        };
        let actual = fs::read(marker_path(&config.installation))?;
        let current: Marker = serde_json::from_slice(&actual)?;
        let value = self
            .marker
            .as_mut()
            .context("maintenance marker unavailable")?;
        anyhow::ensure!(
            current.id == value.id && current.token == value.token,
            "maintenance owner changed before phase transition"
        );
        value.phase = phase;
        if matches!(phase, Phase::Starting | Phase::Verified) {
            value.expected_profile = Some(respire::service::data_dir().canonicalize()?);
        }
        let bytes = serde_json::to_vec(value)?;
        private_write(
            &marker_path(&config.installation),
            &bytes,
            Some(&hash(&actual)),
        )?;
        self.marker_digest = Some(hash(&bytes));
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        if self.completed {
            return Ok(());
        }
        self.mark(Phase::Verified)?;
        let config = self
            .config
            .as_mut()
            .context("maintenance registration unavailable")?;
        config.maintenance = false;
        save(config)?;
        let path = marker_path(&config.installation);
        anyhow::ensure!(
            hash(&fs::read(&path)?)
                == self
                    .marker_digest
                    .as_deref()
                    .context("maintenance digest missing")?,
            "maintenance changed before completion"
        );
        fs::remove_file(&path)?;
        // Already verified, so a namespace-cleanup warning must never trigger a
        // later profile rollback after requests have been accepted.
        if respire_spawn::durable::sync_directory(
            path.parent().context("maintenance parent missing")?,
        )
        .is_err()
        {
            eprintln!("Runtime verified; maintenance namespace cleanup needs a later check.");
        }
        self.completed = true;
        ACTIVE.with(|slot| *slot.borrow_mut() = None);
        Ok(())
    }
}

impl Drop for Maintenance {
    fn drop(&mut self) {
        if self.config.is_some() {
            ACTIVE.with(|slot| *slot.borrow_mut() = None);
        }
    }
}

pub(crate) fn begin_maintenance_locked() -> Result<Maintenance> {
    if ACTIVE.with(|v| v.borrow().is_some()) {
        return Ok(Maintenance::inactive());
    }
    match read_registration(&respire::service::main_data_dir())? {
        Some(config) if config.enabled => Maintenance::begin(config, false),
        _ => Ok(Maintenance::inactive()),
    }
}

fn raw_stop_owned(config: &Registration) -> Result<()> {
    manager::inspect(config)?;
    if let Some(health) = crate::rpc::probe_runtime()? {
        anyhow::ensure!(
            crate::mcp::exe_matches_dest(&health.exe, &config.executable)
                && health.data_dir == respire::service::data_dir().display().to_string(),
            "runtime identity/profile does not match this installation; no lifecycle action taken"
        );
        crate::rpc::stop_occupant(health.pid)?;
    }
    manager::stop(config)
}

fn wait_ready(config: &Registration) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if let Some(health) = crate::rpc::probe_runtime()? {
            anyhow::ensure!(
                health.bin == env!("CARGO_PKG_VERSION")
                    && crate::mcp::exe_matches_dest(&health.exe, &config.executable)
                    && health.data_dir == respire::service::data_dir().display().to_string(),
                "managed runtime version/executable/profile mismatch"
            );
            if health.store_ready || respire::service::off_mode() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("owned runtime did not confirm store readiness; maintenance remains paused")
}

fn start_candidate(guard: &mut Maintenance) -> Result<()> {
    let config = guard
        .config
        .as_ref()
        .context("managed registration missing")?;
    raw_stop_owned(config)?;
    anyhow::ensure!(
        config.executable == crate::mcp::stable_bin_path(),
        "service executable differs from host configuration; explicitly reconfigure startup first"
    );
    let executable = crate::mcp::materialize_bin().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        executable == config.executable,
        "managed native path changed unexpectedly"
    );
    let current = manager::inspect(config)?;
    anyhow::ensure!(current.registered,"startup registration is missing; upgrade never registers it automatically; run runtime autostart enable explicitly");
    guard.mark(Phase::Starting)?;
    manager::start(
        guard
            .config
            .as_ref()
            .context("managed registration missing")?,
    )?;
    wait_ready(
        guard
            .config
            .as_ref()
            .context("managed registration missing")?,
    )
}

pub(crate) fn ensure_managed_locked() -> Result<bool> {
    let Some(config) = read_registration(&respire::service::main_data_dir())? else {
        return Ok(false);
    };
    if !config.enabled {
        return Ok(false);
    }
    owned(&config)?;
    anyhow::ensure!(
        !config.manually_stopped,
        "runtime was manually stopped; use runtime start explicitly"
    );
    if ACTIVE.with(|v| v.borrow().is_some()) {
        let value = marker(&config.installation)?.context("active maintenance marker missing")?;
        let digest = hash(&fs::read(marker_path(&config.installation))?);
        let mut borrowed = Maintenance {
            config: Some(config),
            marker: Some(value),
            marker_digest: Some(digest),
            completed: true,
        };
        let result = start_candidate(&mut borrowed);
        // This borrowed guard does not own completion or its caller's token.
        borrowed.config = None;
        result?;
        return Ok(true);
    }
    if let Some(health) = crate::rpc::probe_runtime()? {
        if crate::rpc::runtime_matches_current(&health)? {
            return Ok(true);
        }
    }
    let mut guard = Maintenance::begin(config, false)?;
    start_candidate(&mut guard)?;
    guard.finish()?;
    Ok(true)
}

pub(crate) fn stop_managed_locked() -> Result<bool> {
    let Some(mut config) = read_registration(&respire::service::main_data_dir())? else {
        return Ok(false);
    };
    if !config.enabled {
        return Ok(false);
    }
    owned(&config)?;
    manager::inspect(&config)?;
    config.manually_stopped = true;
    save(&mut config)?;
    let mut guard = Maintenance::begin(config, false)?;
    raw_stop_owned(
        guard
            .config
            .as_ref()
            .context("managed registration missing")?,
    )?;
    guard.finish()?;
    Ok(true)
}

fn new_registration() -> Result<Registration> {
    let root = respire::service::main_data_dir();
    fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    let owner = manager::owner()?;
    let executable = crate::mcp::stable_bin_path();
    let home = dirs::home_dir()
        .context("current-user home unavailable")?
        .canonicalize()?;
    let mut environment = BTreeMap::new();
    for &key in ENVIRONMENT {
        if let Ok(value) = respire::env::var(key) {
            super::plain_value(&value)?;
            environment.insert(key.into(), value);
        }
    }
    environment.insert(
        "RSRS_DATA_DIR".into(),
        root.to_str().context("non-UTF8 installation")?.into(),
    );
    environment.insert(
        "RSRS_BIN_DIR".into(),
        executable
            .parent()
            .context("native executable parent missing")?
            .to_str()
            .context("non-UTF8 native directory")?
            .into(),
    );
    environment.insert(
        "RSRS_RPC_PORT".into(),
        crate::net_rpc::rpc_port().to_string(),
    );
    Ok(Registration {
        schema: 1,
        platform: Platform::current()?,
        id: identity(&root, &owner),
        installation: root,
        executable,
        user_home: home,
        owner,
        enabled: false,
        manually_stopped: false,
        maintenance: false,
        environment,
        artifact_hashes: BTreeMap::new(),
        digest: None,
    })
}

fn status() -> Result<Value> {
    let mut value = disabled_status()?;
    let root = respire::service::main_data_dir();
    if let Some(config) = read_registration(&root)? {
        owned(&config)?;
        value["registration"] = serde_json::to_value(manager::inspect(&config)?)?;
        value["maintenance"] = json!(marker(&root)?.is_some());
    }
    match crate::rpc::probe_runtime() {
        Ok(Some(health)) => {
            value["runtime"] = json!({"running":true,"pid":health.pid,"version":health.bin,"data_dir":health.data_dir,"store_ready":health.store_ready,"inference":health.inference,"credential_state":"unknown"});
        }
        Ok(None) => value["runtime"] = json!({"running":false}),
        Err(_) => value["runtime"] = json!({"running":null,"state":"unreachable_or_unverified"}),
    }
    Ok(value)
}

fn emit(command: &str, summary: Value) -> Result<()> {
    crate::emit_result(crate::output::ResultEnvelope::new(
        command,
        crate::OutputStatus::Ok,
        summary,
        Vec::new(),
    ))
}

pub(crate) fn execute(command: &RuntimeCommand) -> Result<()> {
    if matches!(
        command,
        RuntimeCommand::Status
            | RuntimeCommand::Autostart {
                command: AutostartCommand::Status
            }
    ) {
        return emit("runtime.autostart.status", status()?);
    }
    crate::runtime_policy::require_host("runtime lifecycle")?;
    anyhow::ensure!(
        !crate::rpc::worker_active(),
        "runtime lifecycle commands require the host CLI, not a runtime request"
    );
    match command {
        RuntimeCommand::Run {
            managed,
            installation_root,
        } => run_foreground(managed.as_deref(), installation_root.as_deref()),
        RuntimeCommand::Stop => {
            crate::rpc::stop_if_running()?;
            emit("runtime.stop", json!({"state":"stopped"}))
        }
        RuntimeCommand::Restart => {
            let value = crate::rpc::restart_runtime(Duration::from_secs(10))?;
            emit("runtime.restart", value)
        }
        RuntimeCommand::Start => {
            let _ownership = crate::runtime_policy::takeover_lock()?;
            if let Some(mut config) = read_registration(&respire::service::main_data_dir())? {
                owned(&config)?;
                config.manually_stopped = false;
                save(&mut config)?;
            }
            crate::rpc::ensure_daemon_locked()?;
            emit("runtime.start", status()?)
        }
        RuntimeCommand::Autostart {
            command: AutostartCommand::Enable { now },
        } => enable(*now),
        RuntimeCommand::Autostart {
            command: AutostartCommand::Disable { stop },
        } => disable(*stop, false),
        RuntimeCommand::Autostart {
            command: AutostartCommand::Remove { stop },
        } => disable(*stop, true),
        _ => bail!("unsupported runtime lifecycle command"),
    }
}

fn enable(now: bool) -> Result<()> {
    let _ownership = crate::runtime_policy::takeover_lock()?;
    let mut config = match read_registration(&respire::service::main_data_dir())? {
        Some(config) => config,
        None => new_registration()?,
    };
    owned(&config)?;
    manager::inspect(&config)?;
    config.manually_stopped = false;
    let was_running = crate::rpc::probe_runtime()?.is_some();
    let mut guard = Maintenance::begin(config, false)?;
    let install = (|| -> Result<()> {
        raw_stop_owned(guard.config.as_ref().context("registration missing")?)?;
        crate::mcp::materialize_bin().map_err(anyhow::Error::msg)?;
        let config = guard.config.as_mut().context("registration missing")?;
        manager::install(config)?;
        config.enabled = true;
        save(config)?;
        if now || was_running {
            start_candidate(&mut guard)?;
        }
        Ok(())
    })();
    if let Err(error) = install {
        if let Some(config) = guard.config.as_mut() {
            config.enabled = false;
            if let Err(save_error) = save(config) {
                return Err(error.context(format!("startup remains paused: {save_error}")));
            }
        }
        return Err(error.context("startup registration did not complete; runtime maintenance remains paused for explicit host recovery"));
    }
    guard.finish()?;
    emit("runtime.autostart.enable", status()?)
}

fn disable(stop: bool, remove: bool) -> Result<()> {
    let _ownership = crate::runtime_policy::takeover_lock()?;
    let Some(mut config) = read_registration(&respire::service::main_data_dir())? else {
        return emit("runtime.autostart.disable", status()?);
    };
    owned(&config)?;
    manager::inspect(&config)?;
    if stop {
        config.manually_stopped = true;
        save(&mut config)?;
        let mut guard = Maintenance::begin(config, false)?;
        raw_stop_owned(guard.config.as_ref().context("registration missing")?)?;
        guard.finish()?;
        config = read_registration(&respire::service::main_data_dir())?
            .context("registration disappeared")?;
    }
    config.enabled = false;
    save(&mut config)?;
    manager::disable(&config)?;
    if remove {
        manager::remove(&config)?;
        config.artifact_hashes.clear();
        save(&mut config)?;
    }
    emit(
        if remove {
            "runtime.autostart.remove"
        } else {
            "runtime.autostart.disable"
        },
        status()?,
    )
}

fn run_foreground(id: Option<&str>, root: Option<&Path>) -> Result<()> {
    if let Some(id) = id {
        let root = root.context("managed runtime needs its explicit installation root")?;
        let config = read_registration(root)?.context("managed runtime registration missing")?;
        owned(&config)?;
        anyhow::ensure!(config.id == id, "managed runtime identity mismatch");
        if !config.enabled || config.manually_stopped {
            return Ok(());
        }
        anyhow::ensure!(
            crate::mcp::same_path(&std::env::current_exe()?, &config.executable),
            "managed startup must use the configured stable native executable"
        );
        for (key, value) in &config.environment {
            std::env::set_var(key, value);
        }
        std::env::set_var("HOME", &config.user_home);
        std::env::set_var("USERPROFILE", &config.user_home);
        MANAGED_ID
            .set(id.to_owned())
            .map_err(|_| anyhow::anyhow!("managed runtime already initialized"))?;
    } else {
        anyhow::ensure!(
            root.is_none(),
            "installation-root is only accepted for a managed registration"
        );
        anyhow::ensure!(!read_registration(&respire::service::main_data_dir())?.is_some_and(|config|config.enabled),"the service manager owns this runtime; use runtime start instead of an unmanaged foreground instance");
        check_direct_access()?;
    }
    verify_managed_boot()?;
    #[cfg(unix)]
    {
        let stopped = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?;
        std::thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = crate::net_rpc::request_stop_with_timeout(Duration::from_secs(5));
        });
    }
    crate::rpc::runtime_entry(crate::rpc::RuntimeFlags {
        port: Some(crate::net_rpc::rpc_port()),
        host: "127.0.0.1".into(),
        status: false,
        stop: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_configuration_refuses_unknown_files_links_and_unplanned_changes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().canonicalize()?.join("registration.json");
        private_write(&path, b"initial", None)?;
        anyhow::ensure!(private_write(&path, b"overwrite", None).is_err());
        anyhow::ensure!(private_write(&path, b"overwrite", Some(&hash(b"wrong"))).is_err());
        private_write(&path, b"updated", Some(&hash(b"initial")))?;
        anyhow::ensure!(fs::read(&path)? == b"updated");
        #[cfg(unix)]
        {
            let link = directory.path().canonicalize()?.join("link");
            std::os::unix::fs::symlink(&path, &link)?;
            anyhow::ensure!(private_write(&link, b"bad", Some(&hash(b"updated"))).is_err());
        }
        Ok(())
    }
}
