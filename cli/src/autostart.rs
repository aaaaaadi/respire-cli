//! Opt-in, current-user runtime supervision. No registration during ordinary startup.
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

mod lifecycle;
mod manager;
pub(crate) use lifecycle::current_boot_token as lifecycle_boot_token;
pub(crate) use lifecycle::{
    authorize_detached_boot_locked, background_paused, begin_maintenance_locked,
    check_direct_access, check_managed_request, coordinate_materialization, ensure_managed_locked,
    execute, managed_id, restart_maintenance_locked, stop_managed_locked, verify_managed_boot,
    with_explicit_recovery,
};

#[derive(Debug, Subcommand)]
pub enum RuntimeCommand {
    /// Serve in the foreground; service managers supervise this process.
    Run {
        #[arg(long, hide = true)]
        managed: Option<String>,
        #[arg(long, hide = true)]
        installation_root: Option<PathBuf>,
    },
    /// Start the host through its configured lifecycle owner.
    Start,
    /// Stop the owned host without automatic resurrection.
    Stop,
    /// Drain and restart the owned host through its configured lifecycle owner.
    Restart,
    /// Inspect the existing host without creating a profile or starting it.
    Status,
    /// Manage opt-in current-user sign-in startup; never installs a system service.
    Autostart {
        #[command(subcommand)]
        command: AutostartCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AutostartCommand {
    /// Register current-user sign-in startup; start now only with --now.
    Enable {
        #[arg(long)]
        now: bool,
    },
    /// Disable future sign-in startup; stop the existing host only with --stop.
    Disable {
        #[arg(long)]
        stop: bool,
    },
    /// Remove only this installation's startup registration; preserve data and keys.
    Remove {
        #[arg(long)]
        stop: bool,
    },
    /// Read registration and runtime status without changing either.
    Status,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Platform {
    Linux,
    Macos,
    Windows,
}

impl Platform {
    fn current() -> Result<Self> {
        match std::env::consts::OS {
            "linux" => Ok(Self::Linux),
            "macos" => Ok(Self::Macos),
            "windows" => Ok(Self::Windows),
            _ => bail!("user runtime autostart is unsupported on this platform"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Linux => "systemd-user",
            Self::Macos => "launch-agent",
            Self::Windows => "user-logon-task",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    schema: u32,
    platform: Platform,
    installation: PathBuf,
    executable: PathBuf,
    user_home: PathBuf,
    owner: String,
    id: String,
    enabled: bool,
    manually_stopped: bool,
    maintenance: bool,
    environment: BTreeMap<String, String>,
    artifact_hashes: BTreeMap<String, String>,
    #[serde(skip)]
    digest: Option<String>,
}

fn control_path(root: &Path) -> PathBuf {
    root.join("runtime")
        .join("autostart")
        .join("registration.json")
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn identity(root: &Path, owner: &str) -> String {
    hash(format!("respire-runtime-v1\0{}\0{owner}", root.display()).as_bytes())[..24].to_owned()
}

fn plain_value(value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty() && !value.chars().any(char::is_control),
        "invalid autostart configuration value"
    );
    Ok(())
}

fn read_registration(root: &Path) -> Result<Option<Registration>> {
    let path = control_path(root);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 64 * 1024,
        "autostart registration must be a bounded regular file"
    );
    let bytes = fs::read(&path)?;
    let mut config: Registration =
        serde_json::from_slice(&bytes).context("invalid autostart registration")?;
    anyhow::ensure!(
        config.schema == 1 && config.platform == Platform::current()?,
        "unsupported autostart registration schema/platform"
    );
    let canonical = root.canonicalize()?;
    anyhow::ensure!(
        config.installation == canonical && config.id == identity(&canonical, &config.owner),
        "autostart registration belongs to another installation"
    );
    for (key, value) in &config.environment {
        anyhow::ensure!(
            ENVIRONMENT.contains(&key.as_str()),
            "autostart registration contains unsupported environment configuration"
        );
        plain_value(value)?;
    }
    config.digest = Some(hash(&bytes));
    Ok(Some(config))
}

fn private_write(path: &Path, bytes: &[u8], expected: Option<&str>) -> Result<()> {
    let parent = path.parent().context("autostart file has no parent")?;
    // Refuse links in the path rather than writing through an unexpected target.
    for ancestor in parent.ancestors() {
        if let Ok(metadata) = fs::symlink_metadata(ancestor) {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "autostart parent is a symlink; no files changed"
            );
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 65536,
                "unknown autostart file; refusing replacement"
            );
            let expected =
                expected.context("existing autostart file is not owned by this installation")?;
            anyhow::ensure!(
                hash(&fs::read(path)?) == expected,
                "autostart file changed; refusing replacement"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::ensure!(
                expected.is_none(),
                "owned autostart file disappeared; inspect registration before retrying"
            );
        }
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".respire-autostart-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if expected.is_some() {
            respire_spawn::durable::replace_file(&temporary, path)?;
        } else {
            respire_spawn::durable::publish_new_file(&temporary, path)?;
        }
        Ok(())
    })();
    if result.is_err() && temporary.try_exists()? {
        fs::remove_file(&temporary)?;
    }
    result
}

// Never persist authentication/recovery material or arbitrary shell environment.
const ENVIRONMENT: &[&str] = &[
    "RSRS_DATA_DIR",
    "RSRS_BIN_DIR",
    "RSRS_RPC_PORT",
    "RSRS_ENGINE",
    "RSRS_M3_DIR",
    "RSRS_INDEX_THREADS",
    "RSRS_RECALL_FEEDBACK",
    "RSRS_MCP_TOOLS_ALLOW",
    "RSRS_MCP_TOOLS_DENY",
];

fn disabled_status() -> Result<Value> {
    let root = respire::service::main_data_dir();
    match read_registration(&root)? {
        None => Ok(
            json!({"schema_version":1,"enabled":false,"registered":false,
            "scope":"user-sign-in","default_enabled":false,"manager":Platform::current()?.name()}),
        ),
        Some(config) => Ok(
            json!({"schema_version":1,"enabled":config.enabled,"registered":true,
            "scope":"user-sign-in","default_enabled":false,"manager":config.platform.name(),
            "installation":config.installation,"id":config.id,"manually_stopped":config.manually_stopped,
            "maintenance":config.maintenance}),
        ),
    }
}

fn systemd_quote(raw: &str) -> Result<String> {
    plain_value(raw)?;
    Ok(format!(
        "\"{}\"",
        raw.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}

// Path-valued systemd directives are not ExecStart argv. Escape whitespace as
// C-style bytes, without introducing literal quote characters into the path.
fn systemd_path(raw: &str) -> Result<String> {
    plain_value(raw)?;
    anyhow::ensure!(
        raw.starts_with('/'),
        "systemd working directory must be absolute"
    );
    Ok(raw
        .replace('\\', "\\\\")
        .replace('%', "%%")
        .replace(' ', "\\x20")
        .replace('"', "\\x22"))
}

fn xml(raw: &str) -> Result<String> {
    plain_value(raw)?;
    Ok(raw
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

fn render(config: &Registration) -> Result<String> {
    let executable = config
        .executable
        .to_str()
        .context("native path is not UTF-8")?;
    let root = config
        .installation
        .to_str()
        .context("installation path is not UTF-8")?;
    match config.platform {
        Platform::Linux => Ok(format!("# Respire user runtime {}\n[Unit]\nDescription=Respire current-user runtime\nStartLimitIntervalSec=120\nStartLimitBurst=3\n[Service]\nType=simple\nExecStart={} runtime run --managed {} --installation-root {}\nWorkingDirectory={}\nRestart=on-failure\nRestartSec=10\nTimeoutStopSec=60\nKillMode=control-group\nStandardOutput=null\nStandardError=null\n[Install]\nWantedBy=default.target\n",
            config.id, systemd_quote(executable)?, config.id, systemd_quote(root)?, systemd_path(root)?)),
        Platform::Macos => Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>ai.risense.respire.runtime.{}</string><key>ProgramArguments</key><array><string>{}</string><string>runtime</string><string>run</string><string>--managed</string><string>{}</string><string>--installation-root</string><string>{}</string></array><key>WorkingDirectory</key><string>{}</string><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>ThrottleInterval</key><integer>10</integer><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string></dict></plist>\n",
            config.id, xml(executable)?, config.id, xml(root)?, xml(root)?)),
        Platform::Windows => {
            let arguments=format!("runtime run --managed {} --installation-root {}",manager::windows_argument(&config.id)?,manager::windows_argument(root)?);
            Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><RegistrationInfo><Description>Respire current-user runtime {}</Description></RegistrationInfo><Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{}</UserId></LogonTrigger></Triggers><Principals><Principal id=\"CurrentUser\"><UserId>{}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled><StartWhenAvailable>true</StartWhenAvailable><RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings><Actions Context=\"CurrentUser\"><Exec><Command>{}</Command><Arguments>{}</Arguments><WorkingDirectory>{}</WorkingDirectory></Exec></Actions></Task>\n",config.id,xml(&config.owner)?,xml(&config.owner)?,xml(executable)?,xml(&arguments)?,xml(root)?))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn fixture(platform: Platform) -> Registration {
        Registration {
            schema: 1,
            platform,
            installation: PathBuf::from("/tmp/a & b"),
            executable: PathBuf::from("/tmp/a & b/bin/rsrs"),
            user_home: PathBuf::from("/tmp/user"),
            owner: "1001".into(),
            id: "0123456789abcdef01234567".into(),
            enabled: false,
            manually_stopped: false,
            maintenance: false,
            environment: BTreeMap::new(),
            artifact_hashes: BTreeMap::new(),
            digest: None,
        }
    }

    #[test]
    fn absent_registration_is_a_read_only_default() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let missing = temporary.path().join("not-created");
        anyhow::ensure!(
            read_registration(&missing)?.is_none(),
            "fresh profile was unexpectedly configured"
        );
        anyhow::ensure!(!missing.exists(), "status created a profile");
        Ok(())
    }

    #[test]
    fn templates_supervise_foreground_user_runtime_without_elevation() -> Result<()> {
        let linux = render(&fixture(Platform::Linux))?;
        anyhow::ensure!(
            linux.contains("Type=simple")
                && linux.contains("runtime run")
                && !linux.contains("status --json")
        );
        anyhow::ensure!(!linux.contains("User=root") && !linux.contains("linger"));
        let mac = render(&fixture(Platform::Macos))?;
        anyhow::ensure!(
            mac.contains("a &amp; b")
                && mac.contains("SuccessfulExit")
                && !mac.contains("LaunchDaemon")
        );
        anyhow::ensure!(systemd_quote("/a%u/$x")? == "\"/a%%u/$$x\"");
        anyhow::ensure!(plain_value("bad\nvalue").is_err());
        for secret in [
            "RSRS_SUPER",
            "RSRS_TOKEN",
            "RSRS_RPC_TOKEN",
            "GH_TOKEN",
            "CORE_SDK_READ_TOKEN",
        ] {
            anyhow::ensure!(!ENVIRONMENT.contains(&secret));
        }
        Ok(())
    }
}
