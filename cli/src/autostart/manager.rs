//! Current-user OS adapters. The only accepted registrations have our exact owner,
//! installation-specific name, executable and arguments; never use elevation.
use super::{hash, plain_value, private_write, render, Platform, Registration};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug, Serialize)]
pub(super) struct State {
    pub registered: bool,
    pub loaded: bool,
    pub running: bool,
    pub enabled: bool,
}

struct Output {
    code: i32,
    stdout: String,
}

/// Creation identity only: never persist a controller command line, which may
/// contain login material. None means that the controller has exited.
pub(super) fn process_birth(pid: u32) -> Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        let raw = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let fields = raw.rsplit_once(')').context("invalid process identity")?.1;
        if fields.split_whitespace().next() == Some("Z") {
            return Ok(None);
        }
        return Ok(Some(
            fields
                .split_whitespace()
                .nth(19)
                .context("process birth missing")?
                .into(),
        ));
    }
    #[cfg(windows)]
    {
        let raw = powershell(format!("$p=Get-CimInstance Win32_Process -Filter 'ProcessId={pid}';if($null -ne $p){{$p.CreationDate.ToUniversalTime().Ticks.ToString()}}"))?;
        return Ok((!raw.trim().is_empty()).then(|| raw.trim().to_owned()));
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = control(
            "ps",
            &["-p".into(), pid.to_string(), "-o".into(), "lstart=".into()],
        )?;
        if output.code == 1 && output.stdout.trim().is_empty() {
            return Ok(None);
        }
        anyhow::ensure!(
            output.code == 0 && !output.stdout.trim().is_empty(),
            "process identity unavailable"
        );
        Ok(Some(output.stdout.trim().into()))
    }
}

fn program(name: &str) -> Result<PathBuf> {
    if name == "powershell" {
        let root = std::env::var_os("SystemRoot").context("Windows SystemRoot unavailable")?;
        let path = PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
        anyhow::ensure!(path.is_file(), "Windows PowerShell unavailable");
        return Ok(path);
    }
    for base in ["/usr/bin", "/bin"] {
        let path = Path::new(base).join(name);
        if path.is_file() {
            return Ok(path);
        }
    }
    bail!("current-user service manager program unavailable: {name}")
}

#[cfg(test)]
type TestControl = Box<dyn FnMut(&str, &[String]) -> Result<Output>>;
#[cfg(test)]
thread_local! { static TEST_CONTROL: std::cell::RefCell<Option<TestControl>> = const { std::cell::RefCell::new(None) }; }

fn control(name: &str, arguments: &[String]) -> Result<Output> {
    #[cfg(test)]
    if let Some(output) = TEST_CONTROL.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(|handler| handler(name, arguments))
    }) {
        return output;
    }
    let mut command = Command::new(program(name)?);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear();
    for key in [
        "HOME",
        "USERPROFILE",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.env(
        "PATH",
        if cfg!(windows) {
            std::env::var_os("SystemRoot")
                .map(|root| PathBuf::from(root).join("System32"))
                .unwrap_or_default()
        } else {
            PathBuf::from("/usr/bin:/bin")
        },
    );
    let mut child = command
        .spawn()
        .context("could not invoke current-user service manager")?;
    let stdout = child
        .stdout
        .take()
        .context("service manager stdout missing")?;
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut data = Vec::new();
        let result = stdout.take(65537).read_to_end(&mut data).map(|_| data);
        let _ = tx.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child
                .kill()
                .context("could not stop timed-out service manager client")?;
            child.wait()?;
            bail!(
                "current-user service manager request timed out; inspect its state before retrying"
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let bytes = rx
        .recv_timeout(Duration::from_secs(1))
        .context("service manager output did not close")??;
    anyhow::ensure!(
        bytes.len() <= 65536,
        "service manager response exceeded limit"
    );
    Ok(Output {
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8(bytes).context("service manager returned invalid UTF-8")?,
    })
}

fn checked(name: &str, args: Vec<String>) -> Result<String> {
    let result = control(name, &args)?;
    anyhow::ensure!(
        result.code == 0,
        "{name} current-user operation failed (exit {}); inspect the owned registration",
        result.code
    );
    Ok(result.stdout)
}

fn ps_literal(value: &str) -> Result<String> {
    plain_value(value)?;
    Ok(format!("'{}'", value.replace('\'', "''")))
}

fn powershell(script: String) -> Result<String> {
    checked("powershell",vec!["-NoLogo".into(),"-NoProfile".into(),"-NonInteractive".into(),"-Command".into(),format!("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);{script}")])
}

pub(super) fn owner() -> Result<String> {
    let value = if cfg!(windows) {
        powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value".into())?
    } else {
        checked("id", vec!["-u".into()])?
    };
    let value = value.trim();
    anyhow::ensure!(
        !value.is_empty()
            && if cfg!(windows) {
                value.starts_with("S-")
                    && value
                        .chars()
                        .all(|c| c == 'S' || c == '-' || c.is_ascii_digit())
            } else {
                value.chars().all(|c| c.is_ascii_digit())
            },
        "could not identify current-user service owner"
    );
    Ok(value.to_owned())
}

pub(super) fn item(config: &Registration) -> PathBuf {
    match config.platform {
        Platform::Linux => config
            .user_home
            .join(".config/systemd/user")
            .join(format!("respire-runtime-{}.service", config.id)),
        Platform::Macos => config
            .user_home
            .join("Library/LaunchAgents")
            .join(format!("ai.risense.respire.runtime.{}.plist", config.id)),
        Platform::Windows => super::control_path(&config.installation).with_file_name("task.xml"),
    }
}

fn name(config: &Registration) -> String {
    match config.platform {
        Platform::Linux => format!("respire-runtime-{}.service", config.id),
        Platform::Macos => format!("ai.risense.respire.runtime.{}", config.id),
        Platform::Windows => format!("Respire-runtime-{}", config.id),
    }
}

fn domain(config: &Registration) -> String {
    format!("gui/{}", config.owner)
}

fn systemd_property(
    config: &Registration,
    interface: &str,
    property: &str,
) -> Result<serde_json::Value> {
    let lookup = checked(
        "busctl",
        vec![
            "--user".into(),
            "--json=short".into(),
            "call".into(),
            "org.freedesktop.systemd1".into(),
            "/org/freedesktop/systemd1".into(),
            "org.freedesktop.systemd1.Manager".into(),
            "GetUnit".into(),
            "s".into(),
            name(config),
        ],
    )?;
    let object: serde_json::Value = serde_json::from_str(&lookup)?;
    let path = object["data"][0]
        .as_str()
        .context("systemd unit object unavailable")?;
    anyhow::ensure!(
        path.starts_with("/org/freedesktop/systemd1/unit/"),
        "unexpected systemd unit object"
    );
    let value = checked(
        "busctl",
        vec![
            "--user".into(),
            "--json=short".into(),
            "get-property".into(),
            "org.freedesktop.systemd1".into(),
            path.into(),
            interface.into(),
            property.into(),
        ],
    )?;
    Ok(serde_json::from_str(&value)?)
}

fn verify_systemd_loaded(
    config: &Registration,
    exec: &serde_json::Value,
    dropins: &serde_json::Value,
) -> Result<()> {
    let overrides = dropins["data"]
        .as_array()
        .context("systemd loaded drop-in list unavailable")?;
    anyhow::ensure!(
        overrides.is_empty(),
        "unknown systemd drop-in override; refusing lifecycle action"
    );
    let entries = exec["data"]
        .as_array()
        .context("systemd loaded ExecStart unavailable")?;
    anyhow::ensure!(entries.len() == 1, "unknown systemd loaded ExecStart count");
    let row = entries[0]
        .as_array()
        .context("invalid systemd loaded ExecStart")?;
    let executable = config.executable.to_str().context("non-UTF8 executable")?;
    anyhow::ensure!(
        row.first().and_then(serde_json::Value::as_str) == Some(executable),
        "systemd loaded executable changed; refusing lifecycle action"
    );
    let argv = row
        .get(1)
        .and_then(serde_json::Value::as_array)
        .context("systemd loaded argv unavailable")?;
    let expected = [
        executable,
        "runtime",
        "run",
        "--managed",
        &config.id,
        "--installation-root",
        config
            .installation
            .to_str()
            .context("non-UTF8 installation")?,
    ];
    anyhow::ensure!(
        argv.len() == expected.len()
            && argv
                .iter()
                .zip(expected)
                .all(|(actual, expected)| actual.as_str() == Some(expected)),
        "systemd loaded arguments changed; refusing lifecycle action"
    );
    Ok(())
}
fn launchd_enabled(disabled: &str, name: &str) -> Result<bool> {
    anyhow::ensure!(
        disabled.contains("disabled services = {") && disabled.trim_end().ends_with('}'),
        "launchd disabled override status unavailable"
    );
    let key = format!("\"{name}\" => ");
    let mut matched = disabled
        .lines()
        .filter_map(|line| line.trim().strip_prefix(&key));
    let enabled = match matched.next() {
        None => true,
        Some("true") => false,
        Some("false") => true,
        Some(_) => bail!("unknown launchd disabled override value"),
    };
    anyhow::ensure!(matched.next().is_none(), "duplicate launchd override entry");
    Ok(enabled)
}

fn label(config: &Registration) -> String {
    format!("{}/{}", domain(config), name(config))
}

fn file_guard(config: &Registration) -> Result<()> {
    anyhow::ensure!(
        config.owner == owner()?,
        "autostart belongs to another OS user"
    );
    let path = item(config);
    if let Some(expected) = config.artifact_hashes.get("service") {
        let metadata = std::fs::symlink_metadata(&path)?;
        anyhow::ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 65536,
            "autostart service file is not a bounded regular file"
        );
        anyhow::ensure!(
            hash(&std::fs::read(&path)?) == *expected,
            "autostart service file changed; refusing overwrite or removal"
        );
    } else {
        anyhow::ensure!(
            !path.try_exists()?,
            "unknown autostart service file; refusing replacement"
        );
    }
    Ok(())
}

// Windows argv quoting follows CommandLineToArgvW, including trailing slashes.
pub(super) fn windows_argument(value: &str) -> Result<String> {
    plain_value(value)?;
    let mut result = String::from("\"");
    let mut slashes = 0;
    for c in value.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        result.push_str(&"\\".repeat(if c == '"' { slashes * 2 + 1 } else { slashes }));
        result.push(c);
        slashes = 0;
    }
    result.push_str(&"\\".repeat(slashes * 2));
    result.push('"');
    Ok(result)
}

fn arguments(config: &Registration) -> Result<String> {
    Ok(format!(
        "runtime run --managed {} --installation-root {}",
        windows_argument(&config.id)?,
        windows_argument(
            config
                .installation
                .to_str()
                .context("non-UTF8 installation")?
        )?
    ))
}

fn task_guard(config: &Registration) -> Result<String> {
    let task = ps_literal(&name(config))?;
    let owner = ps_literal(&config.owner)?;
    let exe = ps_literal(config.executable.to_str().context("non-UTF8 executable")?)?;
    let root = ps_literal(
        config
            .installation
            .to_str()
            .context("non-UTF8 installation")?,
    )?;
    let args = ps_literal(&arguments(config)?)?;
    Ok(format!(
        r#"
function Sid($value){{try{{if($value -match '^S-\d-'){{return ([Security.Principal.SecurityIdentifier]::new($value)).Value}};return ([Security.Principal.NTAccount]::new($value)).Translate([Security.Principal.SecurityIdentifier]).Value}}catch{{return $null}}}}
$t=Get-ScheduledTask -TaskName {task} -TaskPath '\' -ErrorAction SilentlyContinue;
if($null -ne $t){{
 $a=@($t.Actions);$g=@($t.Triggers);
 if((Sid $t.Principal.UserId) -cne {owner} -or $t.Principal.LogonType -ne 'Interactive' -or $t.Principal.RunLevel -ne 'Limited' -or $a.Count -ne 1 -or $g.Count -ne 1 -or $g[0].CimClass.CimClassName -ne 'MSFT_TaskLogonTrigger' -or (Sid $g[0].UserId) -cne {owner}){{throw 'Unknown task principal/trigger; refusing lifecycle action'}};
 if(-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($a[0].Execute),[IO.Path]::GetFullPath({exe})) -or $a[0].Arguments -cne {args} -or -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($a[0].WorkingDirectory),[IO.Path]::GetFullPath({root}))){{throw 'Unknown task action; refusing lifecycle action'}};
 if($t.Description -cne {description}){{throw 'Unknown task marker; refusing lifecycle action'}};
}}
"#,
        description = ps_literal(&format!("Respire current-user runtime {}", config.id))?
    ))
}

pub(super) fn inspect(config: &Registration) -> Result<State> {
    file_guard(config)?;
    match config.platform {
        Platform::Linux => {
            let output = control(
                "systemctl",
                &[
                    "--user".into(),
                    "show".into(),
                    name(config),
                    "--no-pager".into(),
                    "--property=LoadState,ActiveState,MainPID,FragmentPath,UnitFileState".into(),
                ],
            )?;
            anyhow::ensure!(
                output.code == 0 || output.code == 4,
                "systemd user session unavailable; no system/linger fallback is performed"
            );
            let fields: std::collections::BTreeMap<_, _> = output
                .stdout
                .lines()
                .filter_map(|line| line.split_once('='))
                .collect();
            let registered = fields.get("LoadState").is_some_and(|v| *v != "not-found");
            if registered {
                let fragment = fields
                    .get("FragmentPath")
                    .context("systemd unit path missing")?;
                anyhow::ensure!(
                    Path::new(fragment) == item(config),
                    "unknown systemd user unit path; refusing lifecycle action"
                );
                verify_systemd_loaded(
                    config,
                    &systemd_property(config, "org.freedesktop.systemd1.Service", "ExecStart")?,
                    &systemd_property(config, "org.freedesktop.systemd1.Unit", "DropInPaths")?,
                )?;
            }
            Ok(State {
                registered,
                loaded: registered,
                running: fields.get("ActiveState") == Some(&"active"),
                enabled: fields
                    .get("UnitFileState")
                    .is_some_and(|v| matches!(*v, "enabled" | "enabled-runtime")),
            })
        }
        Platform::Macos => {
            let disabled = checked("launchctl", vec!["print-disabled".into(), domain(config)])?;
            let enabled = launchd_enabled(&disabled, &name(config))?;
            let output = control("launchctl", &["print".into(), label(config)])?;
            if output.code != 0 {
                checked("launchctl", vec!["print".into(), domain(config)])?;
                anyhow::ensure!(
                    [3, 113].contains(&output.code),
                    "LaunchAgent query failed; refusing lifecycle action"
                );
                return Ok(State {
                    registered: item(config).is_file(),
                    loaded: false,
                    running: false,
                    enabled,
                });
            }
            let property = |key: &str| {
                output
                    .stdout
                    .lines()
                    .find_map(|line| line.trim().strip_prefix(&format!("{key} = ")))
                    .map(|v| v.trim_matches('"'))
            };
            anyhow::ensure!(
                property("path").is_some_and(|v| Path::new(v) == item(config)),
                "unknown loaded LaunchAgent path; refusing lifecycle action"
            );
            anyhow::ensure!(
                property("program").is_some_and(|v| Path::new(v) == config.executable),
                "unknown loaded LaunchAgent program; refusing lifecycle action"
            );
            let args = output
                .stdout
                .split("arguments = {\n")
                .nth(1)
                .and_then(|s| s.split("\n\t}").next())
                .context("loaded LaunchAgent arguments unavailable")?;
            let actual: Vec<_> = args.lines().map(|v| v.trim().trim_matches('"')).collect();
            let expected = [
                config.executable.to_str().context("non-UTF8 executable")?,
                "runtime",
                "run",
                "--managed",
                &config.id,
                "--installation-root",
                config
                    .installation
                    .to_str()
                    .context("non-UTF8 installation")?,
            ];
            anyhow::ensure!(
                actual == expected,
                "loaded LaunchAgent arguments changed; refusing lifecycle action"
            );
            Ok(State {
                registered: true,
                loaded: true,
                running: property("state") == Some("running"),
                enabled,
            })
        }
        Platform::Windows => {
            let text=powershell(format!("{};[pscustomobject]@{{registered=($null -ne $t);loaded=($null -ne $t);running=($null -ne $t -and $t.State -eq 'Running');enabled=($null -ne $t -and $t.Settings.Enabled)}}|ConvertTo-Json -Compress",task_guard(config)?))?;
            let v: serde_json::Value =
                serde_json::from_str(text.trim_start_matches('\u{feff}').trim())?;
            let boolean = |key| v[key].as_bool().context("invalid scheduled task status");
            Ok(State {
                registered: boolean("registered")?,
                loaded: boolean("loaded")?,
                running: boolean("running")?,
                enabled: boolean("enabled")?,
            })
        }
    }
}

pub(super) fn install(config: &mut Registration) -> Result<()> {
    let before = inspect(config)?;
    anyhow::ensure!(
        !before.registered || config.artifact_hashes.contains_key("service"),
        "unknown existing registration; refusing replacement"
    );
    let content = render(config)?;
    private_write(
        &item(config),
        content.as_bytes(),
        config.artifact_hashes.get("service").map(String::as_str),
    )?;
    config
        .artifact_hashes
        .insert("service".into(), hash(content.as_bytes()));
    match config.platform {
        Platform::Linux => {
            checked(
                "systemctl",
                vec![
                    "--user".into(),
                    "link".into(),
                    item(config).to_string_lossy().into_owned(),
                ],
            )?;
            checked("systemctl", vec!["--user".into(), "daemon-reload".into()])?;
            checked(
                "systemctl",
                vec!["--user".into(), "enable".into(), name(config)],
            )?;
        }
        Platform::Macos => {
            checked("launchctl", vec!["enable".into(), label(config)])?;
        }
        Platform::Windows => {
            powershell(format!("{};$xml=[IO.File]::ReadAllText({});Register-ScheduledTask -TaskName {} -TaskPath '\' -Xml $xml {}|Out-Null",task_guard(config)?,ps_literal(item(config).to_str().context("non-UTF8 task path")?)?,ps_literal(&name(config))?,if before.registered{"-Force"}else{""}))?;
        }
    }
    Ok(())
}

pub(super) fn reset_backoff(config: &Registration) -> Result<()> {
    let state = inspect(config)?;
    if state.registered && config.platform == Platform::Linux {
        checked(
            "systemctl",
            vec!["--user".into(), "reset-failed".into(), name(config)],
        )?;
    }
    Ok(())
}

pub(super) fn start(config: &Registration) -> Result<()> {
    let current = inspect(config)?;
    anyhow::ensure!(
        current.registered,
        "owned autostart registration is missing"
    );
    match config.platform {
        Platform::Linux => {
            checked(
                "systemctl",
                vec!["--user".into(), "start".into(), name(config)],
            )?;
        }
        Platform::Macos => {
            if !current.loaded {
                checked(
                    "launchctl",
                    vec![
                        "bootstrap".into(),
                        domain(config),
                        item(config).to_string_lossy().into_owned(),
                    ],
                )?;
            } else if !current.running {
                checked("launchctl", vec!["kickstart".into(), label(config)])?;
            }
        }
        Platform::Windows => {
            powershell(format!(
                "{};Start-ScheduledTask -TaskName {} -TaskPath '\'",
                task_guard(config)?,
                ps_literal(&name(config))?
            ))?;
        }
    }
    Ok(())
}

pub(super) fn stop(config: &Registration) -> Result<()> {
    let current = inspect(config)?;
    match config.platform {
        Platform::Linux => {
            if current.registered {
                checked(
                    "systemctl",
                    vec!["--user".into(), "stop".into(), name(config)],
                )?;
            }
        }
        Platform::Macos => {
            if current.loaded {
                checked("launchctl", vec!["bootout".into(), label(config)])?;
            }
        }
        Platform::Windows => {
            if current.running {
                powershell(format!(
                    "{};Stop-ScheduledTask -TaskName {} -TaskPath '\'",
                    task_guard(config)?,
                    ps_literal(&name(config))?
                ))?;
            }
        }
    }
    Ok(())
}

pub(super) fn disable(config: &Registration) -> Result<()> {
    let current = inspect(config)?;
    match config.platform {
        Platform::Linux => {
            if current.registered {
                checked(
                    "systemctl",
                    vec!["--user".into(), "disable".into(), name(config)],
                )?;
            }
        }
        Platform::Macos => {
            checked("launchctl", vec!["disable".into(), label(config)])?;
        }
        Platform::Windows => {
            if current.registered {
                powershell(format!(
                    "{};Disable-ScheduledTask -TaskName {} -TaskPath '\'|Out-Null",
                    task_guard(config)?,
                    ps_literal(&name(config))?
                ))?;
            }
        }
    }
    Ok(())
}

pub(super) fn remove(config: &Registration) -> Result<()> {
    let current = inspect(config)?;
    anyhow::ensure!(
        !current.running,
        "stop the owned runtime before removing its startup registration"
    );
    match config.platform {
        Platform::Linux => {
            disable(config)?;
        }
        Platform::Macos => {
            if current.loaded {
                stop(config)?;
            }
            disable(config)?;
        }
        Platform::Windows => {
            if current.registered {
                powershell(format!(
                    "{};Unregister-ScheduledTask -TaskName {} -TaskPath '\' -Confirm:$false",
                    task_guard(config)?,
                    ps_literal(&name(config))?
                ))?;
            }
        }
    }
    file_guard(config)?;
    if item(config).is_file() {
        std::fs::remove_file(item(config))?;
    }
    if config.platform == Platform::Linux {
        checked("systemctl", vec!["--user".into(), "daemon-reload".into()])?;
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(super) mod test_adapter {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    #[derive(Default)]
    pub struct Fake {
        pub registered: bool,
        pub enabled: bool,
        pub running: bool,
        pub dropin: bool,
        pub fail: Option<String>,
        pub changes: Vec<String>,
    }
    pub struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            TEST_CONTROL.with(|slot| *slot.borrow_mut() = None);
        }
    }
    pub fn install(config: &Registration) -> (Scope, Rc<RefCell<Fake>>) {
        let state = Rc::new(RefCell::new(Fake::default()));
        let shared = state.clone();
        let config = config.clone();
        TEST_CONTROL.with(|slot| *slot.borrow_mut() = Some(Box::new(move |name,args| {
            let mut state = shared.borrow_mut();
            let ok = |stdout:String| Ok(Output{code:0,stdout});
            match name {
                "id" => ok(config.owner.clone()),
                "systemctl" => {
                    anyhow::ensure!(args.first().map(String::as_str) == Some("--user"), "fake refuses non-user operation");
                    let operation = args.get(1).context("manager operation missing")?;
                    if state.fail.as_ref() == Some(operation) { return Ok(Output{code:1,stdout:String::new()}); }
                    if operation == "show" { return ok(format!("LoadState={}\nActiveState={}\nMainPID=0\nFragmentPath={}\nUnitFileState={}\n", if state.registered {"loaded"}else{"not-found"},if state.running {"active"}else{"inactive"},item(&config).display(),if state.enabled {"enabled"}else{"disabled"})); }
                    state.changes.push(operation.clone());
                    match operation.as_str() {
                        "link" => state.registered = true,
                        "enable" => state.enabled = true,
                        "disable" => state.enabled = false,
                        "start" => state.running = true,
                        "stop" => state.running = false,
                        "daemon-reload" => {if !item(&config).exists() {state.registered=false;}},
                        "reset-failed" => {},
                        _ => bail!("unexpected fake operation"),
                    }
                    ok(String::new())
                },
                "busctl" => {
                    if args.iter().any(|v|v == "GetUnit") { return ok(serde_json::json!({"data":["/org/freedesktop/systemd1/unit/test"]}).to_string()); }
                    match args.last().map(String::as_str) {
                        Some("DropInPaths") => ok(serde_json::json!({"data":if state.dropin {vec!["/tmp/unknown.conf"]}else{vec![]}}).to_string()),
                        Some("ExecStart") => ok(serde_json::json!({"data":[[config.executable,[config.executable,"runtime","run","--managed",config.id,"--installation-root",config.installation],false,0,0,0,0,0,0,0]]}).to_string()),
                        _ => bail!("unexpected fake property"),
                    }
                },
                _ => bail!("unexpected fake program"),
            }
        })));
        (Scope, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loaded_systemd_configuration_must_match_disk_identity_without_overrides() -> Result<()> {
        let config = super::super::tests::fixture(Platform::Linux);
        let row = serde_json::json!([
            config.executable,
            [
                config.executable,
                "runtime",
                "run",
                "--managed",
                config.id,
                "--installation-root",
                config.installation
            ],
            false,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        ]);
        let exec = serde_json::json!({"data":[row]});
        let clean = serde_json::json!({"data":[]});
        verify_systemd_loaded(&config, &exec, &clean)?;
        anyhow::ensure!(verify_systemd_loaded(
            &config,
            &exec,
            &serde_json::json!({"data":["/tmp/foreign.conf"]})
        )
        .is_err());
        let mut changed = exec.clone();
        changed["data"][0][0] = serde_json::json!("/tmp/foreign");
        anyhow::ensure!(verify_systemd_loaded(&config, &changed, &clean).is_err());
        changed = exec.clone();
        changed["data"][0][1][4] = serde_json::json!("another-installation");
        anyhow::ensure!(verify_systemd_loaded(&config, &changed, &clean).is_err());
        anyhow::ensure!(
            verify_systemd_loaded(&config, &serde_json::json!({"data":[]}), &clean).is_err()
        );
        Ok(())
    }
    #[test]
    fn launchd_status_uses_actual_disabled_override() -> Result<()> {
        anyhow::ensure!(launchd_enabled(
            "disabled services = {\n}",
            "ai.risense.test"
        )?);
        anyhow::ensure!(!launchd_enabled(
            "disabled services = {\n \"ai.risense.test\" => true\n}",
            "ai.risense.test"
        )?);
        anyhow::ensure!(launchd_enabled(
            "disabled services = {\n \"ai.risense.test\" => false\n}",
            "ai.risense.test"
        )?);
        anyhow::ensure!(launchd_enabled(
            "disabled services = {\n \"ai.risense.test\" => unknown\n}",
            "ai.risense.test"
        )
        .is_err());
        anyhow::ensure!(launchd_enabled("unrecognized", "ai.risense.test").is_err());
        Ok(())
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn user_manager_lifecycle_refuses_loaded_overrides_and_preserves_data() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let mut config = super::super::tests::fixture(Platform::Linux);
        config.installation = temporary.path().canonicalize()?;
        config.user_home = config.installation.join("home");
        config.executable = config.installation.join("bin/rsrs");
        let (_scope, state) = test_adapter::install(&config);
        anyhow::ensure!(!inspect(&config)?.registered);
        install(&mut config)?;
        anyhow::ensure!(inspect(&config)?.enabled);
        start(&config)?;
        anyhow::ensure!(inspect(&config)?.running);
        let changes = state.borrow().changes.len();
        state.borrow_mut().dropin = true;
        anyhow::ensure!(stop(&config).is_err());
        anyhow::ensure!(remove(&config).is_err());
        anyhow::ensure!(state.borrow().changes.len() == changes && item(&config).exists());
        state.borrow_mut().dropin = false;
        anyhow::ensure!(
            remove(&config).is_err(),
            "running service must not be removed"
        );
        stop(&config)?;
        disable(&config)?;
        reset_backoff(&config)?;
        anyhow::ensure!(!inspect(&config)?.enabled && !inspect(&config)?.running);
        let preserved = config.installation.join("library.db");
        std::fs::write(&preserved, b"synthetic data")?;
        remove(&config)?;
        anyhow::ensure!(!item(&config).exists() && std::fs::read(preserved)? == b"synthetic data");
        config.artifact_hashes.clear();
        anyhow::ensure!(!inspect(&config)?.registered);
        Ok(())
    }
    #[test]
    fn windows_quoting_and_task_guard_are_literal_and_current_user_only() -> Result<()> {
        anyhow::ensure!(windows_argument("C:\\user folder\\")? == "\"C:\\user folder\\\\\"");
        anyhow::ensure!(ps_literal("a';&b")? == "'a'';&b'");
        let config = super::super::tests::fixture(Platform::Windows);
        let script = task_guard(&config)?;
        anyhow::ensure!(
            script.contains("Interactive")
                && script.contains("Limited")
                && script.contains(".Arguments -cne")
        );
        anyhow::ensure!(
            !script.contains("RunLevel Highest") && !script.contains("ExecutionPolicy Bypass")
        );
        Ok(())
    }
}
