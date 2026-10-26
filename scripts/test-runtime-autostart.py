#!/usr/bin/env python3
"""Actual native foreground lifecycle in a disposable home; no OS registration.

The executable is the only input. No credentials, user data or inherited Respire
configuration are passed to it. Real sign-in service adapters require a separate
platform acceptance run; passing this script does not claim that acceptance.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--register", action="store_true", help="Exercise a disposable current-user OS registration on an ephemeral GitHub runner")
    args = parser.parse_args()
    if args.register and not (os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
        parser.error("OS registration acceptance is limited to an ephemeral GitHub-hosted runner")
    binary = str(args.binary.resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix="respire-autostart-") as temporary:
        base = Path(temporary)
        home = base / "home"
        home.mkdir()
        root = base / ('data spaces % $ " \\' if os.name == "posix" else "data spaces % and $")
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            port = port_socket.getsockname()[1]
        env = {key: os.environ[key] for key in (
            "PATH", "LANG", "LC_ALL", "SystemRoot", "WINDIR", "TEMP", "TMP",
            "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "LLVM_PROFILE_FILE",
            "APPDATA", "LOCALAPPDATA", "COMPUTERNAME", "COMSPEC", "PATHEXT",
            "ProgramFiles", "ProgramFiles(x86)", "ProgramData"
        ) if key in os.environ}
        if args.register and os.name == "posix" and os.uname().sysname == "Linux":
            import stat
            runtime = Path(f"/run/user/{os.getuid()}")
            if runtime.is_dir() and runtime.stat().st_uid == os.getuid():
                bus = runtime / "bus"
                if bus.exists() and stat.S_ISSOCK(bus.stat().st_mode):
                    env.setdefault("XDG_RUNTIME_DIR", str(runtime))
                    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus}")
        env.update(HOME=str(home), USERPROFILE=str(home), RSRS_DATA_DIR=str(root),
                   RSRS_BIN_DIR=str(root / "bin"), RSRS_RPC_PORT=str(port),
                   RSRS_CORE_TEST_MODE="1")

        def command(*argv):
            return subprocess.run([binary, "--json", *argv], env=env,
                                  capture_output=True, text=True, timeout=45)

        status = command("runtime", "autostart", "status")
        assert status.returncode == 0, status.stderr
        summary = json.loads(status.stdout)["summary"]
        assert summary["enabled"] is False and summary["registered"] is False
        assert not root.exists(), "status must not create a profile"
        denied = command("--client-only", "runtime", "autostart", "enable", "--now")
        assert denied.returncode != 0 and not root.exists()
        with (base / "foreground.log").open("w+") as log:
            child = subprocess.Popen([binary, "runtime", "run"], env=env,
                                     stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                health = None
                while time.monotonic() < deadline:
                    if child.poll() is not None:
                        log.seek(0)
                        raise AssertionError("foreground exited: " + log.read()[-3000:])
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/api/health", timeout=1
                        ) as response:
                            health = json.load(response)
                        if health.get("store_ready"):
                            break
                    except (OSError, ValueError):
                        pass
                    time.sleep(0.1)
                assert health and health["store_ready"], "store never became ready"
                assert health["pid"] == child.pid and health["managed_id"] is None
                assert Path(health["installation_root"]).resolve() == root.resolve()
                stopped = command("runtime", "stop")
                assert stopped.returncode == 0, stopped.stderr
                assert child.wait(timeout=20) == 0
                assert not (root / "runtime/autostart/registration.json").exists()
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=20)
        print("PASS: read-only default-off status, client-only denial, actual foreground store readiness and owned stop")
        # A fresh off-mode installation must restart without opening/creating a
        # library. Its detached child is always stopped before leaving the test.
        off_root = base / "off installation"
        off_root.mkdir()
        (off_root / "client.json").write_text(json.dumps({"service_mode":"off"}))
        off_env = dict(env, RSRS_DATA_DIR=str(off_root), RSRS_BIN_DIR=str(base/"off-bin"))
        try:
            for argv in [("runtime","start"),("runtime","stop"),("runtime","restart")]:
                result = subprocess.run([binary,"--json",*argv],env=off_env,capture_output=True,text=True,timeout=45)
                assert result.returncode == 0, f"off mode {argv}: {result.stdout} {result.stderr}"
                assert not (off_root/"rsrs.db").exists() and not (off_root/"onememory.db").exists(), "off restart created a database"
        finally:
            result = subprocess.run([binary,"--json","runtime","stop"],env=off_env,capture_output=True,text=True,timeout=45)
            assert result.returncode == 0, f"off-mode child cleanup failed: {result.stdout} {result.stderr}"
        print("PASS: fresh memory-off start/stop/restart without a database")
        if args.register:
            def collect_managed_profiles():
                # A service manager deliberately does not inherit test-runner
                # profiling variables. Collect the real instrumented native
                # child's default profiles from this disposable working root.
                pattern = os.environ.get("LLVM_PROFILE_FILE")
                if not pattern:
                    return
                import shutil
                import uuid
                destination = Path(pattern).parent
                assert destination.is_dir(), "coverage profile destination missing"
                for profile in root.rglob("*.profraw"):
                    assert not profile.is_symlink() and profile.stat().st_size <= 64 * 1024 * 1024
                    shutil.copyfile(profile, destination / f"autostart-managed-{uuid.uuid4().hex}.profraw")

            def diagnose_registration():
                import hashlib
                import platform
                if os.name != "posix":
                    return
                identity = hashlib.sha256(f"respire-runtime-v1\0{root.resolve()}\0{os.getuid()}".encode()).hexdigest()[:24]
                system = platform.system()
                if system == "Linux":
                    name = f"respire-runtime-{identity}.service"
                    output = subprocess.run(["/usr/bin/systemctl", "--user", "show", name,
                        "--property=LoadState,FragmentPath,DropInPaths,UnitFileState"], env=env,
                        capture_output=True, text=True, timeout=15)
                    print("isolated systemd path diagnostic", json.dumps({"expected":str(home.resolve()/".config/systemd/user"/name),"properties":output.stdout[:8192]}))
                elif system == "Darwin":
                    label = f"ai.risense.respire.runtime.{identity}"
                    output = subprocess.run(["/bin/launchctl", "print-disabled", f"gui/{os.getuid()}"],
                        env=env, capture_output=True, text=True, timeout=15)
                    matching = [line.strip() for line in output.stdout.splitlines() if line.strip().startswith(f'"{label}" => ')]
                    print("isolated launchd override diagnostic",json.dumps({"label":label,"entries":[line[:160] for line in matching]}))

            def run(*argv):
                result = command(*argv)
                if result.returncode != 0:
                    diagnose_registration()
                assert result.returncode == 0, f"{argv}: {result.stderr} {result.stdout}"
                value = json.loads(result.stdout)
                assert value["status"] == "ok", value
                return value["summary"]

            try:
                enabled = run("runtime", "autostart", "enable")
                assert enabled["enabled"] is True and enabled["registered"] is True, enabled
                assert enabled["runtime"]["running"] is False, "enable without --now unexpectedly starts runtime"
                run("runtime", "autostart", "enable")  # idempotent, same installation
                run("runtime", "start")
                up = run("runtime", "status")
                assert up["runtime"]["running"] is True and up["runtime"]["store_ready"] is True, up
                first_pid = up["runtime"]["pid"]
                config_path = root / "runtime/autostart/registration.json"
                unchanged_config = config_path.read_bytes()
                with socket.socket() as other_socket:
                    other_socket.bind(("127.0.0.1",0))
                    other_port = other_socket.getsockname()[1]
                wrong_endpoint = subprocess.run([binary,"--json","runtime","stop"],
                    env=dict(env,RSRS_RPC_PORT=str(other_port)),capture_output=True,text=True,timeout=45)
                assert wrong_endpoint.returncode != 0 and config_path.read_bytes() == unchanged_config
                assert run("runtime","status")["runtime"]["pid"] == first_pid, "wrong-port stop changed the owned process"
                if os.name == "posix" and os.uname().sysname == "Linux":
                    assert Path(f"/proc/{first_pid}/cwd").resolve() == root.resolve(), "supervised process has the wrong actual working directory"
                run("runtime", "stop")
                time.sleep(1)
                stopped = run("runtime", "status")
                assert stopped["runtime"]["running"] is False, "manual stop was automatically resurrected"
                run("runtime", "restart")
                restarted = run("runtime", "status")
                assert restarted["runtime"]["running"] and restarted["runtime"]["pid"] != first_pid, restarted
                secondary = root / "accounts/secondary profile"
                secondary.mkdir(parents=True)
                run("config", "--data-dir", str(secondary))
                switched = run("runtime", "status")
                assert Path(switched["runtime"]["data_dir"]).resolve() == secondary.resolve(), switched
                assert switched["runtime"]["pid"] != restarted["runtime"]["pid"]
                run("config", "--data-dir", str(root))
                restored = run("runtime", "status")
                assert Path(restored["runtime"]["data_dir"]).resolve() == root.resolve(), restored
                assert restored["runtime"]["pid"] != switched["runtime"]["pid"]
                print("PASS: supervised synthetic profile switch and return, with verified new owner processes")

                # Persisted interrupted-controller fixtures are exercised by the
                # actual CLI and OS supervisor. This is process recovery from
                # recorded states, not a physical power-loss experiment.
                import uuid
                registration = root / "runtime/autostart/registration.json"
                marker = registration.with_name("maintenance.json")
                for phase in ("Paused", "Starting", "Verified"):
                    if phase != "Starting":
                        run("runtime", "stop")
                    config = json.loads(registration.read_text())
                    stopped_flag = config["manually_stopped"]
                    config["maintenance"] = True
                    registration.write_text(json.dumps(config))
                    value = {"schema":1,"id":config["id"],"token":str(uuid.uuid4()),"phase":phase,
                        "expected_profile":str(root.resolve()),"expected_version":restarted["runtime"]["version"],
                        "owner_pid":os.getpid(),"owner_birth":"synthetic-expired-controller"}
                    with os.fdopen(os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w") as pending:
                        json.dump(value,pending)
                        pending.flush()
                        os.fsync(pending.fileno())
                    database = root / "rsrs.db"
                    before = database.read_bytes()
                    modified = database.stat().st_mtime_ns
                    denied_start = command("runtime", "start")
                    assert denied_start.returncode != 0 and marker.exists()
                    assert json.loads(registration.read_text())["manually_stopped"] == stopped_flag
                    denied_read = command("--direct", "memory-revision")
                    assert denied_read.returncode != 0 and marker.exists()
                    if phase == "Starting":
                        for method in ("model.prepare", "index.prepare"):
                            request = urllib.request.Request(f"http://127.0.0.1:{port}/api/rpc",
                                data=json.dumps({"v":1,"id":str(uuid.uuid4()),"method":method,"args":[]}).encode(),
                                headers={"Content-Type":"application/json"})
                            with urllib.request.urlopen(request,timeout=5) as response:
                                reply=json.load(response)
                            assert reply["ok"] is False and reply["code"] == "runtime_maintenance", reply
                    assert database.read_bytes() == before and database.stat().st_mtime_ns == modified
                    run("runtime", "restart")
                    recovered = run("runtime", "status")
                    assert recovered["runtime"]["running"] and recovered["runtime"]["store_ready"]
                    assert not marker.exists() and not json.loads(registration.read_text())["maintenance"]
                    print(f"PASS: native persisted {phase} recovery; direct reads/preparation fenced; manual-stop intent retained until explicit restart")

                # Managed off-mode uses process/profile readiness, not a store
                # that this mode intentionally never opens.
                run("runtime", "stop")
                client = root / "client.json"
                previous_client = client.read_bytes() if client.exists() else None
                settings = json.loads(previous_client) if previous_client else {}
                database = root / "rsrs.db"
                before_database = database.read_bytes()
                before_modified = database.stat().st_mtime_ns
                settings["service_mode"] = "off"
                client.write_text(json.dumps(settings))
                run("runtime", "restart")
                off_status = run("runtime", "status")
                assert off_status["runtime"]["running"] and off_status["runtime"]["store_ready"] is False, off_status
                assert database.read_bytes() == before_database and database.stat().st_mtime_ns == before_modified
                run("runtime", "stop")
                if previous_client is None:
                    client.unlink()
                else:
                    client.write_bytes(previous_client)
                run("runtime", "restart")
                assert run("runtime", "status")["runtime"]["store_ready"] is True
                run("runtime", "autostart", "disable", "--stop")
                disabled = run("runtime", "status")
                assert disabled["enabled"] is False and disabled["runtime"]["running"] is False, disabled
                run("runtime", "autostart", "enable", "--now")
                assert run("runtime", "status")["runtime"]["running"] is True
                preserved = root / "synthetic-preserved-file"
                preserved.write_text("must survive uninstall")
                run("runtime", "autostart", "remove", "--stop")
                removed = run("runtime", "status")
                assert not removed["registered"] and not removed["enabled"] and not removed["runtime"]["running"], removed
                assert preserved.read_text() == "must survive uninstall"
                print("PASS: actual current-user register/readback/start/stop/restart/disable/reenable/remove; data retained")
            finally:
                # The CLI revalidates exact owner/action/files before cleanup;
                # never delete unknown OS tasks/units merely to make a test pass.
                cleanup = command("runtime", "autostart", "remove", "--stop")
                assert cleanup.returncode == 0, f"Owned registration cleanup failed: {cleanup.stderr} {cleanup.stdout}"
                collect_managed_profiles()



if __name__ == "__main__":
    main()
