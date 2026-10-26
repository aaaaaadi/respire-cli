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
        root = base / "data"
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            port = port_socket.getsockname()[1]
        env = {key: os.environ[key] for key in (
            "PATH", "LANG", "LC_ALL", "SystemRoot", "WINDIR", "TEMP", "TMP"
        ) if key in os.environ}
        env.update(HOME=str(home), USERPROFILE=str(home), RSRS_DATA_DIR=str(root),
                   RSRS_BIN_DIR=str(base / "bin"), RSRS_RPC_PORT=str(port),
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
        if args.register:
            def run(*argv):
                result = command(*argv)
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
                run("runtime", "stop")
                time.sleep(1)
                stopped = run("runtime", "status")
                assert stopped["runtime"]["running"] is False, "manual stop was automatically resurrected"
                run("runtime", "restart")
                restarted = run("runtime", "status")
                assert restarted["runtime"]["running"] and restarted["runtime"]["pid"] != first_pid, restarted
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



if __name__ == "__main__":
    main()
