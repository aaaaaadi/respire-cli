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
    args = parser.parse_args()
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


if __name__ == "__main__":
    main()
