import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import dev_model_fixture as model


class ModelFixtureTests(unittest.TestCase):
    def test_pins_match_host_and_fixture_bytes_are_shared_and_verified(self):
        host = (Path(__file__).parents[1] / "crates/core-sdk/src/cpu_model.rs").read_text()
        for value in (model.CPU_NAME, model.CPU_SHA256, str(model.CPU_SIZE)):
            self.assertIn(value, host)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "profile/models/bge-m3/onnx" / model.CPU_NAME
            source.parent.mkdir(parents=True)
            source.write_bytes(b"verified fixture container")
            shared = root / "models"
            env = {"RSRS_DATA_DIR": str(root / "profile")}
            with patch.object(model, "CPU_SIZE", source.stat().st_size), patch.object(
                    model, "CPU_SHA256", hashlib.sha256(source.read_bytes()).hexdigest()):
                model.share_cpu_container(root, env, shared)
                self.assertEqual(source.read_bytes(), (shared / "onnx" / model.CPU_NAME).read_bytes())
                model.share_cpu_container(root, env, shared)
                with self.assertRaisesRegex(RuntimeError, "owned_fixture_child"):
                    model.share_cpu_container(root, env, root.parent)
                (shared / "onnx" / model.CPU_NAME).write_bytes(b"corrupt")
                with self.assertRaisesRegex(RuntimeError, "not_fresh"):
                    model.share_cpu_container(root, env, shared)

    def test_failed_install_does_not_create_shared_container(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "missing_or_corrupt"):
                model.share_cpu_container(root, {"RSRS_DATA_DIR": str(root / "profile")}, root / "models")
            self.assertFalse((root / "models").exists())

    def test_diagnostics_keep_errno_and_redact_fixture_and_session_credentials(self):
        spec = importlib.util.spec_from_file_location("legacy", Path(__file__).with_name("dev-legacy-vault-smoke.py"))
        legacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(legacy)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "session.json").write_text(json.dumps({"token": "private-session-token"}))
            smoke = object.__new__(legacy.Smoke)
            smoke.diagnostic_secrets = {"private-fixture-password"}
            result = subprocess.CompletedProcess([], 1, json.dumps({"errors": [
                "No such file (os error 2) private-fixture-password private-session-token Bearer private-bearer"
            ]}).encode(), b"")
            diagnostic = smoke.redacted_cli_error({"RSRS_DATA_DIR": str(root)}, result)
            self.assertIn("os error 2", diagnostic)
            self.assertNotIn("private-", diagnostic)
            self.assertLessEqual(len(diagnostic), 1500)


if __name__ == "__main__":
    unittest.main()
