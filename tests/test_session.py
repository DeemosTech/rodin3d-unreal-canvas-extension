"""Offline OAuth regression: store, reuse, rotate, recover invalid_grant, log out."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rodin_auth as auth
import posix_credentials as posix


class SessionTest(unittest.TestCase):
    def test_lifecycle(self):
        saved = {}
        def keyring(action, state=None):
            if action == "get":
                return dict(saved)
            saved.clear()
            if state:
                saved.update(state)

        counter = 0
        def post(path, body):
            nonlocal counter
            if path == "/device/code":
                return dict(verification_uri="https://hyper3d.ai/test", user_code="TEST",
                            device_code="test", expires_in=90)
            if body["grant_type"] == "refresh_token" and counter == 2:
                raise auth.AuthError("invalid_grant")
            counter += 1
            return dict(access_token=f"mock-access-{counter}", refresh_token=f"mock-refresh-{counter}",
                        expires_in=600)

        with tempfile.TemporaryDirectory() as tmp, ExitStack() as ctx:
            ctx.enter_context(patch.object(auth, "STATE", Path(tmp) / "login.dpapi"))
            ctx.enter_context(patch.object(auth, "oauth_post", side_effect=post))
            ctx.enter_context(patch.object(auth.time, "sleep"))
            if sys.platform != "win32":
                ctx.enter_context(patch.object(auth, "credential", side_effect=keyring))
            token = auth.token(lambda s: None, False)
            self.assertEqual(auth.token(lambda s: None, False), token)
            self.assertEqual(auth.token(lambda s: None, False, rejected=token), "mock-access-2")
            self.assertEqual(auth.token(lambda s: None, False, rejected="mock-access-2"), "mock-access-3")
            self.assertEqual(auth.load()["client_id"], auth.client_id())
            if sys.platform == "win32":
                self.assertNotIn(b"mock-refresh", auth.STATE.read_bytes())
            auth.clear_session()
            self.assertEqual(auth.load(), {})

    def test_secret_service_wire(self):
        item = {}
        def run(argv, payload=None):
            if argv[1] == "store":
                self.assertNotIn("test-token", " ".join(argv))
                item["value"] = payload
            elif argv[1] == "clear":
                item.clear()
            if argv[1] == "lookup" and not item:
                return subprocess.CompletedProcess(argv, 1, "", "")
            return subprocess.CompletedProcess(argv, 0, item.get("value", ""), "")
        with patch.object(posix.shutil, "which", return_value="/usr/bin/secret-tool"), patch.object(posix, "run_helper", side_effect=run):
            posix.secret_service("store", {"access_token":"test-token"})
            self.assertEqual(posix.secret_service("get")["access_token"], "test-token")
            posix.secret_service("erase")
            self.assertEqual(posix.secret_service("get"), {})


if __name__ == "__main__":
    unittest.main()
