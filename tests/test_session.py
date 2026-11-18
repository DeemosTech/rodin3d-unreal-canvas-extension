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
import credential
from credential import linux, macos


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
            ctx.enter_context(patch.object(credential.backend, "STATE_DIR", Path(tmp)))
            ctx.enter_context(patch.object(auth, "oauth_post", side_effect=post))
            ctx.enter_context(patch.object(auth.time, "sleep"))
            if sys.platform != "win32":
                ctx.enter_context(patch.object(credential.backend, "credential", side_effect=keyring))
            token = auth.token(lambda s: None, False)
            self.assertEqual(auth.token(lambda s: None, False), token)
            self.assertEqual(auth.token(lambda s: None, False, rejected=token), "mock-access-2")
            self.assertEqual(auth.token(lambda s: None, False, rejected="mock-access-2"), "mock-access-3")
            self.assertEqual(credential.load()["client_id"], auth.client_id())
            if sys.platform == "win32":
                self.assertNotIn(b"mock-refresh", (Path(tmp) / "login.dpapi").read_bytes())
            credential.clear_session()
            self.assertEqual(credential.load(), {})

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
        with patch.object(linux.shutil, "which", return_value="/usr/bin/secret-tool"), patch.object(linux, "run_helper", side_effect=run):
            linux.credential("store", {"access_token":"test-token"})
            self.assertEqual(linux.credential("get")["access_token"], "test-token")
            linux.credential("erase")
            self.assertEqual(linux.credential("get"), {})

    def test_keychain_wire(self):
        with tempfile.TemporaryDirectory() as tmp:
            helper = Path(tmp) / "git-credential-osxkeychain"
            helper.touch()
            def run(argv, payload=None):
                if argv == ["/usr/bin/git", "--exec-path"]:
                    return subprocess.CompletedProcess(argv, 0, tmp, "")
                self.assertEqual(argv[0], str(helper))
                self.assertIn("username=unreal_canvas_plugin", payload.splitlines())
                if argv[1] == "store":
                    self.assertIn('password={"access_token":"test-token"}', payload.splitlines())
                reply = 'password={"access_token":"test-token"}' if argv[1] == "get" else ""
                return subprocess.CompletedProcess(argv, 0, reply, "")
            with patch.object(macos, "run_helper", side_effect=run):
                macos.credential("store", {"access_token": "test-token"})
                self.assertEqual(macos.credential("get"), {"access_token": "test-token"})
                macos.credential("erase")


if __name__ == "__main__":
    unittest.main()
