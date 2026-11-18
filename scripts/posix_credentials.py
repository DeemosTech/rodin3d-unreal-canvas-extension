"""OS credential storage for macOS and Linux. Secrets travel through pipes."""
import json
import shutil
import subprocess
import sys
from pathlib import Path


class StoreError(Exception):
    pass


def run_helper(command, payload=None):
    try:
        return subprocess.run(command, input=payload, capture_output=True, text=True,
                              encoding="utf8", timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StoreError("The desktop credential helper is unavailable.") from exc


def keychain(action, state=None):
    # Call the Apple Keychain helper directly; do not invoke any configured Git
    # credential helper (which could instead store a plaintext credentials file).
    git = run_helper(["/usr/bin/git", "--exec-path"])
    helper = Path(git.stdout.strip()) / "git-credential-osxkeychain"
    if git.returncode or not helper.is_absolute() or not helper.is_file():
        raise StoreError("Install Apple's Command Line Tools with the osxkeychain helper.")
    fields = ["protocol=https", "host=api.hyper3d.com",
              "path=oauth_cimd/unreal_canvas_plugin.json", "username=unreal_canvas_plugin"]
    if action == "store":
        fields.append("password=" + json.dumps(state, separators=(",", ":")))
    result = run_helper([str(helper), action], "\n".join(fields) + "\n\n")
    if result.returncode:
        raise StoreError("Keychain operation failed. Check the login keychain and its access prompt.")
    if action == "get":
        for line in result.stdout.splitlines():
            if line.startswith("password="):
                return json.loads(line[len("password="):])
        return {}


def secret_service(action, state=None):
    tool = shutil.which("secret-tool")
    if not tool:
        raise StoreError("Install secret-tool (libsecret-tools on Ubuntu) and unlock a Secret Service keyring.")
    args = {"get": ["lookup"], "store": ["store", "--label=Rodin for Unreal Canvas"],
            "erase": ["clear"]}[action]
    result = run_helper([tool, *args, "application", "unreal_canvas_plugin", "purpose", "rodin-mcp-oauth"],
                        json.dumps(state) if action == "store" else None)
    if result.returncode:
        if action in ("get", "erase") and result.returncode == 1 and not result.stderr.strip():
            return {}  # no matching item
        raise StoreError("Secret Service is unavailable or locked. Check the desktop D-Bus session and keyring.")
    if action == "get":
        return json.loads(result.stdout) if result.stdout.strip() else {}


def credential(action, state=None):
    if sys.platform == "darwin":
        return keychain(action, state)
    return secret_service(action, state)
