import json
from pathlib import Path

from . import StoreError
from ._helper import run_helper

STATE_DIR = Path.home() / "Library/Application Support/RodinCanvasMCP"


def credential(action, state=None):
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
