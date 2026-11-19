import json
import os
import shutil
from pathlib import Path

from . import StoreError
from ._helper import run_helper

STATE_DIR = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "RodinCanvasMCP"


def credential(action, state=None):
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
