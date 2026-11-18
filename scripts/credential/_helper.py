"""Subprocess transport for desktop credential helpers."""
import subprocess

from . import StoreError


def run_helper(command, payload=None):
    try:
        return subprocess.run(command, input=payload, capture_output=True, text=True,
                              encoding="utf8", timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StoreError("The desktop credential helper is unavailable.") from exc
