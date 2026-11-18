import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import secrets

from . import StoreError

STATE_DIR = Path(os.environ["LOCALAPPDATA"]) / "RodinCanvasMCP"


class Blob(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def protect(data, decrypt=False):
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    src, dst = Blob(len(data), buf), Blob()
    crypt = ctypes.windll.crypt32
    fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    if not fn(ctypes.byref(src), None, None, None, None, 1, ctypes.byref(dst)):
        raise StoreError("Windows could not open the plugin credential store")
    try:
        return ctypes.string_at(dst.data, dst.length)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(dst.data, ctypes.c_void_p))


def credential(action, state=None):
    path = STATE_DIR / "login.dpapi"
    if action == "get":
        if not path.exists():
            return {}
        return json.loads(protect(path.read_bytes(), decrypt=True))
    if action == "erase":
        path.unlink(missing_ok=True)
        return
    if action != "store":
        raise ValueError("Unknown credential operation")
    tmp = path.with_suffix("." + secrets.token_hex(8) + ".tmp")
    try:
        tmp.write_bytes(protect(json.dumps(state).encode()))
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
