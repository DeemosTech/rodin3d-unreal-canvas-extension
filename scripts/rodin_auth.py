"""Device authorization for Rodin Canvas. Per-user, per-plugin OS credential storage."""
import argparse
import contextlib
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import secrets
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request
import webbrowser

RESOURCE = "https://api.hyper3d.com/api/mcp"
ISSUER = "https://api.hyper3d.com/api/grant/oauth"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
SCOPE = "offline_access rodin:read rodin:generate"
if sys.platform == "win32":
    import msvcrt
    STATE = Path(os.environ["LOCALAPPDATA"]) / "RodinCanvasMCP" / "login.dpapi"
else:
    import fcntl
    from posix_credentials import credential, StoreError
    if sys.platform == "darwin":
        directory = Path.home() / "Library/Application Support/RodinCanvasMCP"
    elif sys.platform.startswith("linux"):
        directory = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "RodinCanvasMCP"
    else:
        raise RuntimeError("Unsupported Rodin Canvas worker platform")
    STATE = directory / "login"  # base for the lock and asset IDs; tokens live in the OS keyring


class AuthError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


http = build_opener(NoRedirect())


class Blob(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def protect(data, decrypt=False):
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    src, dst = Blob(len(data), buf), Blob()
    crypt = ctypes.windll.crypt32
    fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    if not fn(ctypes.byref(src), None, None, None, None, 1, ctypes.byref(dst)):
        raise AuthError("Windows could not open the plugin credential store")
    try:
        return ctypes.string_at(dst.data, dst.length)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(dst.data, ctypes.c_void_p))


def os_credential(action, state=None):
    try:
        return credential(action, state)
    except StoreError as exc:
        raise AuthError(str(exc)) from None


def load():
    if sys.platform != "win32":
        return os_credential("get")
    if not STATE.exists():
        return {}
    return json.loads(protect(STATE.read_bytes(), decrypt=True))


def clear_session():
    if sys.platform == "win32":
        STATE.unlink(missing_ok=True)
    else:
        os_credential("erase")


def save(state):
    if sys.platform != "win32":
        os_credential("store", state)
        return
    tmp = STATE.with_suffix("." + secrets.token_hex(8) + ".tmp")
    try:
        tmp.write_bytes(protect(json.dumps(state).encode()))
        os.replace(tmp, STATE)
    finally:
        tmp.unlink(missing_ok=True)


@contextlib.contextmanager
def locked(tick):
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with STATE.with_suffix(".lock").open("a+b") as lock:
        while True:
            lock.seek(0)
            try:
                if sys.platform == "win32":
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                tick("Waiting for the Rodin sign-in in another window")
                time.sleep(2)
        try:
            yield
        finally:
            lock.seek(0)
            if sys.platform == "win32":
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


def oauth_post(path, body, as_json=False):
    data = json.dumps(body).encode() if as_json else urlencode(body).encode()
    mime = "application/json" if as_json else "application/x-www-form-urlencoded"
    req = Request(ISSUER + path, data=data, headers={"Content-Type": mime, "Accept": "application/json"})
    try:
        with http.open(req, timeout=25) as reply:
            return json.load(reply)
    except HTTPError as exc:
        try:
            code = json.load(exc).get("error")
        except (ValueError, AttributeError):
            code = None
        allowed = {"authorization_pending","slow_down","access_denied","expired_token","invalid_grant",
                   "invalid_client","unauthorized_client","invalid_client_metadata","invalid_scope","unsupported_grant_type","invalid_request"}
        raise AuthError(code if code in allowed else f"OAuth HTTP {exc.code}") from None


def commit_tokens(state, tokens):
    if not tokens.get("access_token"):
        raise AuthError("Missing access token")
    state["access_token"] = tokens["access_token"]
    state["expires_at"] = time.time() + int(tokens.get("expires_in", 300))
    if tokens.get("refresh_token"):
        state["refresh_token"] = tokens["refresh_token"]
    save(state)
    return state["access_token"]


def client_id():
    return os.environ.get("RODIN_CANVAS_CLIENT_ID") or "https://hyper3d.ai/oauth_cimd/unreal_canvas_plugin.json"


def signed_in(state):
    return state.get("client_id") == client_id() and bool(state.get("refresh_token") or state.get("expires_at",0)>time.time())


def token(tick, open_browser=True, rejected=None):
    with locked(tick):
        state = load()
        configured_client = client_id()
        if state.get("client_id") != configured_client:
            state = {}
        if state.get("access_token") != rejected and state.get("expires_at", 0) > time.time()+45:
            return state["access_token"]
        state["client_id"] = configured_client
        common = {"client_id":configured_client,"resource":RESOURCE}
        if state.get("refresh_token"):
            try:
                tokens = oauth_post("/oauth2/token",dict(common,grant_type="refresh_token",refresh_token=state["refresh_token"]))
                return commit_tokens(state,tokens)
            except AuthError as exc:
                if str(exc) != "invalid_grant":
                    raise
                state = {"client_id":configured_client}
                save(state)
        challenge = oauth_post("/device/code",dict(common,scope=SCOPE))
        uri, code = challenge["verification_uri"], challenge["user_code"]
        link = challenge.get("verification_uri_complete") or uri
        for address in (uri,link):
            u = urlsplit(address)
            if u.scheme != "https" or u.hostname not in ("hyper3d.ai","www.hyper3d.ai","api.hyper3d.com"):
                raise AuthError("Unexpected Rodin verification site")
        message = f"Sign in at {uri} with code {code}"
        tick(message)
        if open_browser:
            webbrowser.open(link)
        deadline = time.monotonic() + int(challenge["expires_in"])
        delay = max(1,int(challenge.get("interval",5)))
        while time.monotonic()+delay < deadline:
            time.sleep(delay)
            tick(message)
            try:
                tokens = oauth_post("/oauth2/token",dict(common,grant_type=DEVICE_GRANT,device_code=challenge["device_code"]))
                return commit_tokens(state,tokens)
            except AuthError as exc:
                if str(exc) == "slow_down":
                    delay += 5
                elif str(exc) != "authorization_pending":
                    raise
        raise AuthError("Device code expired. Start sign-in again.")


def main():
    p=argparse.ArgumentParser()
    p.add_argument("action",choices=("login","status","logout"))
    args=p.parse_args()
    last=None
    def display(s):
        nonlocal last
        if last!=s:
            print(s,flush=True)
            last=s
    if args.action=="login":
        token(display)
        print("Rodin Canvas signed in.")
    else:
        with locked(display):
            if args.action=="logout":
                clear_session()
                print("Local Rodin Canvas session removed.")
            else:
                state=load()
                print("Session saved" if signed_in(state) else "Sign-in required")

if __name__ == "__main__":
    try:
        main()
    except (AuthError,OSError,KeyError,ValueError) as exc:
        sys.exit("Rodin sign-in failed: "+(str(exc) if isinstance(exc,AuthError) else type(exc).__name__))
