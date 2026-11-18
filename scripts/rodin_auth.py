"""Device authorization for Rodin Canvas. Per-user, per-plugin OS credential storage."""
import argparse
import json
import os
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request
import webbrowser

import credential

RESOURCE = "https://api.hyper3d.com/api/mcp"
ISSUER = "https://api.hyper3d.com/api/grant/oauth"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
SCOPE = "offline_access rodin:read rodin:generate"


class AuthError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


http = build_opener(NoRedirect())


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
    credential.save(state)
    return state["access_token"]


def client_id():
    return os.environ.get("RODIN_CANVAS_CLIENT_ID") or "https://hyper3d.ai/oauth_cimd/unreal_canvas_plugin.json"


def signed_in(state):
    return state.get("client_id") == client_id() and bool(state.get("refresh_token") or state.get("expires_at",0)>time.time())


def token(tick, open_browser=True, rejected=None):
    with credential.locked(tick):
        state = credential.load()
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
                credential.save(state)
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
        with credential.locked(display):
            if args.action=="logout":
                credential.clear_session()
                print("Local Rodin Canvas session removed.")
            else:
                state=credential.load()
                print("Session saved" if signed_in(state) else "Sign-in required")

if __name__ == "__main__":
    try:
        main()
    except (AuthError,credential.StoreError,OSError,KeyError,ValueError) as exc:
        sys.exit("Rodin sign-in failed: "+(str(exc) if isinstance(exc,(AuthError,credential.StoreError)) else type(exc).__name__))
