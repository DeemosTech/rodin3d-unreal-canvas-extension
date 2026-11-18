"""Direct streamable HTTP MCP client. No Codex, API key, or local HTTP listener."""
import json
from urllib.error import HTTPError
from urllib.request import Request

import rodin_auth


def chunks(response):
    if response.headers.get_content_type() == "application/json":
        yield json.load(response)
        return
    data = []
    for raw in response:
        line = raw.decode("utf8").rstrip("\r\n")
        if line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        elif not line and data:
            yield json.loads("\n".join(data))
            data.clear()
    if data:
        yield json.loads("\n".join(data))


class Rodin:
    def __init__(self, tick):
        self.tick = tick
        self.access = rodin_auth.token(tick)
        self.session = None
        self.version = None
        self.number = 0
        response = self.rpc("initialize", {
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"unreal_canvas_plugin","version":"0.1.0"}
        })
        self.version = response["protocolVersion"]
        self.rpc("notifications/initialized", {}, notification=True)

    def rpc(self, method, params, notification=False):
        self.number += 1
        body = {"jsonrpc":"2.0","method":method,"params":params}
        if not notification:
            body["id"] = self.number
        for attempt in range(2):
            headers = {"Authorization":"Bearer "+self.access,"Content-Type":"application/json",
                       "Accept":"application/json, text/event-stream"}
            if self.session:
                headers["Mcp-Session-Id"] = self.session
            if self.version:
                headers["MCP-Protocol-Version"] = self.version
            req = Request(rodin_auth.RESOURCE,json.dumps(body).encode(),headers)
            try:
                with rodin_auth.http.open(req,timeout=90) as reply:
                    if method=="initialize":
                        self.session=reply.headers.get("Mcp-Session-Id")
                    if notification:
                        return
                    for message in chunks(reply):
                        if message.get("id")==self.number:
                            if "error" in message:
                                raise RuntimeError(f"{method} RPC error {message['error'].get('code')}")
                            return message["result"]
                    raise RuntimeError(f"No {method} response")
            except HTTPError as exc:
                if exc.code==401 and attempt==0:
                    self.access=rodin_auth.token(self.tick,rejected=self.access)
                    continue
                raise RuntimeError(f"{method} returned HTTP {exc.code}") from None

    def tool(self, name, args):
        result=self.rpc("tools/call",{"name":name,"arguments":args})
        if result.get("isError"):
            raise RuntimeError(f"{name} was rejected by Rodin")
        if result.get("structuredContent") is not None:
            return result["structuredContent"]
        return json.loads(next(c["text"] for c in result["content"] if c["type"]=="text"))
