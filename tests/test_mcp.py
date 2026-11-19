"""Exercise the production SDK transport against an in-process MCP HTTP service."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx2
from mcp.server import MCPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rodin_mcp


class TransportTest(unittest.IsolatedAsyncioTestCase):
    async def test_rejected_token_and_structured_result(self):
        server = MCPServer("test-rodin")
        calls = []

        @server.tool()
        def rodin_wait(generation_id: str) -> dict:
            calls.append(generation_id)
            return {"status": "completed"}

        app = server.streamable_http_app(stateless_http=True, json_response=True)

        async def authorized(scope, receive, send):
            headers = dict(scope["headers"])
            if headers.get(b"authorization") == b"Bearer renewed":
                return await app(scope, receive, send)
            await send({"type": "http.response.start", "status": 401, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        client_class = httpx2.AsyncClient
        def http_client(**kwargs):
            return client_class(transport=httpx2.ASGITransport(app=authorized), **kwargs)

        with patch.object(rodin_mcp.rodin_auth, "RESOURCE", "http://127.0.0.1:8765/mcp"), \
             patch.object(rodin_mcp.rodin_auth, "token", side_effect=["expired", "renewed"]) as token, \
             patch.object(rodin_mcp.httpx2, "AsyncClient", side_effect=http_client):
            async with app.router.lifespan_context(app):
                async with rodin_mcp.connect(print) as client:
                    result = await rodin_mcp.call_tool(client, "rodin_wait", {"generation_id": "example"})
        token.assert_called_with(print, rejected="expired")
        self.assertEqual(result, {"status": "completed"})
        self.assertEqual(calls, ["example"])
