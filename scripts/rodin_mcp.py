"""Connect the Canvas session to Rodin using the official MCP client."""
import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
import json

import httpx2
from mcp import Client
from mcp.types import Implementation
from mcp.client.streamable_http import streamable_http_client

import rodin_auth


class RodinAuth(httpx2.Auth):
    def __init__(self, tick):
        self.tick = tick
        self.access = rodin_auth.token(tick)

    async def async_auth_flow(self, request):
        access = self.access
        request.headers["Authorization"] = "Bearer " + access
        response = yield request
        if response.status_code == 401:
            self.access = await asyncio.to_thread(rodin_auth.token, self.tick, rejected=access)
            request.headers["Authorization"] = "Bearer " + self.access
            yield request


@asynccontextmanager
async def connect(tick):
    async with httpx2.AsyncClient(auth=RodinAuth(tick), timeout=90) as http:
        transport = streamable_http_client(rodin_auth.RESOURCE, http_client=http)
        client = Client(
            transport, mode="legacy", read_timeout_seconds=90,
            client_info=Implementation(name="unreal_canvas_extension", version="0.1.3"),
        )
        # Close the SDK task groups normally even when Canvas cancels the job.
        stack = AsyncExitStack()
        try:
            await stack.enter_async_context(client)
        except Exception as exc:
            raise RuntimeError(f"Rodin MCP connection failed ({type(exc).__name__})") from None
        try:
            yield client
        finally:
            await stack.aclose()


async def call_tool(client, name, arguments):
    try:
        result = await client.call_tool(name, arguments)
    except Exception as exc:
        raise RuntimeError(f"{name} failed ({type(exc).__name__})") from None
    if result.is_error:
        raise RuntimeError(f"{name} was rejected by Rodin")
    if result.structured_content is not None:
        return result.structured_content
    for block in result.content:
        if block.type == "text":
            return json.loads(block.text)
    raise ValueError(f"{name} returned no Rodin result")
