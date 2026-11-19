"""Refresh the Canvas controls from the authenticated Rodin MCP tools/list."""
import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from rodin_mcp import connect


def select(key, label, prop):
    options = prop.get("enum")
    if options is None:
        options = [item["const"] for item in prop["anyOf"]]
    if not options or not all(isinstance(value, str) for value in options) or prop["default"] not in options:
        raise ValueError(f"Unsupported MCP options for {key}")
    return dict(type="select", key=key, label=label, default=prop["default"],
                options=[dict(value=value, label=value) for value in options])


async def main():
    properties = {}
    async with connect(print) as client:
        cursor = None
        while True:
            page = await client.list_tools(cursor=cursor)
            for tool in page.tools:
                if tool.name in {"rodin_generate", "rodin_generate_bang"}:
                    properties[tool.name] = tool.input_schema["properties"]
            cursor = page.next_cursor
            if not cursor or len(properties) == 2:
                break

    generate = properties["rodin_generate"]
    controls = [select("tier", "Tier", generate["tier"]), select("mesh_mode", "Mesh mode", generate["mesh_mode"])]
    prop = properties["rodin_generate_bang"]["strength"]
    if prop["type"] != "integer" or not prop["minimum"] <= prop["default"] <= prop["maximum"]:
        raise ValueError("Unsupported BANG strength schema")
    slider = dict(type="slider", key="strength", label="Strength", min=prop["minimum"],
                  max=prop["maximum"], step=1, default=prop["default"])

    for service, params in (("image", controls), ("bang", [slider])):
        path = ROOT / "schemas" / "services" / f"rodin-canvas-{service}.json"
        schema = json.loads(path.read_bytes())
        schema["params"] = params
        for param in params:
            key = param["key"]
            schema["transport"]["inputs"][key] = "{{params." + key + "}}"
        path.write_bytes((json.dumps(schema, indent=2) + "\n").encode())

    # The custom graph editor is shipped as one JS module. Embed the same control.
    path = ROOT / "dist" / "index.js"
    lines = path.read_text(encoding="utf8").splitlines()
    position, = [i for i, line in enumerate(lines) if line.startswith("const bangStrength = ")]
    lines[position] = "const bangStrength = " + json.dumps(slider) + ";"
    path.write_bytes(("\n".join(lines) + "\n").encode())


if __name__ == "__main__":
    asyncio.run(main())
