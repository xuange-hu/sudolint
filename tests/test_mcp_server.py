"""The MCP server registers the same six tools the manifest promises.

Skipped when the optional ``mcp`` extra is not installed; CI installs it.
"""

from __future__ import annotations

import asyncio

import pytest

mcp = pytest.importorskip("mcp")  # noqa: F841  (extra presence check)

from sudolint.mcp_server import build_server, tool_manifest


def test_build_server_registers_the_manifest_tools():
    server = build_server()
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}
    assert names == {entry["name"] for entry in tool_manifest()}


def test_every_registered_tool_has_a_description():
    server = build_server()
    tools = asyncio.run(server.list_tools())
    for tool in tools:
        assert tool.description, f"{tool.name} registered without a description"
