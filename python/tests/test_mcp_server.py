"""
Tests for the optional MCP server mode (skillguard/mcp_server.py), run
in-process via the official `mcp` SDK's own in-memory client/server test
helper (mcp.shared.memory.create_connected_server_and_client_session) --
no child process, no real stdio transport, matching how the TypeScript
suite exercises src/mcp/server.ts (src/mcp/server.test.ts).

The whole module is skipped when the optional `mcp` extra isn't installed
(`pip install "skillguard-cli[mcp]"`) -- this package's base install never
requires it, so CI/dev environments that only installed the base package
should not fail here.
"""
import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="optional `mcp` extra not installed (pip install \"skillguard-cli[mcp]\")")

from skillguard.mcp_server import create_server  # noqa: E402

EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples"


async def _call_tool(name: str, arguments: dict):
    import mcp.shared.memory as mem

    server = create_server()
    async with mem.create_connected_server_and_client_session(server) as client:
        return await client.call_tool(name, arguments)


async def _list_tools():
    import mcp.shared.memory as mem

    server = create_server()
    async with mem.create_connected_server_and_client_session(server) as client:
        return await client.list_tools()


def _first_text(result) -> str:
    return result.content[0].text


def test_advertises_scan_skill_with_documented_input_fields():
    tools = asyncio.run(_list_tools())
    tool = next((t for t in tools.tools if t.name == "scan_skill"), None)
    assert tool is not None
    assert "third-party" in tool.description

    properties = tool.inputSchema["properties"]
    assert set(["path", "severity_threshold", "timeout_ms"]).issubset(properties.keys())
    assert tool.inputSchema["required"] == ["path"]


def test_known_bad_skill_returns_findings_and_exit_code_1():
    result = asyncio.run(
        _call_tool("scan_skill", {"path": str(EXAMPLES_DIR / "known-bad-skill")})
    )
    assert not result.isError
    parsed = json.loads(_first_text(result))
    assert parsed["exitCode"] == 1
    assert len(parsed["findings"]) > 0
    assert parsed["summary"]["HIGH"] > 0


def test_clean_skill_returns_clean_result_with_exit_code_0():
    result = asyncio.run(_call_tool("scan_skill", {"path": str(EXAMPLES_DIR / "clean-skill")}))
    assert not result.isError
    parsed = json.loads(_first_text(result))
    assert parsed["exitCode"] == 0
    assert parsed["findings"] == []


def test_severity_threshold_override_matches_cli_flag_semantics():
    result = asyncio.run(
        _call_tool(
            "scan_skill",
            {"path": str(EXAMPLES_DIR / "known-bad-skill"), "severity_threshold": "LOW"},
        )
    )
    assert not result.isError
    parsed = json.loads(_first_text(result))
    assert parsed["severityThreshold"] == "LOW"
    assert parsed["exitCode"] == 1


def test_invalid_severity_threshold_returns_a_tool_error_not_a_crash():
    result = asyncio.run(
        _call_tool(
            "scan_skill",
            {"path": str(EXAMPLES_DIR / "clean-skill"), "severity_threshold": "NOT_A_LEVEL"},
        )
    )
    assert result.isError
    assert "WHAT:" in _first_text(result)
    assert "WHY:" in _first_text(result)
    assert "FIX:" in _first_text(result)


def test_invalid_timeout_ms_returns_a_tool_error():
    result = asyncio.run(
        _call_tool(
            "scan_skill",
            {"path": str(EXAMPLES_DIR / "clean-skill"), "timeout_ms": -5},
        )
    )
    assert result.isError
    assert "timeout_ms must be a positive number" in _first_text(result)


def test_target_not_found_reports_exit_code_2_and_is_error():
    result = asyncio.run(
        _call_tool("scan_skill", {"path": str(EXAMPLES_DIR / "does-not-exist-fixture")})
    )
    # scan_skill() itself never raises for a missing target -- it returns a
    # structured ScanResult with exit_code 2 -- so the MCP tool call
    # succeeds at the protocol level; the *scan* result is what reports the
    # error, same distinction the TypeScript suite documents.
    assert not result.isError
    parsed = json.loads(_first_text(result))
    assert parsed["exitCode"] == 2
