"""Stock MCP client -> real MCP server over streamable HTTP, with audience-bound tokens (interop demo)."""
import asyncio
import json
import socket
import threading
import time

import pytest

from switchboard import auth

pytest.importorskip("mcp")


@pytest.fixture(scope="module")
def mcp_url():
    import uvicorn

    from switchboard.mcp_servers import build

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    server = uvicorn.Server(uvicorn.Config(build("acs").streamable_http_app(), host="127.0.0.1", port=port,
                                           log_level="warning"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    th.join(5)


def _call(url: str, token: str, tool: str, args: dict) -> dict:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    async def go():
        async with streamablehttp_client(url, headers={"Authorization": f"Bearer {token}"}) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                res = await s.call_tool(tool, {"args": args})
                return json.loads(res.content[0].text)

    return asyncio.run(go())


def test_same_allow_deny_outside_the_agent(mcp_url):
    maya = auth.issue("maya", audience="mcp-acs")
    assert _call(mcp_url, maya, "get_device_status", {"cpe_sn": "CPE-5521"})["status"] == "ok"
    assert _call(mcp_url, maya, "get_device_status", {"cpe_sn": "CPE-4410"})["status"] == "denied"
    assert _call(mcp_url, auth.issue("ext-t1", audience="mcp-acs"), "get_device_status",
                 {"cpe_sn": "CPE-5521"})["status"] == "denied"
    gateway_token = auth.issue("maya")  # wrong audience: must not be accepted by the MCP resource server
    assert _call(mcp_url, gateway_token, "get_device_status", {"cpe_sn": "CPE-5521"})["reason_code"] == \
        "UNAUTHENTICATED"
    wifi = _call(mcp_url, maya, "get_wifi_config", {"cpe_sn": "CPE-5521"})
    assert wifi["status"] == "ok" and "CANARY" not in json.dumps(wifi)
