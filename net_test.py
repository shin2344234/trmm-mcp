"""Test the networked HTTP mode: LAN binding, bearer auth, host validation."""

import asyncio
import json
import os
import subprocess
import sys
import time

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

HOST = os.environ.get("TEST_HOST", "127.0.0.1")
# Deliberately not 8770: the systemd service owns that, and binding over it
# silently tests the running service instead of this subprocess.
PORT = os.environ.get("TEST_PORT", "8778")
from trmm_mcp import config as _cfg
SCHEME = _cfg.SCHEME
VERIFY = _cfg.TLS_CERT if _cfg.TLS_ENABLED else True
URL = f"{SCHEME}://{HOST}:{PORT}/mcp"
TOKEN = ""
for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
    if line.startswith("TRMM_MCP_AUTH_TOKEN="):
        TOKEN = line.split("=", 1)[1].strip()

results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail else ""))


async def main():
    env = {**os.environ, "TRMM_MCP_MODE": "readonly",
           "TRMM_MCP_TRANSPORT": "streamable-http",
           "TRMM_MCP_HTTP_HOST": HOST, "TRMM_MCP_HTTP_PORT": PORT}
    proc = subprocess.Popen(
        [sys.executable, "-m", "trmm_mcp.server"],
        cwd=os.path.dirname(os.path.abspath(__file__)), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        up = False
        for _ in range(60):
            try:
                httpx.get(URL, timeout=1, verify=VERIFY)
                up = True
                break
            except httpx.HTTPError:
                time.sleep(0.25)
        check(f"listening on {HOST}:{PORT}", up)
        if not up:
            raise SystemExit(1)

        # No credentials at all
        r = httpx.post(URL, verify=VERIFY, json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                       timeout=5)
        check("unauthenticated request refused", r.status_code == 403,
              f"HTTP {r.status_code}")

        # Wrong token
        r = httpx.post(URL, verify=VERIFY, headers={"Authorization": "Bearer wrong-token"},
                       json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                       timeout=5)
        check("wrong token refused", r.status_code == 403, f"HTTP {r.status_code}")

        # A 401+WWW-Authenticate would make mcp-remote start an OAuth browser flow
        check("no OAuth challenge sent on refusal",
              "www-authenticate" not in {k.lower() for k in r.headers},
              f"headers={list(r.headers.keys())[:4]}")

        # Correct token, full protocol over the LAN address
        http_client = httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, verify=VERIFY)
        async with streamable_http_client(URL, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                check("authenticated handshake over LAN IP",
                      init.server_info.name == "tacticalrmm",
                      f"{init.server_info.name} v{init.server_info.version}")

                tools = await session.list_tools()
                check("tool list", len(tools.tools) == 20, f"{len(tools.tools)} tools")

                res = await session.call_tool("trmm_fleet_overview", {})
                data = json.loads(res.content[0].text)
                check("tool call returns live data", "totals" in data,
                      json.dumps(data["totals"]))
        await http_client.aclose()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print()
    if all(results):
        print(f"ALL GREEN ({len(results)} checks)")
    else:
        print(f"FAILED: {results.count(False)} of {len(results)}")
        sys.exit(1)


asyncio.run(main())
