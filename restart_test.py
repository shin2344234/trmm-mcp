"""A server restart must not wedge a connected client.

Reproduces the failure the Claude Desktop bridge hit: with stateful streamable
HTTP the client keeps replaying a session id the restarted server has forgotten,
and every tool call hangs until it times out.
"""

import asyncio
import json
import os
import subprocess
import sys
import time

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

PORT = "8779"
from trmm_mcp import config as _cfg
SCHEME = _cfg.SCHEME
VERIFY = _cfg.TLS_CERT if _cfg.TLS_ENABLED else True
URL = f"{SCHEME}://127.0.0.1:{PORT}/mcp"
TOKEN = ""
for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
    if line.startswith("TRMM_MCP_AUTH_TOKEN="):
        TOKEN = line.split("=", 1)[1].strip()

results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail else ""))


def start(stateless: bool):
    env = {**os.environ, "TRMM_MCP_MODE": "elevate",
           "TRMM_MCP_TRANSPORT": "streamable-http",
           "TRMM_MCP_HTTP_HOST": "127.0.0.1", "TRMM_MCP_HTTP_PORT": PORT,
           "TRMM_MCP_STATELESS_HTTP": "true" if stateless else "false"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "trmm_mcp.server"],
        cwd=os.path.dirname(os.path.abspath(__file__)), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(80):
        try:
            httpx.get(URL, timeout=1, verify=VERIFY)
            return proc
        except httpx.HTTPError:
            time.sleep(0.25)
    return proc


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    time.sleep(1)


async def probe(session, label):
    """Call a tool with a hard timeout so a hang fails fast instead of stalling."""
    try:
        res = await asyncio.wait_for(session.call_tool("trmm_server_info", {}), timeout=20)
        return not res.is_error, json.loads(res.content[0].text).get("mcp_mode", "?")
    except asyncio.TimeoutError:
        return False, "HUNG (timed out)"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {str(exc)[:60]}"


async def scenario(stateless: bool):
    name = "stateless" if stateless else "stateful"
    print(f"\n=== {name} HTTP: restart under a live client ===")
    proc = start(stateless)
    try:
        http_client = httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, verify=VERIFY)
        async with streamable_http_client(URL, http_client=http_client) as (r, w):
            async with ClientSession(r, w) as session:
                await asyncio.wait_for(session.initialize(), timeout=20)
                ok, detail = await probe(session, "before")
                check(f"{name}: works before restart", ok, detail)

                stop(proc)
                proc2 = start(stateless)

                ok, detail = await probe(session, "after")
                if stateless:
                    check(f"{name}: still works after a server restart", ok, detail)
                else:
                    # Documents the old behaviour; not a pass/fail requirement.
                    print(f"  [info] {name} after restart -> "
                          f"{'worked' if ok else detail}")
                stop(proc2)
                proc = None
        await http_client.aclose()
    finally:
        if proc:
            stop(proc)


async def main():
    await scenario(stateless=False)
    await scenario(stateless=True)
    print()
    if all(results):
        print(f"ALL GREEN ({len(results)} checks)")
    else:
        print(f"FAILED: {results.count(False)} of {len(results)}")
        sys.exit(1)


asyncio.run(main())
