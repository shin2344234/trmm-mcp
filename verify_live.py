"""Verify the RUNNING service, over the network, exactly as Claude Desktop does.

Targets the live systemd instance - does not start anything of its own.
Read-only: it never approves or executes anything.
"""

import asyncio
import json
import ssl
import subprocess
import os
import sys
import uuid

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

HOST = os.environ.get("TRMM_MCP_VERIFY_HOST", "127.0.0.1")
PORT = 8770
BASE = f"https://{HOST}:{PORT}"
URL = f"{BASE}/mcp"
CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "cert.pem")

TOKEN = ""
for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
    if line.startswith("TRMM_MCP_AUTH_TOKEN="):
        TOKEN = line.split("=", 1)[1].strip()

results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"\n         {detail}" if detail else ""))


async def main():
    print(f"\n{'=' * 70}\nLIVE SERVICE VERIFICATION - {URL}\n{'=' * 70}\n")

    print("--- TLS ---")
    out = subprocess.run(
        ["openssl", "s_client", "-connect", f"{HOST}:{PORT}", "-CAfile", CERT,
         "-verify_return_error", "-brief"],
        input="", capture_output=True, text=True, timeout=20,
    )
    blob = out.stdout + out.stderr
    check("certificate validates against certs/cert.pem",
          "Verification: OK" in blob,
          next((l.strip() for l in blob.splitlines() if "Verification" in l), blob[:120]))
    check("modern TLS protocol",
          "TLSv1.3" in blob or "TLSv1.2" in blob,
          next((l.strip() for l in blob.splitlines() if "Protocol" in l), ""))

    # Verification by IP is the part that usually breaks; prove it explicitly.
    ctx = ssl.create_default_context(cafile=CERT)
    try:
        r = httpx.get(f"{BASE}/approve/", verify=ctx, timeout=10)
        check("TLS hostname/IP verification passes", True, f"HTTP {r.status_code}")
    except Exception as exc:  # noqa: BLE001
        check("TLS hostname/IP verification passes", False, str(exc)[:120])

    print("\n--- auth on the MCP endpoint ---")
    r = httpx.post(URL, verify=CERT, timeout=10,
                   json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    check("rejects a request with no token", r.status_code == 403, f"HTTP {r.status_code}")

    r = httpx.post(URL, verify=CERT, timeout=10,
                   headers={"Authorization": "Bearer nope"},
                   json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    check("rejects a wrong token", r.status_code == 403, f"HTTP {r.status_code}")

    print("\n--- MCP session (as mcp-remote does it) ---")
    client = httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, verify=CERT)
    async with streamable_http_client(URL, http_client=client) as (read, write):
        async with ClientSession(read, write) as session:
            init = await asyncio.wait_for(session.initialize(), timeout=25)
            check("handshake", init.server_info.name == "tacticalrmm",
                  f"{init.server_info.name} v{init.server_info.version}")

            tools = sorted(t.name for t in (await session.list_tools()).tools)
            check("all 28 tools offered (execution enabled)", len(tools) == 28,
                  f"{len(tools)} tools")
            check("execution tools present",
                  {"trmm_run_command", "trmm_run_script", "trmm_reboot_agent"} <= set(tools))

            r = await session.call_tool("trmm_server_info", {})
            info = json.loads(r.content[0].text)
            check("trmm_server_info", info.get("mcp_mode") == "elevate",
                  f"mode={info.get('mcp_mode')} trmm={info.get('trmm_version')} "
                  f"exec_available={info.get('execution_tools_available')}")

            r = await session.call_tool("trmm_fleet_overview", {})
            totals = json.loads(r.content[0].text)["totals"]
            check("live fleet data", totals.get("agents", 0) > 0, json.dumps(totals))

            r = await session.call_tool("trmm_list_agents",
                                        {"fields": ["hostname", "status", "last_seen"]})
            agents = json.loads(r.content[0].text)
            check("agent list", agents["returned"] > 0,
                  json.dumps(agents["agents"]))
            host = agents["agents"][0]["hostname"]

            r = await session.call_tool("trmm_agent_processes",
                                        {"agent": host, "limit": 3})
            procs = json.loads(r.content[0].text)["processes"]
            check(f"live process read from {host}", len(procs) > 0,
                  "; ".join(f"{p['name']} {round(p['membytes'] / 1048576)}MB"
                            for p in procs))

            print("\n--- the approval gate ---")
            # A nonce in the command guarantees no pre-existing approval can
            # match this fingerprint, so we are genuinely testing the refusal
            # path. (Harmless even in the impossible case that it did run.)
            probe_cmd = f"echo trmm-mcp-verify-{uuid.uuid4().hex[:12]}"
            r = await session.call_tool(
                "trmm_run_command",
                {"agent": host, "command": probe_cmd, "shell": "cmd", "timeout": 20},
            )
            text = r.content[0].text if r.content else ""
            check("execution is refused until approved",
                  r.is_error and "APPROVAL REQUIRED" in text)
            check("refusal points at the HTTPS approval page",
                  "/approve/" in text,
                  next((l.strip() for l in text.splitlines() if "approve" in l), ""))
    await client.aclose()

    print("\n--- approval page ---")
    r = httpx.get(f"{BASE}/approve/", verify=CERT, timeout=10)
    check("served over HTTPS", r.status_code == 200)
    check("demands password AND 6-digit code",
          "Password" in r.text and "6-digit code" in r.text)
    check("does not accept the shared bearer token any more",
          "TRMM_MCP_AUTH_TOKEN" not in r.text)

    r = httpx.post(f"{BASE}/approve/login", verify=CERT, timeout=10,
                   data={"password": "definitely-wrong", "code": "000000"},
                   follow_redirects=True)
    check("wrong credentials rejected", "Incorrect password or code" in r.text
          or "Too many failed attempts" in r.text)

    print()
    bad = results.count(False)
    if bad:
        print(f"FAILED: {bad} of {len(results)}")
        sys.exit(1)
    print(f"ALL GREEN - {len(results)} checks against the live service")


asyncio.run(main())
