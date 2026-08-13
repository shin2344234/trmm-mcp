"""End-to-end test of elevate mode: refuse, approve out-of-band, run once, revert."""

import asyncio
import json
import os
import subprocess
import sys
import time

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trmm_mcp import elevation  # noqa: E402

results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"\n         {detail}" if detail else ""))


def payload(res):
    return res.content[0].text if res.content else ""


async def main():
    elevation.revoke_all()
    print("\n=== elevate mode: stdio ===\n")

    env = {**os.environ, "TRMM_MCP_MODE": "elevate"}
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "trmm_mcp.server"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        env=env,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            check("execution tools are visible in elevate mode",
                  "trmm_run_command" in tools, f"{len(tools)} tools")

            host = json.loads(payload(
                await session.call_tool("trmm_list_agents", {"fields": ["hostname"]})
            ))["agents"][0]["hostname"]

            # Reads must work with no approval at all.
            res = await session.call_tool("trmm_fleet_overview", {})
            check("reads need no approval", not res.is_error)

            # First execution attempt must be refused.
            args = {"agent": host, "command": "hostname", "shell": "cmd", "timeout": 20}
            res = await session.call_tool("trmm_run_command", args)
            text = payload(res)
            check("execution refused without approval", res.is_error and "APPROVAL REQUIRED" in text)
            check("refusal tells the user where to approve", "/approve/" in text,
                  text.split("\n")[4].strip() if len(text.split("\n")) > 4 else text[:80])

            pending = [p for p in elevation.snapshot()["pending"] if p["status"] == "pending"]
            check("a pending request was recorded", len(pending) == 1,
                  pending[0]["summary"] if pending else "none")

            # The model cannot approve: nothing in the tool list can grant.
            check("no tool exists that grants approval",
                  not any("approve" in t or "elevat" in t or "grant" in t for t in tools))

            # Approve out of band, exactly as a human would.
            elevation.approve(pending[0]["id"])

            res = await session.call_tool("trmm_run_command", args)
            out = json.loads(payload(res)) if not res.is_error else {}
            check("runs once after approval",
                  not res.is_error and host.lower() in out.get("output", "").lower(),
                  f"output={out.get('output')!r}")

            # The approval must be spent, not sticky.
            res = await session.call_tool("trmm_run_command", args)
            check("approval is consumed - second run refused",
                  res.is_error and "APPROVAL REQUIRED" in payload(res))

            # An approval must not transfer to a different command.
            elevation.revoke_all()
            benign = {"agent": host, "command": "hostname", "shell": "cmd", "timeout": 20}
            res = await session.call_tool("trmm_run_command", benign)
            pend = [p for p in elevation.snapshot()["pending"] if p["status"] == "pending"]
            elevation.approve(pend[0]["id"])
            nasty = {"agent": host, "command": "whoami", "shell": "cmd", "timeout": 20}
            res = await session.call_tool("trmm_run_command", nasty)
            check("approval does not transfer to a different command",
                  res.is_error and "APPROVAL REQUIRED" in payload(res))

            # A window covers a burst of work, then lapses.
            elevation.revoke_all()
            elevation.open_window(60, uses=1)
            res = await session.call_tool("trmm_run_command", benign)
            check("window allows a run without individual approval", not res.is_error)
            res = await session.call_tool("trmm_run_command", nasty)
            check("window with 1 use is exhausted afterwards",
                  res.is_error and "APPROVAL REQUIRED" in payload(res))

            elevation.revoke_all()

    # Web approval page
    print("\n=== approval web page ===\n")
    token = ""
    for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
        if line.startswith("TRMM_MCP_AUTH_TOKEN="):
            token = line.split("=", 1)[1].strip()

    # Blank the approval-page credentials so this exercises the token fallback
    # deterministically, whether or not a password + 2FA is enrolled for real.
    # (approval_auth_test.py covers the password + 2FA path.)
    env = {**os.environ, "TRMM_MCP_MODE": "elevate",
           "TRMM_MCP_TRANSPORT": "streamable-http",
           "TRMM_MCP_HTTP_HOST": "127.0.0.1", "TRMM_MCP_HTTP_PORT": "8771",
           "TRMM_MCP_APPROVAL_PASSWORD_HASH": "",
           "TRMM_MCP_APPROVAL_TOTP_SECRET": ""}
    proc = subprocess.Popen(
        [sys.executable, "-m", "trmm_mcp.server"],
        cwd=os.path.dirname(os.path.abspath(__file__)), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        from trmm_mcp import config as _cfg
        VERIFY = _cfg.TLS_CERT if _cfg.TLS_ENABLED else True
        base = f"{_cfg.SCHEME}://127.0.0.1:8771"
        up = False
        for _ in range(60):
            try:
                httpx.get(f"{base}/approve/", timeout=1, verify=VERIFY)
                up = True
                break
            except httpx.HTTPError:
                time.sleep(0.25)
        check("approval page is served", up)

        r = httpx.get(f"{base}/approve/", timeout=5, verify=VERIFY)
        check("approval page requires signing in first",
              r.status_code == 200 and "Sign in" in r.text)

        with httpx.Client(base_url=base, timeout=5, follow_redirects=True, verify=VERIFY) as c:
            r = c.post("/approve/login", data={"token": "wrong"})
            check("wrong token rejected at the approval page",
                  "not correct" in r.text)

            r = c.post("/approve/login", data={"token": token})
            check("correct token unlocks the page", "Sign out" in r.text)

            record = elevation.request(
                "trmm_run_command", "Run on workstation-01 (cmd): hostname",
                {"agent_id": "x", "command": "hostname"},
            )
            r = c.get("/approve/")
            check("pending request is shown with the exact command",
                  record["id"] in r.text or "hostname" in r.text)

            c.post(f"/approve/approve/{record['id']}")
            state = elevation.snapshot()
            check("clicking approve marks it approved",
                  any(p["id"] == record["id"] and p["status"] == "approved"
                      for p in state["pending"]))

            c.post("/approve/revoke")
            check("revoke clears everything",
                  not elevation.snapshot()["pending"]
                  and not elevation.snapshot()["windows"])

        # The MCP endpoint must still demand its bearer token.
        r = httpx.post(f"{base}/mcp", verify=VERIFY, json={"jsonrpc": "2.0", "id": 1,
                                            "method": "initialize"}, timeout=5)
        check("mcp endpoint still requires bearer auth", r.status_code == 403,
              f"HTTP {r.status_code}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        elevation.revoke_all()

    print()
    if all(results):
        print(f"ALL GREEN ({len(results)} checks)")
    else:
        print(f"FAILED: {results.count(False)} of {len(results)}")
        sys.exit(1)


asyncio.run(main())
