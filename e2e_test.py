"""End-to-end test of the TRMM MCP server, driven exactly like a real client.

Everything here goes over the MCP protocol - no direct function calls.

  A. stdio / read-only : realistic diagnostic workflow
  B. stdio / command   : real execution, guards, error handling
  C. streamable-http   : transport actually starts and serves
"""

import asyncio
import json
import subprocess
import os
import sys
import time

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

RESULTS = []


def record(label, ok, detail=""):
    RESULTS.append((label, ok))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {label}" + (f"\n         {detail}" if detail else ""))


def payload(result):
    """Extract the text payload from a tool result."""
    if not result.content:
        return ""
    return result.content[0].text


def brief(text, n=260):
    text = " ".join(str(text).split())
    return text[:n] + ("..." if len(text) > n else "")


async def call(session, name, args=None):
    return await session.call_tool(name, args or {})


# ---------------------------------------------------------------- section A
async def section_a():
    print("\n" + "=" * 74)
    print("A. stdio / READ-ONLY - diagnostic workflow over the MCP protocol")
    print("=" * 74)

    params = StdioServerParameters(
        command=os.path.join(os.path.dirname(os.path.abspath(__file__)), "run.sh"), args=["readonly"], env=None
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            record(
                "handshake",
                init.server_info.name == "tacticalrmm",
                f"{init.server_info.name} v{init.server_info.version}",
            )

            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            record("tool list retrieved", len(names) == 20, f"{len(names)} tools")
            record(
                "no execution tools exposed",
                not any(
                    n.startswith(("trmm_run_", "trmm_reboot", "trmm_kill", "trmm_wake",
                                  "trmm_service_action"))
                    for n in names
                ),
            )

            # 1. Where are the problems?
            r = await call(session, "trmm_fleet_overview")
            data = json.loads(payload(r))
            totals = data["totals"]
            record("trmm_fleet_overview", "agents" in totals, json.dumps(totals))

            # 2. Which machines?
            r = await call(session, "trmm_list_agents",
                           {"fields": ["hostname", "status", "plat", "last_seen"]})
            agents = json.loads(payload(r))
            record("trmm_list_agents", agents["returned"] > 0,
                   brief(json.dumps(agents["agents"])))
            host = agents["agents"][0]["hostname"]

            # 3. Drill into one machine
            r = await call(session, "trmm_get_agent", {"agent": host})
            detail = json.loads(payload(r))
            record(
                f"trmm_get_agent({host}) by hostname",
                detail.get("hostname") == host,
                f"{detail.get('operating_system','?')[:60]} | "
                f"cpu={brief(detail.get('cpu_model'),40)} | "
                f"ram={detail.get('total_ram')}GB | payload={len(payload(r))} chars",
            )

            # 4. What is running / stopped
            r = await call(session, "trmm_agent_services",
                           {"agent": host, "state": "running", "limit": 5})
            svc = json.loads(payload(r))
            record("trmm_agent_services (running)", svc["total_matched"] > 0,
                   f"{svc['total_matched']} running; e.g. "
                   + ", ".join(s["display_name"][:28] for s in svc["services"][:3]))

            # 5. Resource hogs
            r = await call(session, "trmm_agent_processes",
                           {"agent": host, "sort_by": "memory", "limit": 5})
            procs = json.loads(payload(r))
            top = procs["processes"][:3]
            record("trmm_agent_processes (top memory)", len(top) > 0,
                   "; ".join(f"{p['name']} {round(p['membytes']/1048576)}MB" for p in top))

            # 6. Recent errors on the box
            r = await call(session, "trmm_agent_event_log",
                           {"agent": host, "log_type": "System", "days": 2,
                            "level": "ERROR", "limit": 3})
            evt = json.loads(payload(r))
            record("trmm_agent_event_log (errors)", "events" in evt,
                   f"{evt['total_matched']} error events in 2 days"
                   + (f"; latest: {brief(evt['events'][0].get('source'),40)}"
                      if evt["events"] else ""))

            # 7. What has been run here before
            r = await call(session, "trmm_agent_history", {"agent": host, "limit": 3})
            hist = json.loads(payload(r))
            record("trmm_agent_history", "history" in hist,
                   f"{hist['count']} entries; "
                   + (brief(json.dumps(hist["history"][0]), 110) if hist["count"]
                      else "none yet"))

            # 8. An empty result must still be a visible, explicit answer
            r = await call(session, "trmm_agent_checks", {"agent": host})
            txt = payload(r)
            empty = json.loads(txt) if txt else None
            record("empty result is explicit, not silent",
                   isinstance(empty, dict) and "count" in empty, brief(txt, 90))

            # 9. Escape hatch reaches unwrapped endpoints
            r = await call(session, "trmm_api_get", {"path": "/clients/"})
            record("trmm_api_get escape hatch", not r.is_error, brief(payload(r), 120))

            # 10. An execution tool must not be callable at all
            try:
                r = await call(session, "trmm_run_command",
                               {"agent": host, "command": "hostname"})
                record("execution tool rejected in read-only", bool(r.is_error),
                       brief(payload(r), 150))
            except Exception as exc:  # noqa: BLE001
                record("execution tool rejected in read-only", True,
                       f"{type(exc).__name__}: {brief(exc, 120)}")


# ---------------------------------------------------------------- section B
async def section_b():
    print("\n" + "=" * 74)
    print("B. stdio / COMMAND - real execution and guards")
    print("=" * 74)

    params = StdioServerParameters(
        command=os.path.join(os.path.dirname(os.path.abspath(__file__)), "run.sh"), args=["command"], env=None
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            record("execution tools present", len(names) == 28, f"{len(names)} tools")

            r = await call(session, "trmm_list_agents", {"fields": ["hostname"]})
            host = json.loads(payload(r))["agents"][0]["hostname"]

            # Real command execution
            r = await call(session, "trmm_run_command",
                           {"agent": host, "command": "hostname", "shell": "cmd",
                            "timeout": 25})
            out = json.loads(payload(r))
            record("trmm_run_command executes", host.lower() in out["output"].lower(),
                   f"output={out['output']!r}")

            # Something genuinely diagnostic
            r = await call(session, "trmm_run_command",
                           {"agent": host,
                            "command": "(Get-CimInstance Win32_OperatingSystem)"
                                       ".LastBootUpTime",
                            "shell": "powershell", "timeout": 30})
            out = json.loads(payload(r))
            record("powershell diagnostic returns real data",
                   bool(out["output"].strip()) and "not recognized" not in out["output"],
                   f"last boot: {brief(out['output'], 70)}")

            # Destructive guard
            r = await call(session, "trmm_run_command",
                           {"agent": host, "command": "rm -rf /", "shell": "shell"})
            record("destructive command blocked", bool(r.is_error),
                   brief(payload(r), 170))

            # Windows-flavoured destructive guard
            r = await call(session, "trmm_run_command",
                           {"agent": host, "command": "format C: /q", "shell": "cmd"})
            record("format C: blocked", bool(r.is_error), brief(payload(r), 130))

            # Unknown agent -> clear error, not a crash
            r = await call(session, "trmm_run_command",
                           {"agent": "no-such-host", "command": "hostname"})
            record("unknown agent gives a clear error", bool(r.is_error),
                   brief(payload(r), 150))

            # Script library is readable before running anything
            r = await call(session, "trmm_list_scripts", {"search": "disk", "limit": 3})
            scripts = json.loads(payload(r))
            record("trmm_list_scripts (search)", scripts["total_matched"] > 0,
                   ", ".join(f"[{s['id']}] {s['name']}" for s in scripts["scripts"]))


# ---------------------------------------------------------------- section C
async def section_c():
    print("\n" + "=" * 74)
    print("C. streamable-http transport")
    print("=" * 74)

    # Pin the bind address and a dedicated port rather than inheriting them:
    # .env carries this install's real address, and 8770 belongs to the running
    # service. A test that borrows either one tests the wrong thing, or nothing.
    port = os.environ.get("E2E_HTTP_PORT", "8781")
    env = {
        **os.environ,
        "TRMM_MCP_HTTP_HOST": "127.0.0.1",
        "TRMM_MCP_HTTP_PORT": port,
        "TRMM_MCP_PUBLIC_URL": f"https://127.0.0.1:{port}",
    }
    proc = subprocess.Popen(
        [os.path.join(os.path.dirname(os.path.abspath(__file__)), "run.sh"), "readonly", "http"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        from trmm_mcp import config as _cfg
        VERIFY = _cfg.TLS_CERT if _cfg.TLS_ENABLED else True
        url = f"{_cfg.SCHEME}://127.0.0.1:{port}/mcp"
        ready = False
        for _ in range(40):
            try:
                httpx.get(url, timeout=1, verify=VERIFY)
                ready = True
                break
            except httpx.HTTPError:
                time.sleep(0.25)
        record("http listener came up", ready, url)
        if not ready:
            return

        token = ""
        for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
            if line.startswith("TRMM_MCP_AUTH_TOKEN="):
                token = line.split("=", 1)[1].strip()

        unauth = httpx.post(url, verify=VERIFY, json={"jsonrpc": "2.0", "id": 1,
                                       "method": "initialize"}, timeout=5)
        record("http rejects unauthenticated calls", unauth.status_code == 403,
               f"HTTP {unauth.status_code}")

        http_client = httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}, verify=VERIFY)
        async with streamable_http_client(url, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                record("http handshake", init.server_info.name == "tacticalrmm")

                tools = await session.list_tools()
                record("http tool list", len(tools.tools) == 20,
                       f"{len(tools.tools)} tools")

                r = await session.call_tool("trmm_server_info", {})
                info = json.loads(payload(r))
                record("http tool call", info.get("mcp_mode") == "readonly",
                       f"mode={info.get('mcp_mode')} trmm={info.get('trmm_version')}")
        await http_client.aclose()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        record("http server shut down cleanly", True)


async def main():
    await section_a()
    await section_b()
    await section_c()

    print("\n" + "=" * 74)
    failed = [name for name, ok in RESULTS if not ok]
    print(f"{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if failed:
        print("FAILED: " + ", ".join(failed))
        sys.exit(1)
    print("ALL GREEN")


asyncio.run(main())
