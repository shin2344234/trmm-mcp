"""Self-test for the TRMM MCP server. Run once per mode.

    TRMM_MCP_MODE=readonly venv/bin/python selftest.py
    TRMM_MCP_MODE=command  venv/bin/python selftest.py
"""

import asyncio
import json
import sys

from trmm_mcp import config, server as srv
from trmm_mcp.client import TrmmError, client

EXEC_TOOLS = {
    "trmm_run_command",
    "trmm_run_script",
    "trmm_reboot_agent",
    "trmm_service_action",
    "trmm_kill_process",
    "trmm_wake_on_lan",
    "trmm_run_checks",
    "trmm_run_task",
}

failures = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail else ""))
    if not ok:
        failures.append(label)


async def main():
    print(f"\n=== TRMM MCP self-test (mode={config.MODE}) ===\n")

    tools = {t.name for t in await srv.server.list_tools()}
    print(f"registered tools ({len(tools)}): {', '.join(sorted(tools))}\n")

    exposed_exec = tools & EXEC_TOOLS
    if config.IS_READONLY:
        check("read-only mode exposes no execution tools", not exposed_exec,
              f"found {exposed_exec}" if exposed_exec else "")
    else:
        check("command mode exposes execution tools",
              exposed_exec == EXEC_TOOLS,
              f"missing {EXEC_TOOLS - exposed_exec}")

    info = await srv.trmm_server_info()
    check("trmm_server_info", info.get("trmm_version") is not None,
          f"version={info.get('trmm_version')}")

    overview = await srv.trmm_fleet_overview()
    totals = overview.get("totals", {})
    check("trmm_fleet_overview", "agents" in totals, json.dumps(totals))

    agents = await srv.trmm_list_agents()
    check("trmm_list_agents", agents.get("returned", 0) > 0,
          f"{agents.get('returned')} agents")

    first = agents["agents"][0]
    hostname = first["hostname"]

    detail = await srv.trmm_get_agent(hostname)
    check("trmm_get_agent by hostname", detail.get("hostname") == hostname)
    check("heavy sections omitted by default",
          "services" not in detail and "_omitted_sections" in detail,
          str(detail.get("_omitted_sections")))

    size = len(json.dumps(detail, default=str))
    check("agent detail is context-sized", size < 30000, f"{size} chars")

    try:
        await srv._resolve_agent("definitely-not-a-real-host")
        check("unknown hostname raises", False)
    except TrmmError:
        check("unknown hostname raises", True)

    clients = await srv.trmm_list_clients_sites()
    check("trmm_list_clients_sites", isinstance(clients, dict) and "clients" in clients,
          f"{clients.get('count')} clients")

    # A tool returning an empty list must still produce a visible, explicit
    # result rather than an empty payload the model cannot distinguish from a
    # failure.
    empty = await srv.trmm_agent_checks(hostname)
    check("empty results are explicit, not silent",
          isinstance(empty, dict) and "checks" in empty and "count" in empty,
          json.dumps(empty)[:80])

    alerts = await srv.trmm_list_alerts()
    check("trmm_list_alerts (PATCH path)", alerts is not None,
          f"count={alerts.get('alerts_count') if isinstance(alerts, dict) else 'n/a'}")

    audit = await srv.trmm_audit_log(days=30)
    check("trmm_audit_log (PATCH + pagination)",
          isinstance(audit, dict) and "audit_logs" in audit,
          f"total={audit.get('total') if isinstance(audit, dict) else '?'}")

    scripts = await srv.trmm_list_scripts()
    check("trmm_list_scripts", scripts.get("total_matched", 0) > 0,
          f"{scripts.get('total_matched')} scripts")

    raw = await srv.trmm_api_get("/core/version/")
    check("trmm_api_get escape hatch", raw is not None, str(raw))

    check("trailing slash is added automatically",
          await srv.trmm_api_get("/core/version") is not None)

    # The client guard must refuse writes in read-only mode even if a tool tried.
    if config.IS_READONLY:
        try:
            await client.post("/agents/xxx/cmd/", {"cmd": "hostname"})
            check("client guard blocks POST in read-only mode", False)
        except TrmmError as exc:
            check("client guard blocks POST in read-only mode",
                  "read-only" in str(exc))
    else:
        try:
            await srv.trmm_run_command(hostname, "rm -rf /")
            check("destructive command blocked", False)
        except TrmmError as exc:
            check("destructive command blocked", "blocked destructive" in str(exc))

        result = await srv.trmm_run_command(hostname, "hostname", shell="cmd", timeout=20)
        out = (result.get("output") or "").strip()
        check("trmm_run_command executes", bool(out), f"output={out!r}")

    await client.aclose()

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s): {failures}")
        sys.exit(1)
    print("All checks passed.")


asyncio.run(main())
