"""Exercise the read tools not covered by selftest.py, against a live agent."""

import asyncio
import json

from trmm_mcp import server as srv
from trmm_mcp.client import TrmmError, client


async def try_tool(label, coro):
    try:
        result = await coro
        size = len(json.dumps(result, default=str))
        preview = json.dumps(result, default=str)[:130]
        print(f"  [OK]   {label:38} {size:>7} chars  {preview}")
        return True
    except TrmmError as exc:
        print(f"  [ERR]  {label:38} {exc}")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"  [FAIL] {label:38} {type(exc).__name__}: {exc}")
        return False


async def main():
    agents = await srv.trmm_list_agents()
    host = agents["agents"][0]["hostname"]
    print(f"\nSmoke-testing remaining read tools against {host}\n")

    ok = []
    ok.append(await try_tool("trmm_agent_services", srv.trmm_agent_services(host)))
    ok.append(await try_tool("trmm_agent_services(search=spool)",
                             srv.trmm_agent_services(host, search="spool")))
    ok.append(await try_tool("trmm_agent_processes", srv.trmm_agent_processes(host)))
    ok.append(await try_tool("trmm_agent_event_log",
                             srv.trmm_agent_event_log(host, "System", 1)))
    ok.append(await try_tool("trmm_agent_checks", srv.trmm_agent_checks(host)))
    ok.append(await try_tool("trmm_agent_history", srv.trmm_agent_history(host)))
    ok.append(await try_tool("trmm_agent_software", srv.trmm_agent_software(host)))
    ok.append(await try_tool("trmm_agent_windows_updates",
                             srv.trmm_agent_windows_updates(host)))
    ok.append(await try_tool("trmm_agent_tasks", srv.trmm_agent_tasks(host)))
    ok.append(await try_tool("trmm_pending_actions", srv.trmm_pending_actions()))
    ok.append(await try_tool("trmm_pending_actions(agent)",
                             srv.trmm_pending_actions(host)))
    ok.append(await try_tool("trmm_debug_log", srv.trmm_debug_log()))
    ok.append(await try_tool("trmm_get_script(1)", srv.trmm_get_script(1)))
    ok.append(await try_tool("trmm_get_agent(include=services)",
                             srv.trmm_get_agent(host, include=["services"])))
    ok.append(await try_tool("trmm_api_get(/checks/)", srv.trmm_api_get("/checks/")))
    ok.append(await try_tool("trmm_api_get(/automation/policies/)",
                             srv.trmm_api_get("/automation/policies/")))

    await client.aclose()
    print(f"\n{sum(ok)}/{len(ok)} tools returned successfully")


asyncio.run(main())
