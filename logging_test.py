"""Verify the server logs what it is asked to do, what it does, and what fails."""

import asyncio
import json
import os
import shutil
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

LOG_DIR = "/tmp/trmm-mcp-logtest"
results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"\n         {detail}" if detail else ""))


def read_events():
    path = os.path.join(LOG_DIR, "events.jsonl")
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


async def main():
    shutil.rmtree(LOG_DIR, ignore_errors=True)
    print("\n=== logging ===\n")

    env = {**os.environ, "TRMM_MCP_MODE": "elevate", "TRMM_MCP_LOG_DIR": LOG_DIR}
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "trmm_mcp.server"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        env=env,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            r = await session.call_tool("trmm_list_agents", {"fields": ["hostname"]})
            host = json.loads(r.content[0].text)["agents"][0]["hostname"]

            # A refused execution.
            await session.call_tool(
                "trmm_run_command",
                {"agent": host, "command": "hostname", "shell": "cmd", "timeout": 20},
            )
            # A blocked destructive command.
            await session.call_tool(
                "trmm_run_command",
                {"agent": host, "command": "format C: /q", "shell": "cmd"},
            )
            # An outright failure.
            await session.call_tool("trmm_get_agent", {"agent": "nope-not-real"})
            # A raw API read.
            await session.call_tool("trmm_api_get", {"path": "/core/version/"})

    events = read_events()
    kinds = [e["kind"] for e in events]
    check("events.jsonl written", bool(events), f"{len(events)} events")
    check("startup recorded", "startup" in kinds)

    requests = [e for e in events if e["kind"] == "request" and e.get("tool")]
    check("every tool call is logged with its name",
          {"trmm_list_agents", "trmm_run_command", "trmm_get_agent", "trmm_api_get"}
          <= {e["tool"] for e in requests},
          f"tools seen: {sorted({e['tool'] for e in requests})}")

    args_logged = [e for e in requests if e.get("arguments")]
    check("tool arguments are captured", bool(args_logged),
          json.dumps(args_logged[0]["arguments"])[:110])

    responses = [e for e in events if e["kind"] == "response"]
    check("responses logged with duration", bool(responses)
          and all("duration_ms" in e for e in responses),
          f"{len(responses)} responses, e.g. {responses[0].get('duration_ms')}ms")

    check("results are captured", any(e.get("result") for e in responses))

    api = [e for e in events if e["kind"] == "api_call"]
    check("read API calls are logged (not just mutations)",
          any(e["method"] == "GET" for e in api),
          f"{len(api)} api calls, e.g. {api[0]['method']} {api[0]['path']} -> {api[0].get('status')}")

    check("elevation refusal logged",
          any(e["kind"] == "elevation_required" for e in events))
    check("blocked destructive command logged",
          any(e["kind"] == "blocked" and e.get("reason") == "destructive-pattern"
              for e in events))

    failures = [e for e in events if e["kind"] == "response" and not e.get("ok")]
    check("failed calls recorded as not-ok", bool(failures),
          f"{len(failures)} failed results")

    # Secrets must never appear.
    raw = open(os.path.join(LOG_DIR, "events.jsonl")).read()
    credential_vars = (
        "TRMM_READONLY_API_KEY", "TRMM_COMMAND_API_KEY", "TRMM_MCP_AUTH_TOKEN",
    )
    secrets = []
    for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
        if "=" in line and not line.startswith("#"):
            name, value = line.split("=", 1)
            if name.strip() in credential_vars and len(value.strip()) > 12:
                secrets.append(value.strip())
    leaked = [s for s in secrets if s in raw]
    check("no credentials leaked into the log", not leaked,
          f"checked {len(secrets)} secrets")

    check("server.log exists for diagnostics",
          os.path.exists(os.path.join(LOG_DIR, "server.log")))

    mode = oct(os.stat(os.path.join(LOG_DIR, "events.jsonl")).st_mode)[-3:]
    check("log files are not world-readable", mode == "600", f"mode {mode}")

    print()
    if all(results):
        print(f"ALL GREEN ({len(results)} checks)")
    else:
        print(f"FAILED: {results.count(False)} of {len(results)}")
        sys.exit(1)


asyncio.run(main())
