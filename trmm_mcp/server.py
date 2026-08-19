# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP tools for TacticalRMM.

Read tools are always available. Execution tools are only registered when the
server is started with TRMM_MCP_MODE=command, so in read-only mode the model
cannot even see that they exist.
"""

from __future__ import annotations

import hmac
import json
import logging
import time
from typing import Any

from mcp.server import MCPServer

from . import __version__, config, elevation, observability
from .client import TrmmError, client

observability.setup()

INSTRUCTIONS = f"""
TacticalRMM access for the fleet at {config.API_URL}.
Current mode: {config.MODE.upper()}.

Start troubleshooting with trmm_fleet_overview, then narrow with trmm_list_agents
and the per-agent tools. Anywhere an agent is requested you may pass either the
hostname or the agent_id; hostnames are resolved automatically.

TRMM has no pagination and some endpoints return whole tables, so these tools
project to useful fields by default. Ask for more with the include/fields
arguments when you need them, and use trmm_api_get for anything not covered by a
dedicated tool.

{"Execution tools are NOT available: this server is read-only." if config.IS_READONLY
 else "Execution tools ARE available. They act on real production machines: "
      "confirm the target with trmm_list_agents first, prefer the narrowest "
      "action, and read a script with trmm_get_script before running it."}
""".strip()

server = MCPServer(
    name="tacticalrmm",
    version=__version__,
    instructions=INSTRUCTIONS,
    middleware=[observability.logging_middleware],
)

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

AGENT_LIST_FIELDS = [
    "agent_id",
    "hostname",
    "client_name",
    "site_name",
    "status",
    "last_seen",
    "plat",
    "operating_system",
    "version",
    "needs_reboot",
    "has_patches_pending",
    "pending_actions_count",
    "maintenance_mode",
    "logged_username",
    "public_ip",
    "checks",
]

# Dropped from get_agent by default: on a real machine these were measured at
# 118 KB (services), 60 KB (wmi_detail) and 11 KB (all_timezones).
AGENT_HEAVY_FIELDS = {"services", "wmi_detail", "all_timezones", "graphics"}

_agent_cache: dict[str, Any] = {"at": 0.0, "rows": []}


def _project(row: dict, fields: list[str] | None) -> dict:
    if not fields:
        return row
    return {k: row.get(k) for k in fields if k in row}


def _cap(payload: Any) -> Any:
    """Truncate oversized payloads so one call cannot flood the context."""
    text = json.dumps(payload, default=str)
    if len(text) <= config.MAX_RESPONSE_CHARS:
        return payload
    return {
        "truncated": True,
        "note": (
            f"Response was {len(text)} chars, over the "
            f"{config.MAX_RESPONSE_CHARS} limit. Narrow the query (filters, "
            f"limit, or fields) to see the rest."
        ),
        "preview": text[: config.MAX_RESPONSE_CHARS],
    }


def _listing(key: str, rows: Any, **extra: Any) -> Any:
    """Wrap a result in a dict envelope.

    A tool that returns a bare list is emitted by MCP as one content block per
    item, and an empty list produces no content at all - so "nothing found"
    would be indistinguishable from a failed call. Always returning a dict keeps
    the output a single self-describing block with an explicit count.
    """
    if isinstance(rows, dict) and rows.get("truncated"):
        return rows
    if isinstance(rows, list):
        return {"count": len(rows), key: rows, **extra}
    return {key: rows, **extra}


async def _agent_rows(force: bool = False) -> list[dict]:
    if force or time.time() - _agent_cache["at"] > 60:
        rows = await client.get("/agents/", params={"detail": "false"})
        _agent_cache["rows"] = rows if isinstance(rows, list) else []
        _agent_cache["at"] = time.time()
    return _agent_cache["rows"]


async def _resolve_agent(identifier: str) -> str:
    """Accept an agent_id or a hostname and return the agent_id."""
    identifier = (identifier or "").strip()
    if not identifier:
        raise TrmmError("No agent specified.")

    rows = await _agent_rows()
    for row in rows:
        if row.get("agent_id") == identifier:
            return identifier

    matches = [r for r in rows if (r.get("hostname") or "").lower() == identifier.lower()]
    if not matches:
        matches = [
            r for r in rows if identifier.lower() in (r.get("hostname") or "").lower()
        ]

    if len(matches) == 1:
        return matches[0]["agent_id"]
    if len(matches) > 1:
        names = ", ".join(sorted(m.get("hostname", "?") for m in matches))
        raise TrmmError(f"{identifier!r} matches several agents: {names}. Be specific.")

    # Cache may be stale for a freshly enrolled agent.
    if _agent_cache["at"] and time.time() - _agent_cache["at"] > 5:
        await _agent_rows(force=True)
        return await _resolve_agent(identifier)
    raise TrmmError(f"No agent matches {identifier!r}. Use trmm_list_agents to see them.")


async def _enforce_agent_scope(agent_id: str) -> None:
    """Check the allowlist against the RESOLVED agent, never the typed input.

    Matching on what the caller typed is both too strict and too loose: an
    allowlist of hostnames rejects a legitimate call made by agent_id, while a
    substring like "PC-01" would satisfy the check and then resolve to "PC-011",
    a machine that is not on the list.
    """
    if not config.AGENT_ALLOWLIST:
        return

    hostname = ""
    for row in await _agent_rows():
        if row.get("agent_id") == agent_id:
            hostname = row.get("hostname") or ""
            break

    if agent_id in config.AGENT_ALLOWLIST or (
        hostname and hostname in config.AGENT_ALLOWLIST
    ):
        return
    raise TrmmError(
        f"Refused: agent {hostname or agent_id} is not in TRMM_MCP_AGENT_ALLOWLIST."
    )


RISK_DESTRUCTIVE = "destructive"
RISK_DISRUPTIVE = "disruptive"
RISK_ROUTINE = "routine"

_SHELL_NAMES = {
    "cmd": "Command Prompt",
    "powershell": "PowerShell",
    "shell": "shell",
    "python": "Python",
    "nushell": "Nushell",
    "deno": "Deno",
}


def _runs_as(run_as_user: bool) -> str:
    return "the logged-in user" if run_as_user else "SYSTEM (full privileges)"


async def _script_name(script_id: int) -> str:
    """Best-effort script name, so the page shows more than a bare number."""
    try:
        data = await client.get(f"/scripts/{script_id}/")
        if isinstance(data, dict) and data.get("name"):
            return str(data["name"])
    except TrmmError:
        pass
    return f"script #{script_id}"


async def _require_elevation(
    tool: str,
    summary: str,
    params: dict[str, Any],
    display: dict[str, Any] | None = None,
) -> str:
    """Gate a privileged call on an out-of-band approval.

    In elevate mode the model can ask, but only a human at the approval page or
    the CLI can grant, and the grant is bound to these exact arguments.
    """
    if not config.REQUIRE_APPROVAL:
        return "command mode: approval not required"

    allowed, reason = elevation.consume(tool, params)
    if allowed:
        observability.event(
            "elevation_granted", tool=tool, summary=summary, reason=reason,
            params=params,
        )
        return reason

    record = elevation.request(tool, summary, params, display=display)
    observability.event(
        "elevation_required", tool=tool, summary=summary, params=params,
        request_id=record["id"],
    )
    raise TrmmError(
        f"APPROVAL REQUIRED - this did not run.\n\n"
        f"  {summary}\n\n"
        f"Tell the user to approve it here:\n"
        f"  {config.PUBLIC_URL}/approve/\n\n"
        f"(request {record['id']}, expires in {config.PENDING_TTL // 60} minutes)\n\n"
        f"After they approve, call this tool again with exactly the same "
        f"arguments - the approval is bound to them, and is consumed by that "
        f"one run. Do not attempt to work around this."
    )


def _reject_blocked_command(cmd: str) -> None:
    for pattern in config.BLOCK_PATTERNS:
        if pattern.search(cmd):
            observability.event(
                "blocked", reason="destructive-pattern",
                pattern=pattern.pattern, command=cmd,
            )
            raise TrmmError(
                f"Refused: this command matches a blocked destructive pattern "
                f"({pattern.pattern!r}). Run it by hand if you are certain, or "
                f"adjust TRMM_MCP_BLOCK_PATTERNS."
            )


# --------------------------------------------------------------------------
# read tools
# --------------------------------------------------------------------------


@server.tool(
    description=(
        "Fleet health summary: agent counts by status, plus the machines that "
        "are offline, need a reboot, have failing checks, or have pending "
        "patches. The best first call when hunting for problems."
    )
)
async def trmm_fleet_overview() -> dict:
    agents = await client.get("/agents/")
    if not isinstance(agents, list):
        return {"error": "Unexpected response", "raw": agents}

    def summary(a: dict) -> dict:
        return {
            "hostname": a.get("hostname"),
            "agent_id": a.get("agent_id"),
            "client": a.get("client_name"),
            "site": a.get("site_name"),
            "status": a.get("status"),
            "last_seen": a.get("last_seen"),
        }

    offline = [summary(a) for a in agents if a.get("status") != "online"]
    reboot = [summary(a) for a in agents if a.get("needs_reboot")]
    patches = [summary(a) for a in agents if a.get("has_patches_pending")]
    maintenance = [summary(a) for a in agents if a.get("maintenance_mode")]

    failing = []
    for a in agents:
        checks = a.get("checks") or {}
        if checks.get("failing") or checks.get("warning"):
            failing.append({**summary(a), "checks": checks})

    pending = [
        {**summary(a), "pending_actions": a.get("pending_actions_count")}
        for a in agents
        if a.get("pending_actions_count")
    ]

    return _cap(
        {
            "totals": {
                "agents": len(agents),
                "online": sum(1 for a in agents if a.get("status") == "online"),
                "offline": len(offline),
                "needs_reboot": len(reboot),
                "patches_pending": len(patches),
                "with_failing_checks": len(failing),
                "in_maintenance": len(maintenance),
            },
            "offline_agents": offline,
            "agents_with_failing_checks": failing,
            "agents_needing_reboot": reboot,
            "agents_with_pending_patches": patches,
            "agents_with_pending_actions": pending,
            "agents_in_maintenance": maintenance,
        }
    )


@server.tool(
    description=(
        "List agents with their status. Filter by client/site id, monitoring "
        "type (server/workstation), online state, or a hostname substring."
    )
)
async def trmm_list_agents(
    client_id: int | None = None,
    site_id: int | None = None,
    monitoring_type: str | None = None,
    offline_only: bool = False,
    search: str | None = None,
    fields: list[str] | None = None,
    limit: int = 100,
) -> Any:
    params: dict[str, Any] = {}
    if site_id is not None:
        params["site"] = site_id
    elif client_id is not None:
        params["client"] = client_id
    if monitoring_type:
        params["monitoring_type"] = monitoring_type

    rows = await client.get("/agents/", params=params or None)
    if not isinstance(rows, list):
        return rows

    if offline_only:
        rows = [r for r in rows if r.get("status") != "online"]
    if search:
        needle = search.lower()
        rows = [r for r in rows if needle in (r.get("hostname") or "").lower()]

    total = len(rows)
    rows = rows[:limit]
    projected = [_project(r, fields or AGENT_LIST_FIELDS) for r in rows]
    return _cap(
        {"total_matched": total, "returned": len(projected), "agents": projected}
    )


@server.tool(
    description=(
        "Full detail for one agent: hardware, OS, disks, uptime, checks and "
        "policies. Heavy sections (services, wmi_detail, graphics, timezone "
        "list) are omitted unless named in `include`, since they can be >100KB."
    )
)
async def trmm_get_agent(agent: str, include: list[str] | None = None) -> Any:
    agent_id = await _resolve_agent(agent)
    data = await client.get(f"/agents/{agent_id}/")
    if not isinstance(data, dict):
        return data

    include = include or []
    if "all" in include:
        return _cap(data)

    trimmed = {
        k: v for k, v in data.items() if k not in AGENT_HEAVY_FIELDS or k in include
    }
    omitted = sorted(AGENT_HEAVY_FIELDS - set(include))
    if omitted:
        trimmed["_omitted_sections"] = omitted
        trimmed["_hint"] = (
            "Pass include=['services'] etc. to fetch these, or use "
            "trmm_agent_services / trmm_api_get."
        )
    return _cap(trimmed)


@server.tool(
    description=(
        "Windows services on an agent. Filter by name substring or state "
        "(running/stopped) to avoid pulling the whole list, which is large."
    )
)
async def trmm_agent_services(
    agent: str, search: str | None = None, state: str | None = None, limit: int = 60
) -> Any:
    agent_id = await _resolve_agent(agent)
    rows = await client.get(f"/services/{agent_id}/")
    if not isinstance(rows, list):
        return rows

    if search:
        needle = search.lower()
        rows = [
            r
            for r in rows
            if needle in (r.get("name") or "").lower()
            or needle in (r.get("display_name") or "").lower()
        ]
    if state:
        rows = [r for r in rows if (r.get("status") or "").lower() == state.lower()]

    total = len(rows)
    fields = ["name", "display_name", "status", "start_type", "pid", "username"]
    return _cap(
        {
            "total_matched": total,
            "services": [_project(r, fields) for r in rows[:limit]],
        }
    )


@server.tool(
    description=(
        "Live process list from an agent, sorted by memory or CPU. Requires the "
        "agent to be online."
    )
)
async def trmm_agent_processes(
    agent: str, sort_by: str = "memory", limit: int = 25
) -> Any:
    agent_id = await _resolve_agent(agent)
    rows = await client.get(f"/agents/{agent_id}/processes/")
    if not isinstance(rows, list):
        return rows

    key = "cpu_percent" if sort_by.lower().startswith("cpu") else "membytes"

    def sort_key(row: dict) -> float:
        try:
            return float(row.get(key) or 0)
        except (TypeError, ValueError):
            return 0.0

    rows.sort(key=sort_key, reverse=True)
    return _cap({"sorted_by": key, "processes": rows[:limit]})


@server.tool(
    description=(
        "Windows event log entries from an agent. log_type is Application, "
        "System or Security. Filter by level (error/warning/information) and "
        "an optional message substring."
    )
)
async def trmm_agent_event_log(
    agent: str,
    log_type: str = "Application",
    days: int = 1,
    level: str | None = None,
    search: str | None = None,
    limit: int = 40,
) -> Any:
    agent_id = await _resolve_agent(agent)
    rows = await client.get(f"/agents/{agent_id}/eventlog/{log_type}/{days}/")
    if not isinstance(rows, list):
        return rows

    if level:
        rows = [r for r in rows if (r.get("eventType") or "").lower() == level.lower()]
    if search:
        needle = search.lower()
        rows = [r for r in rows if needle in json.dumps(r, default=str).lower()]

    total = len(rows)
    return _cap({"total_matched": total, "events": rows[:limit]})


@server.tool(description="Checks configured on an agent, with their current status.")
async def trmm_agent_checks(agent: str, failing_only: bool = False) -> Any:
    agent_id = await _resolve_agent(agent)
    rows = await client.get(f"/agents/{agent_id}/checks/")
    if isinstance(rows, list) and failing_only:
        rows = [r for r in rows if (r.get("status") or "").lower() != "passing"]
    return _cap(_listing("checks", rows, agent=agent))


@server.tool(
    description=(
        "Recent command and script runs on an agent, including their captured "
        "output. Use this to see what was already tried, or to retrieve output "
        "from an asynchronous script run."
    )
)
async def trmm_agent_history(agent: str, limit: int = 15) -> Any:
    agent_id = await _resolve_agent(agent)
    rows = await client.get(f"/agents/{agent_id}/history/")
    if not isinstance(rows, list):
        return rows
    rows = sorted(rows, key=lambda r: r.get("time") or "", reverse=True)[:limit]
    return _cap(_listing("history", rows, agent=agent))


@server.tool(description="Installed software inventory for an agent.")
async def trmm_agent_software(agent: str, search: str | None = None) -> Any:
    agent_id = await _resolve_agent(agent)
    data = await client.get(f"/software/{agent_id}/")

    entries = data.get("software", []) if isinstance(data, dict) else data
    if isinstance(entries, list) and search:
        needle = search.lower()
        entries = [e for e in entries if needle in json.dumps(e, default=str).lower()]
    return _cap({"count": len(entries) if isinstance(entries, list) else None,
                 "software": entries})


@server.tool(description="Windows update status for an agent.")
async def trmm_agent_windows_updates(agent: str, pending_only: bool = True) -> Any:
    agent_id = await _resolve_agent(agent)
    data = await client.get(f"/winupdate/{agent_id}/")
    rows = data.get("winupdates", data) if isinstance(data, dict) else data
    if isinstance(rows, list) and pending_only:
        rows = [r for r in rows if not r.get("installed")]
    return _cap(_listing("updates", rows, agent=agent, pending_only=pending_only))


@server.tool(description="All clients and their sites, with ids for filtering.")
async def trmm_list_clients_sites() -> Any:
    return _cap(_listing("clients", await client.get("/clients/")))


@server.tool(
    description=(
        "Current alerts. By default returns the newest unresolved ones. "
        "severity may include 'error', 'warning', 'info'."
    )
)
async def trmm_list_alerts(
    top: int = 25,
    days: int | None = None,
    severity: list[str] | None = None,
    include_resolved: bool = False,
) -> Any:
    # TRMM queries alerts over PATCH with a filter body.
    if not include_resolved and not days and not severity:
        # This path already returns {"alerts_count": N, "alerts": [...]}.
        return _cap(await client.patch("/alerts/", {"top": top}))

    body: dict[str, Any] = {}
    if days:
        body["timeFilter"] = days
    if severity:
        body["severityFilter"] = severity
    # Quirk: TRMM only applies these filters when the value is false, in which
    # case they mean "hide resolved/snoozed".
    if not include_resolved:
        body["resolvedFilter"] = False
        body["snoozedFilter"] = False
    if not body:
        body["timeFilter"] = 30
    rows = await client.patch("/alerts/", body)
    if isinstance(rows, list):
        rows = rows[:top]
    return _cap(_listing("alerts", rows))


@server.tool(
    description=(
        "List scripts available in TRMM. Returns each script's id, which is "
        "what trmm_run_script needs."
    )
)
async def trmm_list_scripts(search: str | None = None, limit: int = 60) -> Any:
    rows = await client.get("/scripts/")
    if not isinstance(rows, list):
        return rows
    if search:
        needle = search.lower()
        rows = [
            r
            for r in rows
            if needle in (r.get("name") or "").lower()
            or needle in (r.get("description") or "").lower()
        ]
    fields = [
        "id",
        "name",
        "description",
        "shell",
        "script_type",
        "supported_platforms",
        "default_timeout",
        "args",
        "category",
    ]
    total = len(rows)
    return _cap(
        {"total_matched": total, "scripts": [_project(r, fields) for r in rows[:limit]]}
    )


@server.tool(
    description=(
        "Full detail for one script including its source code. Read this "
        "before running an unfamiliar script on a machine."
    )
)
async def trmm_get_script(script_id: int) -> Any:
    return _cap(_listing("script", await client.get(f"/scripts/{script_id}/")))


@server.tool(description="Automated tasks configured on an agent.")
async def trmm_agent_tasks(agent: str) -> Any:
    agent_id = await _resolve_agent(agent)
    return _cap(
        _listing("tasks", await client.get(f"/agents/{agent_id}/tasks/"), agent=agent)
    )


@server.tool(
    description=(
        "Pending actions (queued agent work such as reboots or patch installs). "
        "Omit `agent` for the whole fleet."
    )
)
async def trmm_pending_actions(agent: str | None = None) -> Any:
    if agent:
        agent_id = await _resolve_agent(agent)
        rows = await client.get(f"/agents/{agent_id}/pendingactions/")
        return _cap(_listing("pending_actions", rows, agent=agent))
    return _cap(_listing("pending_actions", await client.get("/logs/pendingactions/")))


@server.tool(
    description=(
        "Audit log: who did what in TRMM. Filter by days, agent, or username. "
        "Useful for correlating a change with when a problem started."
    )
)
async def trmm_audit_log(
    days: int = 7,
    agent: str | None = None,
    username: str | None = None,
    page: int = 1,
    rows_per_page: int = 25,
    full: bool = False,
) -> Any:
    body: dict[str, Any] = {
        "pagination": {
            "page": page,
            "rowsPerPage": rows_per_page,
            "sortBy": "entry_time",
            "descending": True,
        },
        "timeFilter": days,
    }
    if agent:
        body["agentFilter"] = [await _resolve_agent(agent)]
    if username:
        body["userFilter"] = [username]

    data = await client.patch("/logs/audit/", body)
    if full or not isinstance(data, dict):
        return _cap(data)

    # before_value/after_value carry whole serialized objects on edit entries,
    # which can push a page of results past 100KB. Keep the narrative fields.
    fields = ["id", "entry_time", "username", "agent", "object_type", "action",
              "message", "ip_address"]
    rows = data.get("audit_logs")
    if isinstance(rows, list):
        data = {
            **data,
            "audit_logs": [_project(r, fields) for r in rows],
            "_note": "before/after values omitted; pass full=true for everything",
        }
    return _cap(data)


@server.tool(description="TRMM server debug log entries.")
async def trmm_debug_log(days: int = 3, log_level: str = "error") -> Any:
    body = {
        "pagination": {
            "page": 1,
            "rowsPerPage": 50,
            "sortBy": "entry_time",
            "descending": True,
        },
        "logLevelFilter": log_level,
        "timeFilter": days,
    }
    try:
        return _cap(_listing("debug_log", await client.patch("/logs/debug/", body)))
    except TrmmError:
        return _cap(_listing("debug_log", await client.get("/logs/debug/")))


@server.tool(
    description="TRMM server version, settings and this MCP server's current mode."
)
async def trmm_server_info() -> Any:
    info: dict[str, Any] = {
        "mcp_mode": config.MODE,
        "execution_tools_available": not config.IS_READONLY,
        "api_url": config.API_URL,
    }
    try:
        info["trmm_version"] = await client.get("/core/version/")
    except TrmmError as exc:
        info["trmm_version_error"] = str(exc)
    try:
        info["dashboard_info"] = await client.get("/core/dashinfo/")
    except TrmmError as exc:
        info["dashboard_info_error"] = str(exc)
    if config.AGENT_ALLOWLIST:
        info["agent_allowlist"] = sorted(config.AGENT_ALLOWLIST)
    return info


@server.tool(
    description=(
        "Escape hatch: issue a raw GET against any TRMM API path and return the "
        "JSON, for data with no dedicated tool. Example paths: /clients/, "
        "/checks/, /automation/policies/, /core/customfields/, /accounts/. "
        "Always permitted, in both modes."
    )
)
async def trmm_api_get(path: str, params: dict[str, Any] | None = None) -> Any:
    return _cap(_listing("result", await client.get(path, params=params), path=path))


# --------------------------------------------------------------------------
# execution tools - registered only in command mode
# --------------------------------------------------------------------------

if config.EXEC_TOOLS_ENABLED:

    @server.tool(
        description=(
            "Run a shell command on an agent and return its output. shell is "
            "'cmd' or 'powershell' on Windows; on Linux/macOS pass 'shell'. "
            "The agent must be online. Every call is written to the audit log."
        )
    )
    async def trmm_run_command(
        agent: str,
        command: str,
        shell: str = "cmd",
        timeout: int = 60,
        run_as_user: bool = False,
    ) -> Any:
        agent_id = await _resolve_agent(agent)
        await _enforce_agent_scope(agent_id)
        _reject_blocked_command(command)
        shell_name = _SHELL_NAMES.get(shell, shell)
        await _require_elevation(
            "trmm_run_command",
            f"Run on {agent} ({shell}): {command}",
            {"agent_id": agent_id, "command": command, "shell": shell,
             "timeout": timeout, "run_as_user": run_as_user},
            display={
                "action": f"Run a {shell_name} command",
                "target": agent,
                "risk": RISK_DISRUPTIVE,
                "code": command,
                "facts": [
                    ["Shell", shell_name],
                    ["Runs as", _runs_as(run_as_user)],
                    ["Timeout", f"{timeout} seconds"],
                ],
            },
        )

        body = {
            "cmd": command,
            "shell": shell,
            "timeout": timeout,
            "run_as_user": run_as_user,
        }
        result = await client.post(f"/agents/{agent_id}/cmd/", body)
        # TRMM returns a bare string here: stderr if non-empty, else stdout.
        return {"agent": agent, "agent_id": agent_id, "command": command,
                "output": result}

    @server.tool(
        description=(
            "Run a saved TRMM script on an agent. Get script_id from "
            "trmm_list_scripts, and read the code with trmm_get_script first. "
            "Waits for completion and returns the output."
        )
    )
    async def trmm_run_script(
        agent: str,
        script_id: int,
        args: list[str] | None = None,
        env_vars: list[str] | None = None,
        timeout: int = 90,
        run_as_user: bool = False,
    ) -> Any:
        agent_id = await _resolve_agent(agent)
        await _enforce_agent_scope(agent_id)
        name = await _script_name(script_id)
        facts = [
            ["Script", f"{name} (#{script_id})"],
            ["Runs as", _runs_as(run_as_user)],
            ["Timeout", f"{timeout} seconds"],
        ]
        if args:
            facts.append(["Arguments", " ".join(str(a) for a in args)])
        if env_vars:
            facts.append(["Environment", " ".join(str(e) for e in env_vars)])
        await _require_elevation(
            "trmm_run_script",
            f"Run script #{script_id} on {agent} (args={args or []})",
            {"agent_id": agent_id, "script_id": script_id, "args": args or [],
             "env_vars": env_vars or [], "timeout": timeout,
             "run_as_user": run_as_user},
            display={
                "action": f"Run the saved script “{name}”",
                "target": agent,
                "risk": RISK_DISRUPTIVE,
                "facts": facts,
            },
        )

        body = {
            "script": script_id,
            "output": "wait",
            "args": args or [],
            "env_vars": env_vars or [],
            "run_as_user": run_as_user,
            "timeout": timeout,
            # Required by the endpoint even when unused.
            "emails": [],
            "emailMode": "default",
            "custom_field": None,
            "save_all_output": False,
        }
        result = await client.post(f"/agents/{agent_id}/runscript/", body)
        return {
            "agent": agent,
            "agent_id": agent_id,
            "script_id": script_id,
            "output": result,
            "note": (
                "Output is stdout+stderr concatenated. For a structured exit "
                "code, check trmm_agent_history."
            ),
        }

    @server.tool(description="Reboot an agent now. Disruptive - confirm the target first.")
    async def trmm_reboot_agent(agent: str) -> Any:
        agent_id = await _resolve_agent(agent)
        await _enforce_agent_scope(agent_id)
        await _require_elevation(
            "trmm_reboot_agent", f"Reboot {agent} immediately",
            {"agent_id": agent_id},
            display={
                "action": "Reboot the machine immediately",
                "target": agent,
                "risk": RISK_DESTRUCTIVE,
                "warning": "Unsaved work on this machine will be lost.",
                "facts": [["Effect", "Restarts now, without warning the user"]],
            },
        )
        return {
            "agent": agent,
            "result": await client.post(f"/agents/{agent_id}/reboot/", {}),
        }

    @server.tool(
        description=(
            "Start, stop or restart a Windows service on an agent. "
            "action is 'start', 'stop' or 'restart'."
        )
    )
    async def trmm_service_action(agent: str, service_name: str, action: str) -> Any:
        if action not in ("start", "stop", "restart"):
            raise TrmmError("action must be 'start', 'stop' or 'restart'")
        agent_id = await _resolve_agent(agent)
        await _enforce_agent_scope(agent_id)
        await _require_elevation(
            "trmm_service_action",
            f"{action} the '{service_name}' service on {agent}",
            {"agent_id": agent_id, "service_name": service_name, "action": action},
            display={
                "action": f"{action.capitalize()} a Windows service",
                "target": agent,
                "risk": RISK_DESTRUCTIVE if action in ("stop", "restart")
                else RISK_DISRUPTIVE,
                "facts": [
                    ["Service", service_name],
                    ["Action", action],
                ],
                "warning": (
                    "Stopping a service can take dependent software offline."
                    if action in ("stop", "restart") else ""
                ),
            },
        )
        result = await client.post(
            f"/services/{agent_id}/{service_name}/", {"sv_action": action}
        )
        return {"agent": agent, "service": service_name, "action": action,
                "result": result}

    @server.tool(description="Kill a process by PID on an agent.")
    async def trmm_kill_process(agent: str, pid: int) -> Any:
        agent_id = await _resolve_agent(agent)
        await _enforce_agent_scope(agent_id)
        await _require_elevation(
            "trmm_kill_process", f"Kill PID {pid} on {agent}",
            {"agent_id": agent_id, "pid": pid},
            display={
                "action": "Force-kill a running process",
                "target": agent,
                "risk": RISK_DESTRUCTIVE,
                "warning": "The process is terminated without saving.",
                "facts": [["Process ID", str(pid)]],
            },
        )
        return {
            "agent": agent,
            "pid": pid,
            "result": await client.delete(f"/agents/{agent_id}/processes/{pid}/"),
        }

    @server.tool(description="Send a Wake-on-LAN packet to an agent.")
    async def trmm_wake_on_lan(agent: str) -> Any:
        agent_id = await _resolve_agent(agent)
        await _enforce_agent_scope(agent_id)
        await _require_elevation(
            "trmm_wake_on_lan", f"Send Wake-on-LAN to {agent}",
            {"agent_id": agent_id},
            display={
                "action": "Send a Wake-on-LAN packet",
                "target": agent,
                "risk": RISK_ROUTINE,
                "facts": [["Effect", "Powers the machine on; changes nothing else"]],
            },
        )
        return {
            "agent": agent,
            "result": await client.post(f"/agents/{agent_id}/wol/", {}),
        }

    @server.tool(description="Force all checks to run now on an agent.")
    async def trmm_run_checks(agent: str) -> Any:
        agent_id = await _resolve_agent(agent)
        await _enforce_agent_scope(agent_id)
        await _require_elevation(
            "trmm_run_checks", f"Force all checks to run on {agent}",
            {"agent_id": agent_id},
            display={
                "action": "Run all monitoring checks now",
                "target": agent,
                "risk": RISK_ROUTINE,
                "facts": [["Effect", "Re-runs existing checks; adds nothing new"]],
            },
        )
        return {
            "agent": agent,
            "result": await client.post(f"/checks/{agent_id}/run/", {}),
        }

    @server.tool(
        description="Run an automated task now. Get task_id from trmm_agent_tasks."
    )
    async def trmm_run_task(task_id: int) -> Any:
        # A task is bound to an agent, so it must honour the allowlist like every
        # other execution path - otherwise the hard scope has a hole in it.
        task_agent = ""
        task_name = f"task #{task_id}"
        try:
            task = await client.get(f"/tasks/{task_id}/")
            if isinstance(task, dict):
                task_agent = str(task.get("agent") or "")
                task_name = str(task.get("name") or task_name)
        except TrmmError:
            task = None

        if config.AGENT_ALLOWLIST:
            if not task_agent:
                raise TrmmError(
                    f"Refused: cannot determine which agent task #{task_id} "
                    f"belongs to, and TRMM_MCP_AGENT_ALLOWLIST is in force."
                )
            await _enforce_agent_scope(task_agent)

        await _require_elevation(
            "trmm_run_task", f"Run automated task #{task_id} now",
            {"task_id": task_id},
            display={
                "action": f"Run the automated task “{task_name}” now",
                "target": task_agent or f"automated task #{task_id}",
                "risk": RISK_DISRUPTIVE,
                "facts": [["Task", f"{task_name} (#{task_id})"],
                          ["Effect", "Runs whatever the task is configured to do"]],
            },
        )
        return {
            "task_id": task_id,
            "result": await client.post(f"/tasks/{task_id}/run/", {}),
        }


# --------------------------------------------------------------------------
# tool annotations
# --------------------------------------------------------------------------
# MCP tool hints let a *client* reason about a tool's safety independently of
# our out-of-band approval gate: a UI can colour a destructive tool, or refuse
# to auto-run one. They are advisory - the real enforcement is still the gate -
# but they cost nothing and make the tool surface self-describing.
#
# Applied from one table after registration rather than on 28 decorators, so
# the safety classification lives in a single readable place. `open_world_hint`
# is true for every tool here: they all reach an external RMM whose state we do
# not control.

# Tools that change a managed machine and cannot simply be undone.
_DESTRUCTIVE_TOOLS = {
    "trmm_run_command",
    "trmm_run_script",
    "trmm_reboot_agent",
    "trmm_service_action",
    "trmm_kill_process",
    "trmm_run_task",
}
# Execution tools that are safe to repeat / not destructive.
_SAFE_WRITE_TOOLS = {
    "trmm_wake_on_lan",  # idempotent: waking an awake machine is a no-op
    "trmm_run_checks",  # idempotent: just re-runs existing checks
}


def _apply_tool_annotations() -> None:
    from mcp_types import ToolAnnotations

    for name, tool in server._tool_manager._tools.items():
        if name in _DESTRUCTIVE_TOOLS:
            tool.annotations = ToolAnnotations(
                read_only_hint=False, destructive_hint=True,
                idempotent_hint=False, open_world_hint=True,
            )
        elif name in _SAFE_WRITE_TOOLS:
            tool.annotations = ToolAnnotations(
                read_only_hint=False, destructive_hint=False,
                idempotent_hint=True, open_world_hint=True,
            )
        else:
            # Everything else is a read: safe, repeatable, changes nothing.
            tool.annotations = ToolAnnotations(
                read_only_hint=True, destructive_hint=False,
                idempotent_hint=True, open_world_hint=True,
            )


_apply_tool_annotations()


class BearerAuthMiddleware:
    """Require `Authorization: Bearer <token>` on every HTTP request.

    Responds 403 rather than 401, and sends no WWW-Authenticate header: a 401
    challenge makes MCP clients such as mcp-remote assume OAuth and launch a
    browser flow instead of reporting a bad token.
    """

    def __init__(self, app: Any, token: str, exempt_prefixes: tuple[str, ...] = ()) -> None:
        self.app = app
        self.expected = f"Bearer {token}"
        self.exempt_prefixes = exempt_prefixes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # The approval pages are for a human in a browser, which cannot set a
        # bearer header; they authenticate with the same token via a cookie.
        path = scope.get("path", "")
        if any(path.startswith(prefix) for prefix in self.exempt_prefixes):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        presented = headers.get(b"authorization", b"").decode("latin-1")

        if not hmac.compare_digest(presented, self.expected):
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8")],
                }
            )
            await send({"type": "http.response.body", "body": b"Forbidden"})
            return

        await self.app(scope, receive, send)


def main() -> None:
    # httpx logs every request line at INFO, which is noise on stderr and echoes
    # API paths into the journal.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    if config.TRANSPORT == "stdio":
        server.run(transport="stdio")
        return

    import uvicorn
    from mcp.server.transport_security import TransportSecuritySettings

    app: Any = server.streamable_http_app(
        streamable_http_path=config.HTTP_PATH,
        stateless_http=config.STATELESS_HTTP,
        transport_security=TransportSecuritySettings(
            allowed_hosts=config.ALLOWED_HOSTS,
            allowed_origins=["*"],
        ),
    )

    if config.REQUIRE_APPROVAL:
        from starlette.routing import Route

        from . import approval_auth, approval_web

        # Without its own credentials the approval page falls back to accepting
        # the bearer token - which every MCP client already holds. That would
        # let a client approve its own executions, collapsing the whole gate.
        if not approval_auth.is_configured():
            message = (
                "approval page has no password/2FA; it would accept the shared "
                "bearer token that MCP clients already hold. "
                "Run setup_approval_auth.py."
            )
            observability.event("startup_warning", problem=message)
            if config.LISTEN_HOST not in ("127.0.0.1", "localhost", "::1"):
                raise SystemExit(
                    f"Refusing to serve the approval page on {config.LISTEN_HOST}: "
                    f"{message}"
                )
            logging.getLogger("trmm_mcp").warning(message)
            print(f"  WARNING: {message}", flush=True)

        app.router.routes.extend(
            [
                Route("/approve/", approval_web.index, methods=["GET"]),
                Route(
                    "/approve/history",
                    approval_web.history,
                    methods=["GET"],
                ),
                Route("/approve/login", approval_web.login, methods=["POST"]),
                Route("/approve/logout", approval_web.logout, methods=["POST"]),
                Route(
                    "/approve/approve/{request_id}",
                    approval_web.approve,
                    methods=["POST"],
                ),
                Route("/approve/deny/{request_id}", approval_web.deny, methods=["POST"]),
                Route("/approve/window", approval_web.window, methods=["POST"]),
                Route("/approve/revoke", approval_web.revoke, methods=["POST"]),
            ]
        )

    if config.AUTH_TOKEN:
        app = BearerAuthMiddleware(app, config.AUTH_TOKEN, exempt_prefixes=("/approve",))

    print(
        f"trmm-mcp listening on {config.SCHEME}://{config.LISTEN_HOST}:"
        f"{config.LISTEN_PORT}{config.HTTP_PATH} (mode={config.MODE}, "
        f"auth={'bearer token' if config.AUTH_TOKEN else 'NONE'}, "
        f"tls={'on' if config.TLS_ENABLED else 'OFF'})",
        flush=True,
    )
    if config.REQUIRE_APPROVAL:
        print(f"  approvals: {config.PUBLIC_URL}/approve/", flush=True)

    tls: dict[str, Any] = {}
    if config.TLS_ENABLED:
        tls = {"ssl_certfile": config.TLS_CERT, "ssl_keyfile": config.TLS_KEY}

    uvicorn.run(
        app,
        host=config.LISTEN_HOST,
        port=config.LISTEN_PORT,
        log_level="warning",
        **tls,
    )


if __name__ == "__main__":
    main()
