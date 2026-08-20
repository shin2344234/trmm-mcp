# Tool reference

Every one of the 28 tools, what is deliberately not exposed, the MCP safety
annotations a client can reason about, and how responses are kept from
swallowing the model's context window.

## Tools

### Read (both modes)

| Tool | What it gives you |
|---|---|
| `trmm_fleet_overview` | Counts plus the offline / needs-reboot / failing-check / pending-patch lists. **Start here.** |
| `trmm_list_agents` | Agents with status; filter by client, site, type, online state, hostname |
| `trmm_get_agent` | Full detail for one machine (heavy sections omitted by default) |
| `trmm_agent_services` | Windows services, filterable by name and state |
| `trmm_agent_processes` | Live process list sorted by memory or CPU |
| `trmm_agent_event_log` | Windows event log, filterable by level and text |
| `trmm_agent_checks` | Configured checks and their status |
| `trmm_agent_history` | Past command/script runs **with their output** |
| `trmm_agent_software` | Installed software inventory |
| `trmm_agent_windows_updates` | Patch status |
| `trmm_agent_tasks` | Automated tasks on an agent |
| `trmm_list_clients_sites` | Clients and sites with ids |
| `trmm_list_alerts` | Current alerts |
| `trmm_list_scripts` / `trmm_get_script` | Script library; full source code |
| `trmm_pending_actions` | Queued agent work |
| `trmm_audit_log` | Who changed what, when |
| `trmm_debug_log` | Server debug log |
| `trmm_server_info` | Versions and the active mode |
| `trmm_api_get` | **Escape hatch** — raw GET against any API path |

### Execution (command mode only)

| Tool | Notes |
|---|---|
| `trmm_run_command` | Shell command, returns output |
| `trmm_run_script` | Saved script by id, waits for output |
| `trmm_reboot_agent` | Immediate reboot |
| `trmm_service_action` | start / stop / restart a Windows service |
| `trmm_kill_process` | Kill by PID |
| `trmm_wake_on_lan` | WoL packet |
| `trmm_run_checks` | Force checks to run now |
| `trmm_run_task` | Run an automated task now |

Anywhere a tool takes an agent you can pass **the hostname or the agent_id** —
hostnames are resolved automatically, and an ambiguous one is rejected rather
than guessed.

### Deliberately not exposed

- Bulk / fleet-wide execution (`/agents/actions/bulk/`): highest blast radius,
  and TRMM returns no output for it anyway.
- Server-side scripts (`run_on_server`), which run on the TRMM server itself.
- Config mutation. No editing agents, policies, users, or settings.
- API key enumeration and the global keystore, which both leak credentials.

Adding any of these is a small edit to `server.py`. They were left out on
purpose, not overlooked.

## Tool annotations

Every tool carries MCP hints (`readOnlyHint` / `destructiveHint` /
`idempotentHint` / `openWorldHint`) so a *client* can reason about safety on its
own — colour a destructive tool, refuse to auto-run one — independent of the
approval gate. They're advisory; the real enforcement is still the out-of-band
gate. The classification lives in two small sets in `server.py`
(`_DESTRUCTIVE_TOOLS` / `_SAFE_WRITE_TOOLS`), applied after registration, so
adding a tool means adding one line there, not editing a decorator.

## Context-size handling

TRMM has no pagination and returns whole tables. On this install a single
`GET /agents/<id>/` was **192 KB** (`services` 118 KB, `wmi_detail` 60 KB).
Dumped raw, one call would consume a large share of the model's context.

So: `trmm_get_agent` omits heavy sections unless you name them in `include`
(the same agent comes back as **3.3 KB**, a 58× reduction); list tools project
to useful fields and take `limit`; and every result is capped at
`TRMM_MCP_MAX_RESPONSE_CHARS` with an explicit truncation notice rather than
silent cutoff.

## Output shape

Every tool returns a **JSON object**, never a bare list. This matters: the MCP
layer emits one content block per item for a list return, and an *empty* list
produces no content at all — so "no checks are configured" would be
indistinguishable from a failed call. Listing tools therefore return
`{"count": N, "<thing>": [...]}`, and an empty result reads as
`{"count": 0, "checks": [], "agent": "workstation-01"}`.

