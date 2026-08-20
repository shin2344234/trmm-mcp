<!-- mcp-name: io.github.shin2344234/trmm-mcp -->

# TacticalRMM MCP server

Lets an AI assistant read everything in your TacticalRMM install, and — when
you explicitly switch it on — run commands on your managed machines.

Ask "which machines are offline and why", "what's eating memory on the front
desk PC", "show me every failed check this week", and get answers from live
fleet data. Turn on `elevate` mode and the assistant can also fix things, but
only after you approve each action yourself.

## Why I built it

I manage machines for a number of clients, and TacticalRMM already collects far
more about each one than anyone has time to sit and read. I wanted to actually
use that data: run deeper diagnostics than the dashboard puts in front of you,
produce per-client reports covering every device, and find the things worth
fixing before someone rings up to report them.

It does grow billable work, and I think that is fine as long as the work is
real. A disk throwing early SMART errors, a server quietly filling up, patches
that stopped applying three months ago and nobody noticed — catching those is
worth paying for. Billing for busywork is not. The test I hold this to is
whether every item on a report is something the client can see the sense in
fixing once it has been explained to them.

## What you get

**28 tools.** 20 read-only ones covering agents, checks, alerts, services,
processes, event logs, software inventory, patches, scripts and audit history;
8 execution tools for running commands and scripts, rebooting, controlling
services, killing processes, and waking machines.

**A full audit trail of everything.** Every inbound request, every tool call
with its arguments, every result, every TRMM API call, every approval decision
and every refusal is written to a structured JSONL log with credential
redaction and rotation. For a bridge that can run commands as SYSTEM across a
fleet, knowing exactly who asked for what and when is not optional — so it is
on by default and cannot be silently skipped. Details in
[Audit logging][audit-log].

**An approval gate the model cannot reach.** In `elevate` mode an execution is
refused until you approve that exact call in a browser (password + TOTP) or
from a shell on the server. Approvals are bound to a fingerprint of the
arguments, are single-use, and expire. No tool exists that grants elevation.

**Read-only that actually holds.** Three independent layers: the execution
tools are never registered, the HTTP client refuses non-read requests, and the
API key itself is bound to a TRMM role with no execution permissions.

**Built for real fleets.** TRMM has no pagination and returns whole tables —
one agent detail call measured 192 KB here. Responses are projected, capped and
truncated with an explicit notice, so a single call cannot swallow the model's
context.

**HTTPS with bearer auth**, a self-signed certificate carrying an IP SAN, and a
hardened systemd unit. Clients trust that one certificate rather than skipping
verification.

Works with Claude Code, Claude Desktop and LM Studio on macOS, Windows and
Linux. Built and verified against **TRMM 1.5.1**. The TRMM API itself is
documented independently in [docs/trmm-api.md][trmm-api].

---

## Three modes

| | `readonly` (default) | `elevate` | `command` |
|---|---|---|---|
| Tools exposed | 20 read tools | 28 | 28 |
| Reads | yes | yes | yes |
| Executions | **never** | **only what you approve, one call at a time** | always |
| TRMM key for reads | `mcp-readonly` | `mcp-readonly` | `mcp-command` |
| TRMM key for executions | — | `mcp-command`, only after approval | `mcp-command` |
| Good for | pure Q&A | day-to-day chat | unattended automation |

`elevate` is the one to use for interactive work: Claude can look at anything,
but the moment it wants to *do* something it stops and waits for you.

## Security

The short version:

- **The approval gate is out of band.** In `elevate` mode an execution is
  refused until you approve that exact call in a browser (password + TOTP) or
  from a shell on the server. Approvals are bound to a fingerprint of the
  arguments, are single-use, and expire. No tool exists that grants elevation,
  so the model has no route to its own approval.
- **Read-only holds at three independent layers.** The execution tools are
  never registered, the HTTP client refuses non-read requests, and the API key
  itself is bound to a TRMM role with no execution permissions.
- **Destructive patterns are refused client-side** in `command` mode — `rm -rf
  /`, `mkfs`, `dd of=/dev/*`, `format c:` and the rest — with an optional agent
  allowlist to hard-scope what can be touched at all.
- **HTTPS with bearer auth**, a self-signed certificate carrying an IP SAN, and
  a hardened systemd unit. Clients trust that one certificate rather than
  skipping verification.

There is one honest caveat about the third read-only layer, because TRMM has no
view-only permission for services, processes or Windows updates. That, the
approval page's own password + TOTP gate, and why MCP elicitation is not used as
the approval channel, are all written up in **[docs/security.md][security]**.

## Setup

Already done on this box:

- venv at `venv/` with `mcp` 2.0 and `httpx`
- TRMM roles `MCP Read Only` and `MCP Command`, users `mcp-readonly` and
  `mcp-command` (both blocked from UI login, unusable passwords)
- API keys written to `.env` (mode 600)

To re-provision or rotate keys:

```bash
/rmm/api/env/bin/python /opt/trmm-mcp/provision_trmm_accounts.py --rotate
```

## Running the server

To reach it from other machines, first tell it which address to serve on. These
go in `.env`, not in the unit file — the unit is in git, and an address baked in
there would follow every copy of it onto the wrong machine:

```bash
cat >> /opt/trmm-mcp/.env <<'EOF'
TRMM_MCP_HTTP_HOST=10.0.0.5
TRMM_MCP_PUBLIC_URL=https://10.0.0.5:8770
EOF
```

Substitute your own address. `TRMM_MCP_PUBLIC_URL` is what the assistant tells
you to open when something needs approving, so it has to be a URL your browser
can actually reach. Skip this step and the server binds `127.0.0.1`, which is
fine if the client runs on the same box.

Then install the unit and start it:

```bash
sudo cp /opt/trmm-mcp/trmm-mcp.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now trmm-mcp
```

Check what it came up on — the startup line names the address, the mode and
whether TLS is on:

```bash
journalctl -u trmm-mcp -n 5 --no-pager | grep listening
```

It serves HTTPS on port 8770 by default and requires the bearer token from
`.env`. To run it in the foreground instead, for a quick test:

```bash
/opt/trmm-mcp/run.sh readonly http
```

The listener runs stateless (`TRMM_MCP_STATELESS_HTTP=true`, the default). This
matters: with stateful streamable HTTP the server hands out a session id that
dies with the process, so restarting the service leaves any connected client
replaying a session the server has forgotten. Through `mcp-remote` that shows up
as tool calls hanging for minutes and then failing, while `tools/list` still
answers, with `Rejected request with unknown or expired session ID` in
`logs/server.log`. Stateless removes the failure mode; we use no
server-initiated requests, so it costs nothing. `restart_test.py` proves both
behaviours.

The bearer token is the only authentication on that port, so anything that can
reach it inherits this server's TRMM permissions. Keep it on the LAN or behind a
tunnel rather than binding a public interface.

## Connecting a client

You need two things from the server: the **bearer token** from `.env`, and a
copy of **`certs/cert.pem`** so the client can verify the TLS certificate.

Claude Code speaks HTTP directly and needs no bridge:

```bash
claude mcp add --transport http trmm https://192.0.2.10:8770/mcp \
  --header "Authorization: Bearer <TRMM_MCP_AUTH_TOKEN>" --scope user
```

On the server itself you can skip the network entirely and run it over stdio:

```bash
claude mcp add trmm -- /opt/trmm-mcp/run.sh readonly
```

Swap `readonly` for `elevate` to get the approval gate, or `command` for
unattended execution.

Claude Desktop needs the `mcp-remote` bridge, LM Studio speaks remote HTTP
natively, and either can instead be run across SSH with nothing listening on the
network at all. Working configs for all three on macOS, Windows and Linux — plus
installing the certificate into the system trust store — are in
**[docs/clients.md][clients]**.

## Tools

**28 tools: 20 read-only, 8 execution.** Anywhere a tool takes an agent you can
pass **the hostname or the agent_id** — hostnames are resolved automatically,
and an ambiguous one is rejected rather than guessed.

- **Start here** — `trmm_fleet_overview`: counts, plus the offline,
  needs-reboot, failing-check and pending-patch lists.
- **Fleet** — agents with status and filters, clients and sites, alerts,
  pending actions, server info and the active mode.
- **Diagnostics** — services, processes, event log, configured checks,
  installed software, patch status, automated tasks, and past command and
  script runs *with their output*.
- **Audit and scripts** — the TRMM audit log, the server debug log, the script
  library and full script source.
- **Escape hatch** — `trmm_api_get`: a raw GET against any API path.
- **Execution** (`elevate` and `command` only) — run a command, run a saved
  script, reboot, start/stop/restart a service, kill a process, wake-on-LAN,
  force checks to run, run an automated task.

Bulk fleet-wide execution, server-side scripts and all config mutation are
deliberately **not** exposed. The full 28-row table, the reasoning behind the
omissions, the MCP safety annotations and the context-size handling are in
**[docs/tools.md][tools]**.

## Documentation

| | |
|---|---|
| **[Security][security]** | The approval gate, the three read-only layers, TLS, and the honest caveats |
| **[Installation][installation]** | pip versus a clone, where it keeps its files, rebuilding the venv |
| **[Connecting a client][clients]** | Claude Code, Claude Desktop, LM Studio, SSH, and the certificate |
| **[Tools][tools]** | All 28 tools, what is not exposed, annotations, context-size handling |
| **[Operations][operations]** | Audit logging, the browser log pages, backups, testing, troubleshooting |
| **[Configuration][configuration]** | Every environment variable, and what each file in the repo does |
| **[TRMM API][trmm-api]** | Independent documentation of the TacticalRMM API itself |

## Changelog

See [CHANGELOG.md][changelog].

## License

AGPL-3.0-or-later (`LICENSE`), with per-file SPDX headers. The copyleft terms
mean anyone who runs a modified copy as a network service must publish their
changes — deliberate, to keep execution-capable forks open.

[security]: https://github.com/shin2344234/trmm-mcp/blob/master/docs/security.md
[installation]: https://github.com/shin2344234/trmm-mcp/blob/master/docs/installation.md
[clients]: https://github.com/shin2344234/trmm-mcp/blob/master/docs/clients.md
[tools]: https://github.com/shin2344234/trmm-mcp/blob/master/docs/tools.md
[operations]: https://github.com/shin2344234/trmm-mcp/blob/master/docs/operations.md
[configuration]: https://github.com/shin2344234/trmm-mcp/blob/master/docs/configuration.md
[trmm-api]: https://github.com/shin2344234/trmm-mcp/blob/master/docs/trmm-api.md
[audit-log]: https://github.com/shin2344234/trmm-mcp/blob/master/docs/operations.md#audit-logging
[changelog]: https://github.com/shin2344234/trmm-mcp/blob/master/CHANGELOG.md
