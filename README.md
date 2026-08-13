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
[Audit logging](#audit-logging).

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
documented independently in [TRMM-API.md](TRMM-API.md).

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

### How elevate works

1. Claude calls an execution tool. It does **not** run. The call is refused with
   an explanation and a link.
2. You open `http://192.0.2.10:8770/approve/`, see the exact command and
   target, and click **Approve once** (or run `approve.py ok` on the server).
3. Claude retries the identical call. It runs, and the approval is **consumed**.
4. Anything further needs approving again — it is back to read-only by itself.

The approval is bound to a fingerprint of the exact arguments, so an approval
for `hostname` cannot be spent on a different command. Verified in the tests.

For a burst of work, open a **window** (e.g. 10 minutes / 5 uses) from the same
page. Windows expire on their own; "Revoke every grant now" kills everything
immediately.

### Protecting the approval page

The approval page is the only thing between a model asking to run something and
it running, so give it credentials of its own:

```bash
cd /opt/trmm-mcp && ./venv/bin/python setup_approval_auth.py
```

It asks for a password, generates a TOTP secret, prints a QR code to scan with
any authenticator app, and writes the result to `.env`. Then restart the
server. Sign-in afterwards needs **both** the password and a 6-digit code.

Why bother, when the page already asked for a token: that token is the *bearer
token*, and every MCP client config holds a copy. Anything with the token could
approve its own requests, which defeats the point of out-of-band approval.
Password + TOTP is a credential that exists only in your head and your phone.

What the implementation does:

- The password is hashed with PBKDF2-HMAC-SHA256, 600k rounds, and a per-install
  salt. Only the hash is stored.
- TOTP codes can't be replayed. A code is spent on use, and only once both
  factors pass, so a mistyped password doesn't burn a good code.
- One 30-second step of drift either side is tolerated.
- After five failed attempts it locks out with exponential backoff, per client
  address, and refuses correct credentials while the lockout lasts.
- The session cookie holds no secret, just a signed expiry and an epoch
  (`HttpOnly`, `SameSite=Strict`, 12 hours). Re-running setup bumps the epoch and
  signs everyone out.
- Failed logins are recorded as `approval_login` events noting which factor
  failed. The page never tells the visitor which one was wrong.

### TLS

The listener serves **HTTPS** using a self-signed certificate at
`certs/cert.pem` (key `certs/key.pem`, 10 years). It carries an **IP SAN** for
`192.0.2.10` as well as `127.0.0.1`, `rmm-server`, `localhost` and
`mcp.example.com` — without an IP SAN, a client dialling the address by
IP cannot verify the certificate at all and you are pushed into disabling
verification, which defeats the point.

Because traffic is encrypted, the session cookie is issued with `Secure` set.

Clients are told to **trust this one certificate** rather than to skip checking:

- **mcp-remote / Node** — `NODE_EXTRA_CA_CERTS` pointing at a copy of
  `cert.pem`, not `NODE_TLS_REJECT_UNAUTHORIZED=0`.
- **Browser** — you will get a warning the first time. Either accept it, or
  import `cert.pem` into *Trusted Root Certification Authorities* on the
  workstation to make it go away properly.

To regenerate (after an IP change, say), recreate the pair with the same SAN
list and restart. Set `TRMM_MCP_TLS=false` to fall back to plain HTTP.

### Why not MCP elicitation

The protocol has an `elicitation/create` feature that would put the prompt right
in the chat, and it is the wrong tool here:

- **Claude Desktop does not implement it.** It returns a synthetic `cancel` in
  ~47 ms with no UI ever shown, so the server cannot tell refusal from silence.
- **It is not a security boundary even where it works.** The spec says clients
  *SHOULD* get user approval, not MUST, and explicitly declines to mandate any
  interaction model. Claude Code ships an `Elicitation` hook whose documented
  purpose is auto-answering these prompts without showing a dialog, and an
  `ElicitationResult` hook that can rewrite the user's answer.

So approval here happens on a channel the model has no access to. There is no
tool that grants elevation — the only ways in are the browser page and a shell
on this box. That is the property worth having, and the tests assert it.

### Why read-only is actually read-only

Three independent layers, each sufficient on its own:

1. The execution tools are never registered in read-only mode, and Claude can't
   call a tool it can't see. Verified over the wire, not just in theory.
2. The HTTP client refuses non-read requests. GET is allowed; PATCH only for
   `/alerts/` and `/logs/audit/`, which is how TRMM queries those. Everything
   else raises before a packet leaves the process.
3. The API key itself can't execute. `mcp-readonly` is bound to a TRMM role with
   no execution permissions, so TRMM returns 403 even if the first two layers
   were bypassed. That key gets 403 on `POST /agents/<id>/cmd/`, `/runscript/`,
   `/reboot/` and `/wol/`.

The command key is not even loaded into the process in read-only mode.

### One honest caveat about layer 3

TRMM has **no view-only permission** for Windows services, processes, or
Windows updates — viewing and acting are gated by the same `can_manage_procs` /
`can_manage_winsvcs` / `can_manage_winupdates` flag (verified in
`services/permissions.py`, `agents/permissions.py`, `winupdate/permissions.py`).

Without them the read-only role cannot list running services or processes at
all, which removes most of the value for diagnosing a sick machine. So the
read-only role **does** hold those three flags. The consequence, stated plainly:

- The read-only **key**, used outside this server, could stop a service, kill a
  process, or trigger a Windows update install.
- It still **cannot** run commands, run scripts, reboot, or send WoL — those are
  403 at the key level.
- Through this MCP server none of it is reachable, because layer 2 refuses every
  non-GET request before it leaves the process, and layer 1 never exposes a tool
  that would try.

If you would rather have a strictly minimal key and lose service/process
visibility, drop `VIEW_REQUIRES_MANAGE_PERMS` in
`provision_trmm_accounts.py` and re-run it.

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

Install the systemd unit and start it:

```bash
sudo cp /opt/trmm-mcp/trmm-mcp.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now trmm-mcp
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

Claude Code, Claude Desktop and LM Studio are covered below, each on macOS,
Windows and Linux. Whichever you use, you need two things from the server: the
**bearer token** from `.env`, and a copy of **`certs/cert.pem`** so the client
can verify the TLS certificate.

Copy the certificate over first.

macOS and Linux:

```bash
scp rmmuser@192.0.2.10:/opt/trmm-mcp/certs/cert.pem ~/trmm-mcp-cert.pem
```

Windows (PowerShell):

```powershell
scp rmmuser@192.0.2.10:/opt/trmm-mcp/certs/cert.pem $env:USERPROFILE\trmm-mcp-cert.pem
```

### Claude Code — macOS, Windows, Linux

The simplest of the three, because Claude Code speaks HTTP directly and needs no
bridge:

```bash
claude mcp add --transport http trmm https://192.0.2.10:8770/mcp \
  --header "Authorization: Bearer <TRMM_MCP_AUTH_TOKEN>" --scope user
```

`--scope user` makes it available across all your projects; leave it off for the
current project only. Claude Code reads the operating system's certificate
store, so once you have installed the certificate (see
[Trusting the certificate](#trusting-the-certificate)) nothing further is
needed.

On the server itself you can skip the network entirely and run it over stdio:

```bash
claude mcp add trmm -- /opt/trmm-mcp/run.sh readonly
```

Swap `readonly` for `elevate` to get the approval gate, or `command` for
unattended execution. Keeping two entries (`trmm` and `trmm-command`) makes the
active capability obvious at a glance.

### Claude Desktop — macOS, Windows, Linux (beta)

Desktop's built-in "custom connector" UI cannot reach this server. Those
connectors are dialled from Anthropic's own infrastructure, so a private address
is unroutable from there and a self-signed certificate is rejected.
`claude_desktop_config.json` is stdio-only as well — it has no `url` field. The
working route is `mcp-remote`, a small Node bridge that Desktop launches locally
and which speaks HTTP to this server. Node 18+ is required.

Open the config with **Settings → Developer → Edit Config** (the Claude menu in
the menu bar or app menu, not the in-window account settings). That button opens
whichever file the install actually reads, which saves you guessing. The paths,
if you want them directly:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` (not documented by Anthropic; prefer the in-app button) |

**macOS and Linux** — `npx` is invoked directly:

```json
{
  "mcpServers": {
    "tacticalrmm": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote@latest",
        "https://192.0.2.10:8770/mcp",
        "--transport", "http-only",
        "--header", "Authorization:${AUTH_HEADER}"
      ],
      "env": {
        "AUTH_HEADER": "Bearer <TRMM_MCP_AUTH_TOKEN from .env>",
        "NODE_EXTRA_CA_CERTS": "/Users/you/trmm-mcp-cert.pem"
      }
    }
  }
}
```

On Linux the certificate path is typically `/home/you/trmm-mcp-cert.pem`.

**Windows** — the same thing wrapped in `cmd /c`:

```json
{
  "mcpServers": {
    "tacticalrmm": {
      "command": "cmd",
      "args": [
        "/c", "npx", "-y", "mcp-remote@latest",
        "https://192.0.2.10:8770/mcp",
        "--transport", "http-only",
        "--header", "Authorization:${AUTH_HEADER}"
      ],
      "env": {
        "AUTH_HEADER": "Bearer <TRMM_MCP_AUTH_TOKEN from .env>",
        "NODE_EXTRA_CA_CERTS": "C:\\Users\\YOU\\trmm-mcp-cert.pem"
      }
    }
  }
}
```

Three details worth understanding:

- `cmd /c` is a Windows-only workaround. There, `npx` is the batch shim
  `npx.cmd`, which Node only resolves through `PATHEXT` when spawned with a
  shell; Electron hosts that spawn without one fail with `spawn npx ENOENT`. No
  such shim exists on macOS or Linux, so the wrapper is unnecessary there. Some
  Windows builds do spawn with a shell and work without it — treat `cmd /c` as
  the safe default rather than a hard requirement.
- `Authorization:${AUTH_HEADER}` with the value in `env`, and no space after the
  colon. Claude Desktop on Windows does not escape spaces inside `args`, which
  splits a literal `Bearer xyz` into stray arguments. mcp-remote expands
  `${VAR}` itself, so the space stays safely inside the variable. Harmless on
  every platform, so use it everywhere.
- `NODE_EXTRA_CA_CERTS` is the same variable name on all three systems. It
  *appends* to Node's trust store rather than disabling verification, so the
  certificate still has to match the address you dial. Prefer it over
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, which switches verification off for
  everything that process touches. Escape the backslashes on Windows.

Then quit Claude Desktop completely and reopen it. On Windows and macOS, closing
the window leaves it running — use the tray or menu-bar icon and pick Quit.
Start a new chat afterwards, since the tool list is fixed when a conversation
begins.

If Desktop appears to ignore your config on Windows, you are probably on the
MSIX build from the Store or WinGet, which virtualizes the filesystem. It reads
`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\`, while the "Edit
Config" button may open the un-virtualized `%APPDATA%` copy. Find the real one:

```powershell
$p = Get-ChildItem "$env:LOCALAPPDATA\Packages\Claude_*" -Directory | Select-Object -First 1
"$($p.FullName)\LocalCache\Roaming\Claude\claude_desktop_config.json"
```

To test the bridge outside Desktop when something misbehaves:

```bash
npx -p mcp-remote@latest mcp-remote-client https://192.0.2.10:8770/mcp --transport http-only --header "Authorization: Bearer <token>"
```

Connection failures are logged to `mcp.log`, and each server's stderr to
`mcp-server-tacticalrmm.log` — under `~/Library/Logs/Claude` on macOS and
`%APPDATA%\Claude\logs` on Windows (with the same MSIX redirect).

### LM Studio — macOS, Windows, Linux

LM Studio speaks remote HTTP natively, so no bridge is needed. Edit `mcp.json`
through the app: right sidebar → **Program** → **Install** → **Edit mcp.json**.
The documented path (`~/.lmstudio/mcp.json`) and the path several versions
actually use (`~/.cache/lm-studio/mcp.json`) disagree, so the in-app editor is
the reliable route.

```json
{
  "mcpServers": {
    "tacticalrmm": {
      "url": "https://192.0.2.10:8770/mcp",
      "headers": { "Authorization": "Bearer <TRMM_MCP_AUTH_TOKEN from .env>" },
      "timeout": 60000
    }
  }
}
```

Two caveats. LM Studio rejects self-signed certificates and offers no setting to
trust one, so start it with the CA in the environment:

```bash
NODE_EXTRA_CA_CERTS=~/trmm-mcp-cert.pem "/Applications/LM Studio.app/Contents/MacOS/LM Studio"   # macOS
NODE_EXTRA_CA_CERTS=~/trmm-mcp-cert.pem lm-studio                                                # Linux
```

```powershell
$env:NODE_EXTRA_CA_CERTS="$env:USERPROFILE\trmm-mcp-cert.pem"; & "$env:LOCALAPPDATA\Programs\LM Studio\LM Studio.exe"
```

And recent versions block private IP addresses for servers added dynamically
through the API. Declaring the server in `mcp.json`, as above, is the supported
way around that.

LM Studio prompts before every tool call and shows the arguments, which is a
useful second pair of eyes — but it is the client asking, and it can be set to
"always allow". The approval gate on this server is the real boundary.

### Over SSH instead — no open port

Rather than exposing the HTTP listener, a client can run the stdio server across
SSH. Nothing listens on the network and SSH keys do the authentication. This
suits Claude Desktop, which has no HTTP transport of its own.

Confirm passwordless SSH from the workstation first.

macOS and Linux:

```bash
ssh -o BatchMode=yes rmmuser@192.0.2.10 "echo OK"
ssh-keygen -t ed25519 -C "mcp-client"                      # if it prompted
ssh-copy-id rmmuser@192.0.2.10
```

Windows (PowerShell):

```powershell
ssh -o BatchMode=yes rmmuser@192.0.2.10 "echo OK"
ssh-keygen -t ed25519 -C "mcp-client"                      # if it prompted
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh rmmuser@192.0.2.10 "cat >> ~/.ssh/authorized_keys"
```

Then, in `claude_desktop_config.json` — `ssh` on macOS and Linux,
`C:\\Windows\\System32\\OpenSSH\\ssh.exe` on Windows:

```json
{
  "mcpServers": {
    "tacticalrmm": {
      "command": "ssh",
      "args": [
        "-T",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "rmmuser@192.0.2.10",
        "/opt/trmm-mcp/run.sh readonly"
      ]
    }
  }
}
```

`-T` is required: a pseudo-TTY would corrupt the JSON-RPC stream. `BatchMode`
makes a missing key fail immediately instead of hanging on a password prompt the
client cannot answer.

Verified on this server: launching under a minimal environment from a different
working directory still handshakes cleanly, and `~/.bashrc` has the standard
non-interactive guard, so nothing pollutes the protocol stream.

### Trusting the certificate

Node-based clients (Claude Desktop via mcp-remote, LM Studio) read
`NODE_EXTRA_CA_CERTS` and need nothing else. Claude Code and your browser read
the operating system store, so install the certificate there to use the approval
page without warnings.

**macOS:**

```bash
sudo security add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain ~/trmm-mcp-cert.pem
```

**Windows** (elevated prompt):

```cmd
certutil -addstore -f root "%USERPROFILE%\trmm-mcp-cert.pem"
```

**Linux** (Debian/Ubuntu — note the `.crt` extension is required):

```bash
sudo cp ~/trmm-mcp-cert.pem /usr/local/share/ca-certificates/trmm-mcp.crt && sudo update-ca-certificates
```

**Linux** (RHEL/Fedora):

```bash
sudo cp ~/trmm-mcp-cert.pem /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust extract
```

Two browser quirks. Firefox keeps its own certificate store on every platform
and ignores the system one, so import there separately or set
`security.enterprise_roots.enabled` in `about:config`. Chrome on Linux also uses
its own NSS database rather than the system bundle:

```bash
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "trmm-mcp" -i ~/trmm-mcp-cert.pem
```

Alternatively just accept the browser warning once — the approval page still
protects itself with a password and TOTP.

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

## Safety features in command mode

- Every mutating call is audit-logged to `command-audit.log` as JSON lines
  (timestamp, mode, method, path, body, outcome), refusals included.
- Destructive-command patterns are refused client-side: `rm -rf /`, `mkfs`,
  `dd of=/dev/*`, `format c:`, `diskpart`, `cipher /w`, recursive `Remove-Item`
  on `C:\`, and forced immediate `shutdown`. Override with
  `TRMM_MCP_BLOCK_PATTERNS` (set empty to disable).
- Optional agent allowlist: set `TRMM_MCP_AGENT_ALLOWLIST` to a comma-separated
  list of hostnames/agent_ids to hard-scope what can be touched.

## Audit logging

Everything the server is asked to do, everything it does, and everything that
fails is recorded under `logs/`. Both files rotate at 10 MB × 5 backups and are
mode 600.

| File | What's in it |
|---|---|
| `logs/events.jsonl` | The audit trail: one JSON object per line |
| `logs/server.log` | Human-readable diagnostics — warnings, errors, tracebacks, and anything uvicorn/httpx/the SDK emit |
| `command-audit.log` | Mutating TRMM calls only, kept as a short separate record |

Event kinds in `events.jsonl`:

| kind | Meaning |
|---|---|
| `startup` | Process start, with mode and transport |
| `request` | An inbound MCP call, with tool name and full arguments |
| `response` | Its outcome: ok/error, duration, result payload |
| `api_call` | Every TRMM API request — method, path, status, bytes, duration, whether the command key was used |
| `mutation` | A state-changing TRMM call |
| `elevation_required` / `elevation_granted` | Approval refused or spent |
| `approval` | Approve/deny/window/revoke decisions |
| `blocked` | A refusal — read-only guard, destructive pattern, agent allowlist |
| `error` | An exception, with type, message and traceback |

Reading it:

```bash
cd /opt/trmm-mcp && ./venv/bin/python logs.py -n 40
```

`-f` follows live, `-k error` or `-k blocked` filters by kind, `-t run_command`
by tool, `--full` prints whole records. It's plain JSONL, so `jq` works too:

```bash
jq -c 'select(.kind=="response" and .ok==false)' /opt/trmm-mcp/logs/events.jsonl
```

Credentials are redacted on the way to disk — the TRMM API keys and the
bearer token are replaced with `<redacted:abcd...>` wherever they appear,
including inside error text. Verified by a test that greps the log for each
live secret.

Two things to know. Tool results are recorded, and for an RMM that means
command output can land in the log — that is usually what you want for an audit
trail, but treat `logs/` as sensitive. Payloads are clipped to
`TRMM_MCP_LOG_PAYLOAD_CHARS` (default 4000, `-1` for everything, `0` to record
sizes only). And nothing is ever written to stdout, because under stdio that
channel carries the protocol.

## Backups

Two things need backing up on this box, and **TacticalRMM itself is the
important one** — it holds agent enrolment, history and MeshCentral state, none
of which can be recreated.

| What | Script | Output |
|---|---|---|
| TacticalRMM (Postgres ×2, MeshCentral, certs, configs) | `/rmm/backup.sh --auto` (ships with TRMM) | `/rmmbackups/{daily,weekly,monthly}` |
| This MCP server (.env, TLS keypair, approval state, code) | `backup-mcp.sh --auto` | `/rmmbackups/mcp/{daily,weekly,monthly}` |

Both use the same retention so there is one scheme to remember: **daily kept 14
days, weekly 60, monthly 380**. Weekly is Friday, monthly is the 10th.

Install the schedule:

```bash
sudo mkdir -p /rmmbackups/{daily,weekly,monthly} /rmmbackups/mcp && sudo chmod 700 /rmmbackups && sudo cp /opt/trmm-mcp/backup-units/*.service /opt/trmm-mcp/backup-units/*.timer /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now mcp-backup.timer trmm-backup.timer
```

The MCP backup deliberately excludes `venv/` (rebuildable from
`requirements.txt`) so an archive is ~200 KB rather than hundreds of megabytes.
Every archive carries a `RESTORE.txt` with step-by-step instructions and a
`MANIFEST.sha256` of every file, plus a `.sha256` alongside it.

**Encrypt before it leaves the box.** An archive contains the TRMM API keys, the
bearer token, the TLS private key and the approval password hash + TOTP secret —
it is a credential store. Create a passphrase file and the script switches to
GPG AES-256 automatically:

```bash
openssl rand -base64 48 > /opt/trmm-mcp/.backup-passphrase && chmod 600 /opt/trmm-mcp/.backup-passphrase
```

Store that passphrase somewhere other than this machine, or the backups are
unrecoverable when you most need them.

Check an archive is actually restorable:

```bash
/opt/trmm-mcp/backup-mcp.sh --verify /rmmbackups/mcp/daily/<file>
```

The script verifies each new archive *before* pruning old ones, so a broken
backup never causes a good one to be deleted. Both services write
`/rmmbackups/LAST_SUCCESS_*` on success and append to
`/rmmbackups/BACKUP-FAILURES.log` on failure — point a TRMM check at the age of
those files and your RMM will tell you when its own backups stop running.

**Still on you:** these all live on the same disk as the data they protect. Copy
`/rmmbackups` somewhere else — that is the difference between a backup and a
convenience.

## Installing as a package

The server is a proper Python package (`pyproject.toml`), pinned to the SDK 2.0
API it targets:

```bash
cd /opt/trmm-mcp && ./venv/bin/pip install -e .
```

That registers a `trmm-mcp` console entry point equivalent to
`python -m trmm_mcp.server`. The existing systemd unit and `run.sh` keep working
either way — installing is only needed if you want the entry point or to build a
distributable wheel.

## Tool annotations

Every tool carries MCP hints (`readOnlyHint` / `destructiveHint` /
`idempotentHint` / `openWorldHint`) so a *client* can reason about safety on its
own — colour a destructive tool, refuse to auto-run one — independent of the
approval gate. They're advisory; the real enforcement is still the out-of-band
gate. The classification lives in one table in `server.py`
(`_DESTRUCTIVE_TOOLS` / `_SAFE_WRITE_TOOLS`), applied after registration, so
adding a tool means adding one line there, not editing a decorator.

## License

AGPL-3.0-or-later (`LICENSE`), with per-file SPDX headers. The copyleft terms
mean anyone who runs a modified copy as a network service must publish their
changes — deliberate, to keep execution-capable forks open.

## Rebuilding the venv

Dependencies are pinned in `requirements.txt`. This matters: the server is
written against **MCP SDK 2.0**, whose API differs from 1.x (`mcp.server.fastmcp`
no longer exists, results arrive as dicts, `is_error` not `isError`). An
unpinned rebuild can silently pull an incompatible SDK.

```bash
cd /opt/trmm-mcp && ./venv/bin/pip install -r requirements.txt
```

## Configuration

All settings are environment variables, read from `.env` in this directory
(real environment variables take precedence).

| Variable | Default | Meaning |
|---|---|---|
| `TRMM_API_URL` | — | Backend base URL |
| `TRMM_MCP_MODE` | `readonly` | `readonly`, `elevate` or `command` |
| `TRMM_MCP_APPROVAL_PASSWORD_HASH` | unset | PBKDF2 hash; set by `setup_approval_auth.py` |
| `TRMM_MCP_APPROVAL_TOTP_SECRET` | unset | Base32 TOTP secret; set by the same script |
| `TRMM_MCP_APPROVAL_SESSION` | `43200` | Approval-page session lifetime, seconds |
| `TRMM_MCP_APPROVAL_MAX_ATTEMPTS` | `5` | Failed sign-ins before lockout |
| `TRMM_MCP_PENDING_TTL` | `600` | Seconds an unapproved request stays open |
| `TRMM_MCP_MAX_GRANT_SECONDS` | `3600` | Ceiling on any approval window |
| `TRMM_MCP_PUBLIC_URL` | derived | Approval URL shown to the user |
| `TRMM_MCP_STATE_DIR` | `./state` | Where grants are persisted |
| `TRMM_READONLY_API_KEY` | — | Key used in read-only mode |
| `TRMM_COMMAND_API_KEY` | — | Key used in command mode only |
| `TRMM_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |
| `TRMM_MCP_HTTP_HOST` / `_PORT` / `_PATH` | `127.0.0.1` / `8770` / `/mcp` | HTTP listener |
| `TRMM_MCP_MAX_RESPONSE_CHARS` | `60000` | Truncation cap per tool result |
| `TRMM_MCP_AGENT_ALLOWLIST` | empty (all) | Restrict execution targets |
| `TRMM_MCP_BLOCK_PATTERNS` | built-in list | Refused command regexes |
| `TRMM_MCP_AUDIT_LOG` | `./command-audit.log` | Mutation log path |
| `TRMM_MCP_LOG_DIR` | `./logs` | Where events.jsonl and server.log live |
| `TRMM_MCP_LOG_LEVEL` | `INFO` | Diagnostic verbosity |
| `TRMM_MCP_LOG_PAYLOAD_CHARS` | `4000` | Per-payload cap; `-1` unlimited, `0` sizes only |
| `TRMM_MCP_LOG_MAX_BYTES` / `_BACKUPS` | `10485760` / `5` | Rotation |
| `TRMM_CA_BUNDLE` | `/opt/trmm-certs/fullchain.pem` | CA for the self-signed origin cert |
| `TRMM_VERIFY_SSL` | `true` | Set false only to disable verification outright |
| `TRMM_HTTP_TIMEOUT` | `60` | Connect/write timeout, seconds |
| `TRMM_HTTP_READ_TIMEOUT` | `300` | Read timeout — must exceed the longest tool timeout, since synchronous runs hold the connection open |

TLS note: rather than disabling verification for the self-signed origin cert,
the server uses that cert as its own CA bundle — so the connection is still
verified.

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

## Testing

```bash
cd /opt/trmm-mcp && ./venv/bin/python e2e_test.py
```

The main one: drives the server over the real MCP protocol exactly as Claude
does — a full read-only diagnostic workflow, then command mode with real
execution and the guards, then the HTTP transport. 25 checks.

```bash
cd /opt/trmm-mcp && TRMM_MCP_MODE=readonly ./venv/bin/python selftest.py
```

Checks live API reads, hostname resolution, payload trimming, and that the
read-only guard blocks writes. Run with `TRMM_MCP_MODE=command` to additionally
verify the destructive-pattern guard and a real command execution.

```bash
cd /opt/trmm-mcp && ./venv/bin/python protocol_test.py readonly
```

Launches the server as a real MCP client would and asserts no execution tools
are exposed over the wire.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `403` on a read | The role lacks that flag — add it in `provision_trmm_accounts.py` and re-run |
| `403` on execution | You are in read-only mode. Expected. |
| `Method "GET" not allowed` | Missing trailing slash, or the endpoint wants PATCH |
| `HTTP 500` on execution | A required body field was missing — see TRMM-API.md §4 |
| `Unable to contact the agent` | Agent offline; there is no queueing |
| `matches several agents` | Ambiguous hostname — pass the agent_id |

## Files

```
provision_trmm_accounts.py   creates TRMM roles/users/keys, writes .env
trmm_mcp/config.py           env config, mode selection, guard patterns
trmm_mcp/client.py           HTTP client, read-only enforcement, audit log
trmm_mcp/server.py           tool definitions
run.sh                       launcher
trmm_mcp/observability.py    logging: event stream, redaction, MCP middleware
trmm_mcp/approval_auth.py    password hashing, TOTP, sessions, lockout
setup_approval_auth.py       enrol the approval-page password + 2FA
approval_auth_test.py        auth suite (hashing, 2FA, replay, lockout)
approve.py                   CLI to approve/deny/window/revoke
logs.py                      read/follow/filter the audit trail
logging_test.py              asserts what gets logged, and that secrets don't
elevation_test.py            elevate-mode suite (refuse, approve, consume, revert)
e2e_test.py                  full protocol-level suite (both modes + HTTP)
selftest.py                  live API checks
smoketest_remaining.py       exercises every read tool against a live agent
protocol_test.py             minimal MCP handshake check
trmm-mcp.service             optional systemd unit for HTTP mode
.env                         credentials (mode 600)
command-audit.log            append-only record of mutating calls
```
