# Security

How the approval gate works, why read-only holds, and what the honest limits
are. This is the part of the design worth reading before you switch on
`elevate`.

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

The MCP client does not retain or use the command key in read-only mode.

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

## Safety features in command mode

- Every mutating call is audit-logged to `command-audit.log` as JSON lines
  (timestamp, mode, method, path, body, outcome), refusals included.
- Destructive-command patterns are refused client-side: `rm -rf /`, `mkfs`,
  `dd of=/dev/*`, `format c:`, `diskpart`, `cipher /w`, recursive `Remove-Item`
  on `C:\`, and forced immediate `shutdown`. Override with
  `TRMM_MCP_BLOCK_PATTERNS` (set empty to disable).
- Optional agent allowlist: set `TRMM_MCP_AGENT_ALLOWLIST` to a comma-separated
  list of hostnames/agent_ids to hard-scope what can be touched.

