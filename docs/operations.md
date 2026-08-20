# Operations

Running this thing day to day: the audit trail and the two browser pages that
read it, backups, the test suites, and the symptoms you are most likely to hit.

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

### Reading it in the browser

The approval page has a **View activity log** button leading to
`/approve/history`, behind the same password + 2FA. It reads the same
`events.jsonl`, so there is one audit trail rather than a second one that can
disagree with the first.

Filter chips narrow it to approvals, changes actually made, refused commands,
problems, sign-ins, tool calls or TRMM API traffic; there is a free-text
search, and the row count goes up to 1000. Only the tail of the log is scanned
(the last 20,000 lines), so a filter that matches nothing recent cannot turn
into a full scan of a large file — the page says so when that limit is what
bounded the results.

Every value shown comes from the model or from a managed machine, so it is
escaped and passed through the same treatment the approval page gives a
command: bidi overrides, zero-width and control characters are rendered as
visible markers like `⟦202E⟧` rather than being obeyed. A logged command cannot
reorder itself into looking harmless on the page you use to audit it.

Each row opens. Clicking one expands it to the long form: for an execution
that means the verbatim command, the facts (shell, privilege, timeout), how it
ended, and what the machine printed — reconstructed by pairing the request with
its response. Every row also carries the raw JSON record underneath. It uses
`<details>`, so there is no JavaScript involved and it works with the keyboard.

Filtering does not break the pairing: the correlation index is built from every
scanned line rather than the filtered subset, so narrowing to "Tool calls" still
shows you the response that says what the call did.

### Reviewing what was run

`/approve/commands` — linked from the approval page as **Review commands run** —
answers the question people actually ask: what has been run on my machines, and
what came back. One card per execution, correlated request-to-response, showing
the verbatim command in a numbered block and the machine's output beneath it.

Each card is labelled with what actually happened, which is not the same as what
was asked for:

| Label | Meaning |
|---|---|
| `RAN` | Executed, output shown |
| `FAILED` | Executed and errored |
| `NEEDED APPROVAL — DID NOT RUN` | The gate refused it |
| `BLOCKED BY A GUARD` | Refused by the destructive-pattern guard |
| `NO RESULT RECORDED` | Asked for, no response logged (e.g. a crash) |

Refused attempts are deliberately kept. What was asked for and denied is as much
of the audit record as what ran.

Filter by outcome, or search across the command text, the machine name and the
output. Pairing is keyed on process id *and* request id, because request ids
restart at 1 with every session — matching on the id alone would attribute one
session's output to another session's command.

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

```bash
cd /opt/trmm-mcp && ./venv/bin/python config_test.py
```

Checks where `.env`, `state/`, `certs/` and the audit log get resolved to, for a
clone, a pip install and an explicit `TRMM_MCP_BASE_DIR` — the case that matters
being that an installed copy never writes credentials into `site-packages`.
9 checks, no network or live TRMM needed.

The remaining suites — `render_test.py`, `elevation_test.py`,
`approval_auth_test.py`, `logging_test.py` — cover the approval-page rendering
and spoofing defences, the approval lifecycle, the password/TOTP gate and the
audit log, and likewise run offline.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `403` on a read | The role lacks that flag — add it in `provision_trmm_accounts.py` and re-run |
| `403` on execution | You are in read-only mode. Expected. |
| `Method "GET" not allowed` | Missing trailing slash, or the endpoint wants PATCH |
| `HTTP 500` on execution | A required body field was missing — see [trmm-api.md](trmm-api.md) §4 |
| `Unable to contact the agent` | Agent offline; there is no queueing |
| `matches several agents` | Ambiguous hostname — pass the agent_id |

