# Configuration and files

Every environment variable the server reads with its default, and what each file
in the repo is for.

## Configuration

All settings are environment variables, read from `.env` in the base directory
(real environment variables take precedence). Paths shown as `./x` below are
relative to that base directory — see
[Where it keeps its files](installation.md#where-it-keeps-its-files).

| Variable | Default | Meaning |
|---|---|---|
| `TRMM_API_URL` | — | Backend base URL |
| `TRMM_MCP_BASE_DIR` | repo root, or `~/.local/share/trmm-mcp` when installed | Where `.env`, `state/`, `certs/` and logs live |
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
| `TRMM_COMMAND_API_KEY` | — | Key used for executions in `elevate` and `command` modes |
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
