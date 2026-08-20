# Changelog

Notable changes to the TacticalRMM MCP server. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-08-20

Three new views on the approval page, so the audit trail is readable without
shell access to the server.

### Added

- **Commands run** (`/approve/commands`) — one card per execution attempt,
  correlated request-to-response, showing the verbatim command in a numbered
  block and the machine's output beneath it. Cards are labelled by what
  actually happened rather than what was asked for: ran, failed, refused by the
  approval gate, blocked by the destructive-pattern guard, or no result
  recorded. Refused attempts are kept — what was asked for and denied is part
  of the record. Filter by outcome, or search across command text, machine name
  and output.
- **Activity log** (`/approve/history`) — the full event stream, filterable to
  approvals, executions, refusals, problems, sign-ins, tool calls or TRMM API
  traffic, with free-text search. Rows are `<details>` elements: opening one
  shows the verbatim command, its facts, how it ended, what the machine
  printed, and the raw JSON record. No JavaScript.
- Both pages sit behind the existing approval-page password + TOTP, and read
  the same `events.jsonl` the `trmm-mcp-logs` CLI reads, so there is one audit
  trail rather than two that can disagree.
- `history_test.py` (28 checks) and `commands_test.py` (32 checks).

### Fixed

- **Fact values on the approval page are now unmasked, not just escaped.**
  `render.facts_table` HTML-escapes but leaves bidi and zero-width characters
  intact, which is correct for the server-written facts it was built for. The
  approval card also feeds it model-supplied values — a service name, script
  arguments, and when a request carries no display block, the raw parameters.
  A `U+202E` in a service name could therefore reorder what the approval page
  showed before you approved it. Those values now get the same treatment a
  command block gets. `render.facts_table` itself is unchanged.
- A meta line ran an HTML entity through `html.escape` and rendered a literal
  `&middot;`.

### Notes

Only the tail of the log is scanned (the last 20,000 lines), so a filter
matching nothing recent cannot become a full read of a large file; both pages
say when that window is what bounded the results. Request/response pairing is
keyed on `(pid, request_id)` because `request_id` restarts at 1 every session —
matching on the id alone attributes one session's output to another session's
command.

## [1.0.1] — 2026-08-14

### Fixed

- **An installed copy no longer keeps its files in `site-packages`.**
  `BASE_DIR` was derived from the package location: correct for a clone, but
  `site-packages` for a `pip install`. An installed copy would look for `.env`
  there, put approval state and TLS material there, and
  `trmm-mcp-setup-auth` would write the approval password hash and TOTP secret
  in among the installed packages. Under `uvx`, whose cache is disposable,
  approval state would not survive a restart at all.

### Added

- `TRMM_MCP_BASE_DIR`. Resolution order is now that variable, then a per-user
  directory when the package is detected inside `site-packages`/`dist-packages`
  (`$XDG_DATA_HOME/trmm-mcp`, defaulting to `~/.local/share/trmm-mcp`, or
  `%APPDATA%\trmm-mcp` on Windows, created mode `0700`), then the previous
  behaviour. A clone or `pip install -e .` resolves exactly as before.
- The operator CLIs ship in the wheel: `trmm-mcp-setup-auth`,
  `trmm-mcp-approve`, `trmm-mcp-logs` alongside `trmm-mcp`. Previously an
  installed copy could run the server but had no way to enrol the approval
  password and TOTP that `elevate` mode needs.
- `server.json` for the official MCP registry.
- `config_test.py` (9 checks).
- README documents the PyPI install, what the wheel does and does not ship, and
  which install path suits which mode.

## [1.0.0] — 2026-08-13

Initial public release.

- 28 tools: 20 read-only covering agents, checks, alerts, services, processes,
  event logs, software inventory, patches, scripts and audit history; 8
  execution tools for commands, scripts, reboots, service control, killing
  processes and wake-on-LAN.
- Three modes: `readonly`, `elevate` and `command`.
- An out-of-band approval gate that no tool can reach. Approvals are bound to a
  fingerprint of the exact arguments, single-use, and expire.
- Read-only enforced in three independent layers, the outermost being a TRMM
  role with no execution permissions.
- Structured JSONL audit logging with credential redaction and rotation.
- Approval page protected by PBKDF2 password + TOTP, with replay prevention and
  exponential-backoff lockout.
- HTTPS with a self-signed certificate carrying an IP SAN, bearer auth, and a
  hardened systemd unit.
- Independent documentation of the TRMM API in `TRMM-API.md`.

[1.1.0]: https://github.com/shin2344234/trmm-mcp/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/shin2344234/trmm-mcp/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/shin2344234/trmm-mcp/releases/tag/v1.0.0
