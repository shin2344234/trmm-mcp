# Documentation

The [README](../README.md) covers the pitch, the three modes, setting the server
up and running it, and a summary of the tools. Everything else lives here.

| | |
|---|---|
| **[security.md](security.md)** | How the approval gate works, protecting the approval page with password + TOTP, TLS, why MCP elicitation is not used, why read-only actually holds, the honest caveat about layer 3, and the safety features in `command` mode |
| **[installation.md](installation.md)** | Installing from PyPI versus cloning the repo, where an installed copy keeps its credentials and state, and rebuilding the virtualenv |
| **[clients.md](clients.md)** | Connecting Claude Code, Claude Desktop and LM Studio on macOS, Windows and Linux; running over SSH with no open port; installing the TLS certificate |
| **[tools.md](tools.md)** | The full 28-tool reference, what is deliberately not exposed, the MCP tool annotations, context-size handling and the output shape |
| **[operations.md](operations.md)** | The audit trail and the two browser pages that read it, backups, the test suites, and troubleshooting |
| **[configuration.md](configuration.md)** | Every environment variable with its default, and what each file in the repo is for |
| **[trmm-api.md](trmm-api.md)** | Independent documentation of the TacticalRMM API this server talks to |

## Where a section went

Everything that used to be in the README is still here, in full. If you are
looking for something specific:

| Was | Now |
|---|---|
| Three modes, How elevate works, Protecting the approval page, TLS, Why not MCP elicitation, Why read-only is actually read-only, One honest caveat about layer 3, Safety features in command mode | [security.md](security.md) |
| Setup, Running the server | [README](../README.md#setup) — kept there |
| Installing as a package, Where it keeps its files, Rebuilding the venv | [installation.md](installation.md) |
| Connecting a client and all four client sections, Trusting the certificate | [clients.md](clients.md) |
| Tools, Deliberately not exposed, Tool annotations, Context-size handling, Output shape | [tools.md](tools.md) |
| Audit logging, Reading it in the browser, Reviewing what was run, Backups, Testing, Troubleshooting | [operations.md](operations.md) |
| Configuration, Files | [configuration.md](configuration.md) |
| `TRMM-API.md` at the top level | [trmm-api.md](trmm-api.md) |
