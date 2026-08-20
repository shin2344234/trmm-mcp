# Installation

Installing from PyPI versus cloning, where an installed copy keeps its
credentials and state, and how to rebuild the virtualenv.

Setting up the server itself — provisioning the TRMM roles and API keys, and
running it under systemd — is in the
[README](../README.md#setup).

## Installing as a package

Published on PyPI as [`trmm-mcp`](https://pypi.org/project/trmm-mcp/):

```bash
pip install trmm-mcp
```

That gives you four console entry points — `trmm-mcp` (the server, equivalent to
`python -m trmm_mcp.server`), plus `trmm-mcp-setup-auth`, `trmm-mcp-approve` and
`trmm-mcp-logs`. A client config can then just say `"command": "trmm-mcp"`.

**Which install do you want?**

| | `pip install trmm-mcp` | git clone |
|---|---|---|
| read-only mode | yes | yes |
| elevate / command mode | possible, but see below | recommended |
| `provision_trmm_accounts.py` | not included | included |
| systemd unit, `backup-mcp.sh` | not included | included |

The wheel deliberately ships only the `trmm_mcp` package. The provisioning
script that creates the TRMM roles and API keys, the systemd unit and the backup
scripts are operational tooling, not library code, so they live in the repo. For
read-only use none of that matters: pass `TRMM_API_URL` and
`TRMM_READONLY_API_KEY` in your client's `env` block and you are done.

Elevate mode is the awkward one. It wants a persistent state directory, a TLS
keypair and enrolled approval credentials, plus something to keep the process
running — which is what the clone gives you. It will work from a pip install,
but you are assembling by hand what the repo already has.

### Where it keeps its files

`.env`, `state/`, `certs/`, `logs/` and `command-audit.log` all sit under one
base directory, resolved in this order:

1. `TRMM_MCP_BASE_DIR`, if set.
2. An installed copy (pip/pipx/uvx): `$XDG_DATA_HOME/trmm-mcp`, defaulting to
   `~/.local/share/trmm-mcp` (`%APPDATA%\trmm-mcp` on Windows). Created mode
   `0700`, because it holds API keys, the approval password hash and the TOTP
   secret.
3. A clone or `pip install -e .`: the repo root, as before.

Set `TRMM_MCP_BASE_DIR` explicitly if you want it somewhere else — and do set it
if you run from `uvx`, whose cache is disposable and would otherwise take your
approval state with it.

To work on the code in place, `cd /opt/trmm-mcp && ./venv/bin/pip install -e .`
still behaves exactly as a clone does. The systemd unit and `run.sh` keep
working either way.

## Rebuilding the venv

Dependencies are pinned in `requirements.txt`. This matters: the server is
written against **MCP SDK 2.0**, whose API differs from 1.x (`mcp.server.fastmcp`
no longer exists, results arrive as dicts, `is_error` not `isError`). An
unpinned rebuild can silently pull an incompatible SDK.

```bash
cd /opt/trmm-mcp && ./venv/bin/pip install -r requirements.txt
```

