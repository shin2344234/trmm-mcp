# SPDX-License-Identifier: AGPL-3.0-or-later
"""Configuration, loaded from the environment or the sibling .env file."""

from __future__ import annotations

import os
import re
from pathlib import Path

def _resolve_base_dir() -> Path:
    """Where .env, state/, certs/ and the audit log live.

    Three cases, in order:

    1. TRMM_MCP_BASE_DIR, if set. Read from the real environment rather than
       .env, since it decides where .env is found in the first place.
    2. An installed copy (pip/pipx/uvx). The package sits in site-packages,
       whose parent is not a sane place to write credentials and approval
       state - and under uvx it is a disposable cache. Use a per-user
       directory instead.
    3. A clone or editable install: the repo root, as it always has been.
    """
    override = os.environ.get("TRMM_MCP_BASE_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()

    here = Path(__file__).resolve()
    installed = any(p.name in ("site-packages", "dist-packages") for p in here.parents)
    if not installed:
        return here.parent.parent

    if os.name == "nt":
        root = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
    else:
        root = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    base = Path(root).expanduser().resolve() / "trmm-mcp"
    # Holds API keys, the approval password hash and the TOTP secret.
    try:
        base.mkdir(parents=True, exist_ok=True)
        base.chmod(0o700)
    except OSError:
        pass
    return base


BASE_DIR = _resolve_base_dir()

READONLY = "readonly"
ELEVATE = "elevate"
COMMAND = "command"


def _load_env_file(path: Path) -> None:
    """Minimal .env reader. Real environment variables always win."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file(BASE_DIR / ".env")


def _flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


class ConfigError(SystemExit):
    pass


MODE = os.environ.get("TRMM_MCP_MODE", READONLY).strip().lower()
if MODE not in (READONLY, ELEVATE, COMMAND):
    raise ConfigError(
        f"TRMM_MCP_MODE must be one of {READONLY!r}, {ELEVATE!r}, {COMMAND!r}; got {MODE!r}"
    )

API_URL = os.environ.get("TRMM_API_URL", "").strip().rstrip("/")
if not API_URL:
    raise ConfigError("TRMM_API_URL is not set (e.g. https://api.example.com)")

_READONLY_KEY = os.environ.get("TRMM_READONLY_API_KEY", "").strip()
_COMMAND_KEY = (
    os.environ.get("TRMM_COMMAND_API_KEY", "").strip()
    if MODE in (ELEVATE, COMMAND)
    else ""
)

# The command key is never retained in this module in read-only mode, so the
# HTTP client has no path to an execution-capable credential.
#
# In elevate mode both keys are held, but reads still go out under the
# read-only key - only an approved execution is allowed to use the command key.
API_KEY = _COMMAND_KEY if MODE == COMMAND else _READONLY_KEY
if not API_KEY:
    missing = "TRMM_COMMAND_API_KEY" if MODE == COMMAND else "TRMM_READONLY_API_KEY"
    raise ConfigError(f"{missing} is not set but TRMM_MCP_MODE={MODE}")

COMMAND_API_KEY = _COMMAND_KEY
if MODE == ELEVATE and not COMMAND_API_KEY:
    raise ConfigError("TRMM_COMMAND_API_KEY is not set but TRMM_MCP_MODE=elevate")

IS_READONLY = MODE == READONLY
EXEC_TOOLS_ENABLED = MODE in (ELEVATE, COMMAND)
REQUIRE_APPROVAL = MODE == ELEVATE

# Where pending approval requests and active grants are persisted, so the CLI,
# the web approval page and the MCP process all see the same state.
STATE_DIR = Path(os.environ.get("TRMM_MCP_STATE_DIR", str(BASE_DIR / "state")))

# How long an unapproved request stays open before it must be re-issued.
PENDING_TTL = int(os.environ.get("TRMM_MCP_PENDING_TTL", "600"))

# Ceiling on any single time-boxed grant.
MAX_GRANT_SECONDS = int(os.environ.get("TRMM_MCP_MAX_GRANT_SECONDS", "3600"))

# Credentials for the approval page. Deliberately separate from the bearer
# token: every MCP client holds that token, and the whole point of the approval
# page is to be somewhere the client cannot reach.
APPROVAL_PASSWORD_HASH = os.environ.get("TRMM_MCP_APPROVAL_PASSWORD_HASH", "").strip()
APPROVAL_TOTP_SECRET = os.environ.get("TRMM_MCP_APPROVAL_TOTP_SECRET", "").strip()
APPROVAL_SESSION_SECONDS = int(os.environ.get("TRMM_MCP_APPROVAL_SESSION", "43200"))
APPROVAL_MAX_ATTEMPTS = int(os.environ.get("TRMM_MCP_APPROVAL_MAX_ATTEMPTS", "5"))

HTTP_TIMEOUT = float(os.environ.get("TRMM_HTTP_TIMEOUT", "60"))

# Synchronous command/script runs keep the connection open for the whole
# execution, so the read phase has to allow for the longest tool timeout a
# caller can ask for, plus TRMM's own few seconds of overhead.
HTTP_READ_TIMEOUT = float(
    os.environ.get("TRMM_HTTP_READ_TIMEOUT", str(max(HTTP_TIMEOUT, 300.0)))
)

# stdio: Claude launches the server itself (same machine).
# streamable-http: long-running service, reachable from another machine.
TRANSPORT = os.environ.get("TRMM_MCP_TRANSPORT", "stdio").strip().lower()
if TRANSPORT in ("http", "streamable_http"):
    TRANSPORT = "streamable-http"
if TRANSPORT not in ("stdio", "streamable-http"):
    raise ConfigError(f"TRMM_MCP_TRANSPORT must be stdio or streamable-http, got {TRANSPORT!r}")

# Bind to loopback by default: the listener has no authentication of its own,
# so anything that can reach it inherits this server's TRMM permissions.
LISTEN_HOST = os.environ.get("TRMM_MCP_HTTP_HOST", "127.0.0.1").strip()
LISTEN_PORT = int(os.environ.get("TRMM_MCP_HTTP_PORT", "8770"))
HTTP_PATH = os.environ.get("TRMM_MCP_HTTP_PATH", "/mcp").strip()

# Stateful streamable-HTTP hands the client a session id that dies with the
# process, so every server restart wedges a connected client until it is
# restarted too (it keeps replaying a session the server has forgotten, and the
# call simply hangs). We use no server-initiated requests or resumable streams,
# so statelessness costs nothing and makes restarts survivable.
STATELESS_HTTP = _flag("TRMM_MCP_STATELESS_HTTP", True)

# TLS for our own listener. Self-signed is fine here - the cert carries an IP
# SAN for the address clients actually dial, and each client is told to trust
# this one certificate rather than being told to skip verification.
_default_cert = BASE_DIR / "certs" / "cert.pem"
_default_key = BASE_DIR / "certs" / "key.pem"
TLS_CERT = os.environ.get("TRMM_MCP_TLS_CERT", str(_default_cert)).strip()
TLS_KEY = os.environ.get("TRMM_MCP_TLS_KEY", str(_default_key)).strip()
TLS_ENABLED = (
    _flag("TRMM_MCP_TLS", True)
    and bool(TLS_CERT)
    and Path(TLS_CERT).exists()
    and Path(TLS_KEY).exists()
)
SCHEME = "https" if TLS_ENABLED else "http"

# Shared secret for the HTTP listener. Required whenever the listener is bound
# to anything other than loopback - an unauthenticated port here would hand the
# whole RMM to anything on the network.
AUTH_TOKEN = os.environ.get("TRMM_MCP_AUTH_TOKEN", "").strip()

_LOOPBACK = ("127.0.0.1", "localhost", "::1")
if TRANSPORT != "stdio" and LISTEN_HOST not in _LOOPBACK and not AUTH_TOKEN:
    raise ConfigError(
        f"Refusing to listen on {LISTEN_HOST} without authentication. "
        f"Set TRMM_MCP_AUTH_TOKEN, or bind to 127.0.0.1."
    )

# The MCP SDK enables DNS-rebinding protection by default with an empty
# allowlist, which rejects any Host header we do not name here.
_extra_hosts = [
    h.strip()
    for h in os.environ.get("TRMM_MCP_ALLOWED_HOSTS", "").split(",")
    if h.strip()
]
ALLOWED_HOSTS: list[str] = []
for _host in [LISTEN_HOST, "127.0.0.1", "localhost", *_extra_hosts]:
    for _candidate in (_host, f"{_host}:{LISTEN_PORT}"):
        if _candidate not in ALLOWED_HOSTS:
            ALLOWED_HOSTS.append(_candidate)

# The TRMM origin cert is self-signed, so use it as its own CA bundle rather
# than disabling verification outright.
_DEFAULT_CA = "/opt/trmm-certs/fullchain.pem"
_ca_bundle = os.environ.get("TRMM_CA_BUNDLE", "").strip()
if not _flag("TRMM_VERIFY_SSL", True):
    VERIFY: bool | str = False
elif _ca_bundle:
    VERIFY = _ca_bundle
elif Path(_DEFAULT_CA).exists():
    VERIFY = _DEFAULT_CA
else:
    VERIFY = True

# Cap on serialized tool output, to keep a single call from flooding the model's
# context. TRMM has no pagination, so some endpoints return entire tables.
MAX_RESPONSE_CHARS = int(os.environ.get("TRMM_MCP_MAX_RESPONSE_CHARS", "60000"))

AUDIT_LOG = Path(
    os.environ.get("TRMM_MCP_AUDIT_LOG", str(BASE_DIR / "command-audit.log"))
)

# --- logging -------------------------------------------------------------
LOG_DIR = Path(os.environ.get("TRMM_MCP_LOG_DIR", str(BASE_DIR / "logs")))
LOG_LEVEL = os.environ.get("TRMM_MCP_LOG_LEVEL", "INFO").upper()
LOG_MAX_BYTES = int(os.environ.get("TRMM_MCP_LOG_MAX_BYTES", str(10 * 1024 * 1024)))
LOG_BACKUPS = int(os.environ.get("TRMM_MCP_LOG_BACKUPS", "5"))

# How much of each payload (tool arguments, results, API bodies) to record.
# -1 keeps everything, 0 records only sizes.
LOG_PAYLOAD_CHARS = int(os.environ.get("TRMM_MCP_LOG_PAYLOAD_CHARS", "4000"))

# Strings that must never reach a log file.
SECRETS = [s for s in (_READONLY_KEY, _COMMAND_KEY, AUTH_TOKEN) if s and len(s) > 7]

# Optional hard scope: only these agent_ids/hostnames may be targeted by any
# execution tool. Empty means every agent the API key can see.
AGENT_ALLOWLIST = {
    item.strip()
    for item in os.environ.get("TRMM_MCP_AGENT_ALLOWLIST", "").split(",")
    if item.strip()
}

# Commands matching these patterns are refused client-side in command mode.
# Set TRMM_MCP_BLOCK_PATTERNS="" to disable entirely.
_DEFAULT_BLOCK_PATTERNS = r"""
rm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*/(\s|$)
mkfs(\.|\s)
\bdd\s+.*\bof=/dev/
format\s+[a-zA-Z]:
diskpart
\bcipher\s+/w
Remove-Item\s+.*[Cc]:\\?\s*(-Recurse|$)
shutdown\s+.*(/f|-f).*(/t\s*0|-t\s*0)
"""
_patterns_raw = os.environ.get("TRMM_MCP_BLOCK_PATTERNS")
if _patterns_raw is None:
    _patterns = [p for p in _DEFAULT_BLOCK_PATTERNS.split("\n") if p.strip()]
elif _patterns_raw.strip():
    _patterns = [p for p in _patterns_raw.split("\n") if p.strip()]
else:
    _patterns = []

BLOCK_PATTERNS = [re.compile(p.strip(), re.IGNORECASE) for p in _patterns]

# Base URL shown to the user when an execution needs approval. Must be reachable
# from their browser, which is not necessarily the address we bind to.
PUBLIC_URL = os.environ.get(
    "TRMM_MCP_PUBLIC_URL", f"{SCHEME}://{LISTEN_HOST}:{LISTEN_PORT}"
).rstrip("/")
