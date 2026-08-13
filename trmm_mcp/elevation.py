# SPDX-License-Identifier: AGPL-3.0-or-later
"""Out-of-band approval for privileged operations.

The model can ask for an execution but cannot approve one. Approval happens
through a channel the model has no access to - a browser page or the CLI - and
is bound to the exact call that was requested, so an approval for
`hostname` cannot be spent on `del /f /s /q C:\\`.

Two grant shapes:

  request  a single named call, matched by fingerprint, consumed on use
  window   a time-boxed allowance for several calls, for a burst of work

State lives in a JSON file under a lock so the MCP process, the approval web
page and the CLI all agree, even across a restart.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import time
from contextlib import contextmanager
from typing import Any

from . import config

STATE_FILE = config.STATE_DIR / "elevation.json"
LOCK_FILE = config.STATE_DIR / "elevation.lock"

_EMPTY: dict[str, Any] = {"pending": [], "windows": [], "log": []}


def _ensure_dir() -> None:
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(config.STATE_DIR, 0o700)
    except OSError:
        pass


@contextmanager
def _locked_state():
    """Read-modify-write the state file under an exclusive lock."""
    _ensure_dir()
    with open(LOCK_FILE, "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            try:
                data = json.loads(STATE_FILE.read_text())
            except (OSError, ValueError):
                data = json.loads(json.dumps(_EMPTY))
            for key in _EMPTY:
                data.setdefault(key, [])

            _prune(data)
            yield data

            tmp = STATE_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2))
            os.chmod(tmp, 0o600)
            os.replace(tmp, STATE_FILE)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _prune(data: dict[str, Any]) -> None:
    now = time.time()
    data["pending"] = [
        p
        for p in data["pending"]
        if p.get("expires", 0) > now and p.get("status") in ("pending", "approved")
    ]
    data["windows"] = [
        w
        for w in data["windows"]
        if w.get("expires", 0) > now and (w.get("uses_left") is None or w["uses_left"] > 0)
    ]
    data["log"] = data["log"][-200:]


def fingerprint(tool: str, params: dict[str, Any]) -> str:
    """Stable identity for one specific call."""
    payload = json.dumps({"tool": tool, "params": params}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def _record(data: dict[str, Any], event: str, detail: str) -> None:
    data["log"].append({"time": time.time(), "event": event, "detail": detail})
    # Also surface every approval decision in the main audit stream.
    from . import observability

    observability.event("approval", decision=event, detail=detail)


def request(
    tool: str,
    summary: str,
    params: dict[str, Any],
    display: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Open an approval request for one call. Returns the pending record.

    `display` carries human-readable detail captured here, at request time -
    the hostname behind an agent_id, a script's name, a plain-English action.
    The approval page has no API client of its own and cannot look any of this
    up later. It is presentation only and is deliberately excluded from the
    fingerprint, so it can never affect what an approval authorises.
    """
    fp = fingerprint(tool, params)
    with _locked_state() as data:
        for existing in data["pending"]:
            if existing["fingerprint"] == fp:
                return dict(existing)

        record = {
            "id": secrets.token_urlsafe(8),
            "fingerprint": fp,
            "tool": tool,
            "summary": summary,
            "params": params,
            "display": display or {},
            "created": time.time(),
            "expires": time.time() + config.PENDING_TTL,
            "status": "pending",
        }
        data["pending"].append(record)
        _record(data, "requested", f"{tool}: {summary}")
        return dict(record)


def consume(tool: str, params: dict[str, Any]) -> tuple[bool, str]:
    """Spend an approval for this exact call, or an open window.

    Returns (allowed, reason).
    """
    fp = fingerprint(tool, params)
    with _locked_state() as data:
        for record in data["pending"]:
            if record["fingerprint"] == fp and record["status"] == "approved":
                record["status"] = "consumed"
                _record(data, "consumed", f"{tool}: {record['summary']}")
                data["pending"] = [p for p in data["pending"] if p is not record]
                return True, "approved for this specific call"

        now = time.time()
        for window in data["windows"]:
            if window["expires"] <= now:
                continue
            scope = window.get("agent")
            if scope and scope not in (params.get("agent"), params.get("agent_id")):
                continue
            if window.get("uses_left") is not None:
                window["uses_left"] -= 1
            remaining = int(window["expires"] - now)
            _record(data, "window-use", f"{tool} under window {window['id']}")
            return True, f"covered by an approval window ({remaining}s left)"

    return False, "no approval"


def approve(request_id: str) -> dict[str, Any] | None:
    with _locked_state() as data:
        for record in data["pending"]:
            if record["id"] == request_id and record["status"] == "pending":
                record["status"] = "approved"
                record["approved_at"] = time.time()
                _record(data, "approved", f"{record['tool']}: {record['summary']}")
                return dict(record)
    return None


def deny(request_id: str) -> bool:
    with _locked_state() as data:
        for record in data["pending"]:
            if record["id"] == request_id:
                _record(data, "denied", f"{record['tool']}: {record['summary']}")
                data["pending"] = [p for p in data["pending"] if p["id"] != request_id]
                return True
    return False


def open_window(seconds: int, uses: int | None = None, agent: str | None = None) -> dict:
    seconds = max(1, min(int(seconds), config.MAX_GRANT_SECONDS))
    with _locked_state() as data:
        window = {
            "id": secrets.token_urlsafe(6),
            "expires": time.time() + seconds,
            "uses_left": uses,
            "agent": agent,
            "created": time.time(),
        }
        data["windows"].append(window)
        _record(data, "window-opened", f"{seconds}s uses={uses} agent={agent or 'any'}")
        return dict(window)


def revoke_all() -> None:
    """Drop every grant immediately - the panic button."""
    with _locked_state() as data:
        data["pending"] = []
        data["windows"] = []
        _record(data, "revoked", "all grants cleared")


def snapshot() -> dict[str, Any]:
    with _locked_state() as data:
        return json.loads(json.dumps(data))
