# SPDX-License-Identifier: AGPL-3.0-or-later
"""Password + TOTP authentication for the approval page.

The approval page is the one thing standing between a model asking to run
something and it actually running, so it gets its own credentials rather than
reusing the bearer token that every MCP client already holds.

  password   PBKDF2-HMAC-SHA256, 600k iterations, per-install salt
  second     TOTP (RFC 6238), 30s step, one step of drift either way
  session    HMAC-signed cookie carrying only an expiry and an epoch

Codes cannot be replayed, failures are rate limited, and bumping the epoch
invalidates every outstanding session at once.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any

import pyotp

from . import config

PBKDF2_ROUNDS = 600_000
SESSION_FILE = config.STATE_DIR / "approval_sessions.json"

# Failed attempts, per client address. In memory: a restart clears them, which
# is acceptable given the lockout exists to slow guessing, not to store state.
_failures: dict[str, dict[str, float]] = {}

# TOTP counters already spent, so a captured code cannot be replayed.
_used_counters: set[tuple[str, int]] = set()


def is_configured() -> bool:
    return bool(config.APPROVAL_PASSWORD_HASH and config.APPROVAL_TOTP_SECRET)


# --- password -------------------------------------------------------------


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_b64, digest_b64 = encoded.split("$")
        if algo != "pbkdf2_sha256":
            return False
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), base64.b64decode(salt_b64), int(rounds)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# --- second factor --------------------------------------------------------


def check_totp(code: str) -> int | None:
    """Validate a code without spending it.

    Returns the time step it matched, or None. Checking and consuming are kept
    apart deliberately: burning the counter here would mean a mistyped password
    invalidates a perfectly good code, and would let anyone who can reach the
    login form exhaust the real user's codes.
    """
    secret = config.APPROVAL_TOTP_SECRET
    if not secret:
        return None
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return None

    totp = pyotp.TOTP(secret)
    counter = int(time.time()) // 30
    # One step either side absorbs clock drift.
    for candidate in (counter, counter - 1, counter + 1):
        if totp.verify(code, for_time=candidate * 30):
            if (secret[:6], candidate) in _used_counters:
                return None  # already spent
            return candidate
    return None


def consume_totp(counter: int) -> None:
    """Spend a time step so the same code cannot be replayed."""
    secret = config.APPROVAL_TOTP_SECRET
    _used_counters.add((secret[:6], counter))
    now = int(time.time()) // 30
    for entry in list(_used_counters):
        if entry[1] < now - 3:  # older steps can no longer verify anyway
            _used_counters.discard(entry)


# --- lockout --------------------------------------------------------------


def locked_for(client: str) -> int:
    record = _failures.get(client)
    if not record:
        return 0
    remaining = int(record.get("until", 0) - time.time())
    return max(0, remaining)


def note_failure(client: str) -> None:
    record = _failures.setdefault(client, {"count": 0, "until": 0})
    record["count"] = record.get("count", 0) + 1
    if record["count"] >= config.APPROVAL_MAX_ATTEMPTS:
        # Back off harder the longer they keep going.
        over = record["count"] - config.APPROVAL_MAX_ATTEMPTS
        record["until"] = time.time() + min(900, 30 * (2**over))


def note_success(client: str) -> None:
    _failures.pop(client, None)


# --- sessions -------------------------------------------------------------


def _signing_key() -> bytes:
    return hashlib.sha256(
        (config.APPROVAL_PASSWORD_HASH + config.APPROVAL_TOTP_SECRET + "session").encode()
    ).digest()


def _epoch() -> int:
    try:
        return int(json.loads(SESSION_FILE.read_text()).get("epoch", 1))
    except (OSError, ValueError):
        return 1


def bump_epoch() -> None:
    """Invalidate every outstanding session."""
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_text(json.dumps({"epoch": _epoch() + 1}))
    try:
        os.chmod(SESSION_FILE, 0o600)
    except OSError:
        pass


def issue_session() -> str:
    payload = {"exp": int(time.time()) + config.APPROVAL_SESSION_SECONDS,
               "epoch": _epoch(), "nonce": secrets.token_urlsafe(8)}
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hmac.new(_signing_key(), raw.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{raw}.{signature}"


def valid_session(cookie: str | None) -> bool:
    if not cookie or "." not in cookie:
        return False
    raw, _, signature = cookie.rpartition(".")
    expected = hmac.new(_signing_key(), raw.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(signature, expected):
        return False
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload: dict[str, Any] = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError):
        return False
    if payload.get("exp", 0) < time.time():
        return False
    return int(payload.get("epoch", 0)) == _epoch()


def provisioning_uri(secret: str, label: str = "TRMM MCP approvals") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name="TacticalRMM MCP")
