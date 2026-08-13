# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP client for the TacticalRMM API, with read-only enforcement."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from . import config, observability


class TrmmError(RuntimeError):
    """A TRMM API call failed, with a message meant for the model to read."""


# In read-only mode only these (method, path) combinations are permitted.
# GET is allowed everywhere. TRMM queries alerts and logs over PATCH with a
# filter body, so a naive "GET only" rule would break legitimate reads.
_READ_PATCH_PATHS = (
    re.compile(r"^/alerts/$"),
    re.compile(r"^/logs/audit/$"),
    re.compile(r"^/logs/debug/$"),
)


def _normalize_path(path: str) -> str:
    """TRMM requires trailing slashes; omitting one turns POST into a redirected GET."""
    if not path.startswith("/"):
        path = "/" + path
    base, sep, query = path.partition("?")
    if not base.endswith("/"):
        base += "/"
    return base + sep + query


def _audit(method: str, path: str, body: Any, outcome: str) -> None:
    """Append to the dedicated mutation log, and to the unified event stream."""
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "mode": config.MODE,
        "method": method,
        "path": path,
        "body": body,
        "outcome": outcome,
    }
    try:
        with config.AUDIT_LOG.open("a") as handle:
            handle.write(json.dumps(observability.redact(entry), default=str) + "\n")
    except OSError:
        # Auditing must never take the server down.
        pass
    observability.event(
        "mutation", method=method, path=path, body=body, outcome=outcome
    )


class TrmmClient:
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=config.API_URL,
                headers={
                    "X-API-KEY": config.API_KEY,
                    "Content-Type": "application/json",
                    "User-Agent": "trmm-mcp/1.0",
                },
                # Connect/write/pool stay short, but the read phase must outlast
                # the longest tool timeout: TRMM holds the connection open for
                # the whole run of a synchronous command or script, so a 90s
                # script under a 60s read timeout reports a spurious failure for
                # work that actually succeeded.
                timeout=httpx.Timeout(
                    config.HTTP_TIMEOUT,
                    read=config.HTTP_READ_TIMEOUT,
                ),
                verify=config.VERIFY,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _guard(self, method: str, path: str) -> None:
        """Refuse anything that is not a read while in read-only mode."""
        if not config.IS_READONLY:
            return
        if method == "GET":
            return
        if method == "PATCH" and any(p.match(path) for p in _READ_PATCH_PATHS):
            return
        observability.event(
            "blocked", reason="readonly-mode", method=method, path=path
        )
        _audit(method, path, None, "blocked:readonly")
        raise TrmmError(
            f"Refused: the MCP server is running in read-only mode, so "
            f"{method} {path} is not permitted. Restart it with "
            f"TRMM_MCP_MODE=command to enable execution tools. "
            f"(The read-only API key also lacks the TRMM role permissions for this.)"
        )

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: dict[str, Any] | None = None,
        audit: bool = False,
        elevated: bool = False,
    ) -> Any:
        method = method.upper()
        path = _normalize_path(path)
        self._guard(method, path)

        # In elevate mode the process holds both keys but ordinary traffic goes
        # out under the read-only one; the command key is used only for a call
        # that has actually been approved.
        overrides = None
        if elevated and config.COMMAND_API_KEY:
            overrides = {"X-API-KEY": config.COMMAND_API_KEY}

        client = await self._get_client()
        started = time.perf_counter()
        try:
            response = await client.request(
                method, path, json=json_body, params=params, headers=overrides
            )
        except httpx.TimeoutException as exc:
            observability.event(
                "api_call", method=method, path=path, outcome="timeout",
                elevated=elevated,
                duration_ms=round((time.perf_counter() - started) * 1000, 1),
            )
            if audit:
                _audit(method, path, json_body, "timeout")
            raise TrmmError(
                f"Timed out after {config.HTTP_TIMEOUT}s calling {method} {path}. "
                f"If this was an agent command, the agent may be offline or the "
                f"command may still be running on it."
            ) from exc
        except httpx.HTTPError as exc:
            observability.event(
                "api_call", method=method, path=path, outcome="transport-error",
                error=str(exc), elevated=elevated,
                duration_ms=round((time.perf_counter() - started) * 1000, 1),
            )
            if audit:
                _audit(method, path, json_body, f"transport-error:{exc}")
            raise TrmmError(f"Could not reach TRMM at {config.API_URL}: {exc}") from exc

        observability.event(
            "api_call",
            method=method,
            path=path,
            status=response.status_code,
            outcome="ok" if response.is_success else "http-error",
            elevated=elevated,
            bytes=len(response.content or b""),
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
        )

        if response.is_success:
            if audit:
                _audit(method, path, json_body, f"ok:{response.status_code}")
            if not response.content:
                return None
            try:
                return response.json()
            except ValueError:
                return response.text

        detail = response.text[:500]
        if audit:
            _audit(method, path, json_body, f"http-{response.status_code}:{detail[:200]}")

        hint = ""
        if response.status_code == 403:
            hint = (
                " The API key's TRMM role does not grant this. In read-only mode "
                "that is expected and intentional."
            )
        elif response.status_code == 401:
            hint = " The API key is invalid, expired, or its user is disabled."
        elif response.status_code == 405:
            hint = (
                " TRMM requires a trailing slash on every URL, and several read "
                "endpoints use PATCH rather than GET."
            )
        elif response.status_code == 404:
            hint = " Check the agent_id (a ~40-char string, not the numeric id)."
        elif response.status_code >= 500:
            hint = (
                " TRMM reads request fields directly without validation, so a "
                "missing required field surfaces as a 500 rather than a 400."
            )

        raise TrmmError(f"TRMM returned HTTP {response.status_code}: {detail}{hint}")

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)

    async def patch(self, path: str, body: Any) -> Any:
        return await self.request("PATCH", path, json_body=body)

    async def post(
        self, path: str, body: Any, *, audit: bool = True, elevated: bool = True
    ) -> Any:
        return await self.request(
            "POST", path, json_body=body, audit=audit, elevated=elevated
        )

    async def put(
        self, path: str, body: Any, *, audit: bool = True, elevated: bool = True
    ) -> Any:
        return await self.request(
            "PUT", path, json_body=body, audit=audit, elevated=elevated
        )

    async def delete(self, path: str, *, audit: bool = True, elevated: bool = True) -> Any:
        return await self.request("DELETE", path, audit=audit, elevated=elevated)


client = TrmmClient()
