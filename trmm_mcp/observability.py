# SPDX-License-Identifier: AGPL-3.0-or-later
"""Logging for everything the server is asked to do and everything it does.

Two streams, both rotating:

  logs/events.jsonl   one JSON object per line - the audit trail. Every inbound
                      MCP request, every tool call with its arguments and
                      result, every TRMM API call, every approval decision,
                      every refusal.
  logs/server.log     human-readable diagnostics: warnings, errors, tracebacks,
                      and anything uvicorn/httpx/the MCP SDK emit.

Nothing is ever written to stdout: under the stdio transport stdout carries the
protocol, and a stray byte there corrupts the session.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import time
import traceback
from typing import Any

from . import config

EVENTS = logging.getLogger("trmm_mcp.events")
LOG = logging.getLogger("trmm_mcp")

_configured = False


def redact(value: Any) -> Any:
    """Strip credentials out of anything on its way to disk."""
    if isinstance(value, str):
        for secret in config.SECRETS:
            if secret in value:
                value = value.replace(secret, f"<redacted:{secret[:4]}...>")
        return value
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def _clip(payload: Any) -> Any:
    """Bound a payload so one huge result cannot dominate the log."""
    if payload is None:
        return None
    try:
        text = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    except (TypeError, ValueError):
        text = str(payload)

    limit = config.LOG_PAYLOAD_CHARS
    if limit == 0:
        return {"chars": len(text)}
    if limit > 0 and len(text) > limit:
        return {"chars": len(text), "truncated": True, "preview": redact(text[:limit])}
    return redact(text)


def setup() -> None:
    """Install handlers. Safe to call more than once."""
    global _configured
    if _configured:
        return
    _configured = True

    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(config.LOG_DIR, 0o700)
    except OSError:
        pass

    def _rotating(filename: str) -> logging.Handler:
        path = config.LOG_DIR / filename
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=config.LOG_MAX_BYTES, backupCount=config.LOG_BACKUPS
        )
        try:
            path.touch(exist_ok=True)
            os.chmod(path, 0o600)
        except OSError:
            pass
        return handler

    # Structured audit stream: the message is already JSON.
    events_handler = _rotating("events.jsonl")
    events_handler.setFormatter(logging.Formatter("%(message)s"))
    EVENTS.addHandler(events_handler)
    EVENTS.setLevel(logging.INFO)
    EVENTS.propagate = False

    # Diagnostics. Note stderr, never stdout.
    root = logging.getLogger()
    root.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))

    text_handler = _rotating("server.log")
    text_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    root.addHandler(text_handler)

    stderr_handler = logging.StreamHandler()
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(stderr_handler)

    # httpx logs a line per request at INFO; we record API calls ourselves with
    # more detail, so keep its noise out of the diagnostics file.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    event("startup", mode=config.MODE, transport=config.TRANSPORT,
          api_url=config.API_URL, log_dir=str(config.LOG_DIR))


def event(kind: str, **fields: Any) -> None:
    """Append one structured event. Never raises."""
    try:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "epoch": round(time.time(), 3),
            "kind": kind,
            "mode": config.MODE,
            "pid": os.getpid(),
        }
        record.update(redact(fields))
        EVENTS.info(json.dumps(record, default=str))
    except Exception:  # noqa: BLE001 - logging must never break the server
        try:
            LOG.exception("failed to write event %s", kind)
        except Exception:  # noqa: BLE001
            pass


def _as_mapping(result: Any) -> dict[str, Any]:
    """Handler results reach middleware as either a pydantic model or a dict."""
    if result is None:
        return {}
    if isinstance(result, dict):
        return result
    dump = getattr(result, "model_dump", None)
    if callable(dump):
        try:
            return dump(by_alias=True)
        except Exception:  # noqa: BLE001
            pass
    return {}


def _text_of(content: Any) -> str | None:
    """Flatten a content block list to plain text for the log."""
    if not content:
        return None
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict):
            text = block.get("text")
        else:
            text = getattr(block, "text", None)
        if text:
            parts.append(str(text))
    return "\n".join(parts) if parts else None


def _tool_details(ctx: Any) -> tuple[str | None, Any]:
    """Pull the tool name and arguments out of a tools/call request."""
    params = getattr(ctx, "params", None)
    if not isinstance(params, dict):
        return None, None
    return params.get("name"), params.get("arguments")


async def logging_middleware(ctx: Any, call_next: Any) -> Any:
    """Record every inbound MCP request, its outcome, and how long it took."""
    method = getattr(ctx, "method", "?")
    request_id = getattr(ctx, "request_id", None)
    tool_name, tool_args = _tool_details(ctx)
    started = time.perf_counter()

    event(
        "request",
        method=method,
        request_id=request_id,
        tool=tool_name,
        arguments=_clip(tool_args) if tool_args is not None else None,
        notification=request_id is None,
    )

    try:
        result = await call_next(ctx)
    except Exception as exc:  # noqa: BLE001 - observe, then re-raise unchanged
        event(
            "error",
            method=method,
            request_id=request_id,
            tool=tool_name,
            error_type=type(exc).__name__,
            error=str(exc),
            traceback=traceback.format_exc(limit=6),
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
        )
        LOG.warning("%s failed: %s: %s", tool_name or method, type(exc).__name__, exc)
        raise

    duration = round((time.perf_counter() - started) * 1000, 1)
    data = _as_mapping(result)
    is_error = bool(data.get("isError") or data.get("is_error"))
    payload = _text_of(data.get("content"))

    event(
        "response",
        method=method,
        request_id=request_id,
        tool=tool_name,
        ok=not is_error,
        duration_ms=duration,
        result=_clip(payload) if payload else None,
    )
    if is_error:
        LOG.info("%s returned an error result", tool_name or method)
    return result
