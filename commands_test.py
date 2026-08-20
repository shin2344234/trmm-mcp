#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The 'commands run' review page.

Two things are easy to get wrong here and both would mislead the reader:
pairing a response to the wrong request (request_id restarts at 1 every
session, so it is only unique per pid), and calling something "ran" when the
approval gate actually refused it. Most of these checks are about those.
"""

import asyncio
import json
import shutil
import sys
import tempfile
from pathlib import Path

from starlette.requests import Request

from trmm_mcp import approval_auth, approval_web

results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"\n         {detail}" if detail else ""))


def req(query: str = "", cookie: str | None = None) -> Request:
    headers = []
    if cookie:
        headers.append((b"cookie", f"{approval_web.COOKIE}={cookie}".encode()))
    return Request({
        "type": "http", "method": "GET", "path": "/approve/commands",
        "query_string": query.encode(), "headers": headers,
        "client": ("127.0.0.1", 41234),
    })


def render(query: str = "", cookie: str | None = None) -> str:
    return asyncio.run(approval_web.commands(req(query, cookie))).body.decode()


def event(**kw):
    base = {"mode": "elevate", "method": "tools/call"}
    base.update(kw)
    return json.dumps(base)


def main():
    print("\n" + "=" * 70)
    print("COMMANDS RUN PAGE")
    print("=" * 70 + "\n")

    session = approval_auth.issue_session()

    # --- the door ------------------------------------------------------------
    body = render(cookie=None)
    check("unauthenticated visitors get the sign-in page",
          "Commands run</h1>" not in body and "class='cmd" not in body)
    check("a forged cookie is refused",
          "class='cmd " not in render(cookie="nope"))

    # --- arguments are logged as a JSON string, not a dict --------------------
    check("a JSON-string arguments field is parsed",
          approval_web._args_of({"arguments": '{"agent": "PC-1"}'}) == {"agent": "PC-1"})
    check("a dict arguments field still works",
          approval_web._args_of({"arguments": {"agent": "PC-1"}}) == {"agent": "PC-1"})
    check("malformed arguments do not explode",
          approval_web._args_of({"arguments": "not json"}) == {})

    # --- did it actually run? ------------------------------------------------
    approved = {"ok": True, "result": json.dumps({"output": "WLK-1\r\n"})}
    check("a successful run is reported as RAN and its output extracted",
          approval_web._outcome(approved) == ("ran", "WLK-1\r\n", ""))

    refused = {"ok": False, "result":
               "Error executing tool trmm_run_command: APPROVAL REQUIRED - this did not run."}
    status, _, _ = approval_web._outcome(refused)
    check("a gate refusal is NOT reported as having run", status == "refused", status)

    blocked = {"ok": False, "result": "refused: command blocked by pattern guard"}
    check("a guard refusal is distinguished from a failure",
          approval_web._outcome(blocked)[0] == "blocked")

    check("a genuine error is a failure",
          approval_web._outcome({"ok": False, "result": "HTTP 500 from TRMM"})[0]
          == "failed")
    check("a request with no response is not silently dropped",
          approval_web._outcome(None)[0] == "unknown")

    # --- wording matches the approval page -----------------------------------
    described = approval_web._describe(
        "trmm_run_command",
        {"agent": "WLK-1", "command": "hostname", "shell": "cmd", "timeout": 20})
    check("a command is described the way the approval page describes it",
          described["action"] == "Run a Command Prompt command"
          and described["target"] == "WLK-1"
          and described["code"] == "hostname", json.dumps(described))
    check("run_as_user is spelled out, not left as a boolean",
          ["Runs as", "SYSTEM (full privileges)"] in described["facts"])
    check("a reboot is described as a reboot",
          approval_web._describe("trmm_reboot_agent", {"agent": "X"})["action"]
          == "Reboot the machine immediately")

    # --- pairing across sessions ---------------------------------------------
    tmp = Path(tempfile.mkdtemp())
    real_log_dir = approval_web.config.LOG_DIR
    try:
        (tmp / "events.jsonl").write_text("\n".join([
            # session A: request 5 -> ran "alpha"
            event(kind="request", pid=111, request_id=5, tool="trmm_run_command",
                  ts="2026-01-01T10:00:00", epoch=1,
                  arguments='{"agent":"PC-A","command":"alpha","shell":"cmd"}'),
            event(kind="response", pid=111, request_id=5, tool="trmm_run_command",
                  ts="2026-01-01T10:00:01", epoch=2, ok=True, duration_ms=5,
                  result='{"output":"ALPHA-OUT"}'),
            # session B: same request_id 5, different pid -> ran "beta"
            event(kind="request", pid=222, request_id=5, tool="trmm_run_command",
                  ts="2026-01-01T11:00:00", epoch=3,
                  arguments='{"agent":"PC-B","command":"beta","shell":"cmd"}'),
            event(kind="response", pid=222, request_id=5, tool="trmm_run_command",
                  ts="2026-01-01T11:00:01", epoch=4, ok=True, duration_ms=7,
                  result='{"output":"BETA-OUT"}'),
        ]) + "\n")
        approval_web.config.LOG_DIR = tmp

        entries, _ = approval_web._pair_commands(50, "all", "")
        by_code = {e["code"]: e for e in entries}
        check("both sessions are recovered despite sharing request_id 5",
              len(entries) == 2, f"{len(entries)} entries")
        check("session A kept its own output",
              by_code.get("alpha", {}).get("output") == "ALPHA-OUT")
        check("session B was not paired with session A's response",
              by_code.get("beta", {}).get("output") == "BETA-OUT",
              json.dumps(by_code.get("beta", {}).get("output")))
        check("each kept its own machine",
              by_code.get("alpha", {}).get("target") == "PC-A"
              and by_code.get("beta", {}).get("target") == "PC-B")

        only_ran, _ = approval_web._pair_commands(50, "ran", "")
        check("the status filter selects", len(only_ran) == 2)
        found, _ = approval_web._pair_commands(50, "all", "BETA-OUT")
        check("search reaches into the output text",
              len(found) == 1 and found[0]["code"] == "beta")
    finally:
        approval_web.config.LOG_DIR = real_log_dir
        shutil.rmtree(tmp, ignore_errors=True)

    # --- hostile text ---------------------------------------------------------
    card = approval_web._command_card({
        "tool": "trmm_run_command", "ts": "2026-01-01T00:00:00", "epoch": 0,
        "action": "Run a Command Prompt command",
        "target": "<b>PC</b>", "code": "echo hi ‮# rm -rf /",
        "facts": [], "status": "ran",
        "output": "<script>alert(1)</script>", "error": "", "duration_ms": 1,
    })
    check("markup in the target cannot become markup",
          "<b>PC</b>" not in card and "&lt;b&gt;" in card)
    check("markup in the output cannot become markup",
          "<script>alert(1)</script>" not in card)
    check("a bidi override in the command is defanged",
          "‮" not in card and "202E" in card)

    # --- the page, against the real log --------------------------------------
    body = render("n=5", session)
    check("the page renders", "Commands run</h1>" in body)
    check("it offers the status filters",
          all(v in body for v in approval_web.COMMAND_FILTERS.values()))
    check("no unescaped HTML entity leaks into the meta line",
          "&amp;middot;" not in body)
    check("it links to the activity log", "href='history'" in body)

    for query in ("n=x", "n=-1", "n=99999", "show=../etc", "q=" + "z" * 400):
        try:
            ok = "Commands run</h1>" in render(query, session)
        except Exception as exc:  # noqa: BLE001
            ok = False
            print("        ", repr(exc)[:140])
        check(f"survives ?{query[:24]}", ok)

    index = asyncio.run(approval_web.index(req(cookie=session))).body.decode()
    check("the approvals page links to it",
          "href='commands'" in index and "Review commands run" in index)

    print()
    bad = results.count(False)
    if bad:
        print(f"FAILED: {bad} of {len(results)}")
        sys.exit(1)
    print(f"ALL GREEN ({len(results)} checks)")


main()
