#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The activity log page.

The interesting risk here is not the table layout: it is that every string in
events.jsonl came from the model or from a remote machine. A command that can
smuggle markup or bidi overrides into this page could make a dangerous entry
read as a harmless one - on the very page an operator uses to check up on the
server. So most of these checks are about text that fights back.
"""

import sys

from starlette.requests import Request

from trmm_mcp import approval_auth, approval_web

results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"\n         {detail}" if detail else ""))


def make_request(query: str = "", cookie: str | None = None) -> Request:
    headers = []
    if cookie:
        headers.append((b"cookie", f"{approval_web.COOKIE}={cookie}".encode()))
    return Request({
        "type": "http", "method": "GET", "path": "/approve/history",
        "query_string": query.encode(), "headers": headers,
        "client": ("127.0.0.1", 41234),
    })


async def render(query: str = "", cookie: str | None = None) -> str:
    response = await approval_web.history(make_request(query, cookie))
    return response.body.decode()


def main():
    import asyncio

    print("\n" + "=" * 70)
    print("ACTIVITY LOG PAGE")
    print("=" * 70 + "\n")

    session = approval_auth.issue_session()

    # --- it is behind the same door as everything else ----------------------
    body = asyncio.run(render(cookie=None))
    check("an unauthenticated visitor gets the sign-in page, not the log",
          "Activity" not in body and ("password" in body.lower()
                                      or "sign in" in body.lower()),
          body[:120])
    check("no log content leaks to an unauthenticated visitor",
          "<table class='log'>" not in body)

    body = asyncio.run(render(cookie="not-a-real-session"))
    check("a forged cookie is refused", "<table class='log'>" not in body)

    # --- the page itself ----------------------------------------------------
    body = asyncio.run(render(cookie=session))
    check("signed in, the page renders", "<h1>Activity</h1>" in body)
    check("it links back to the approvals page", "Back to approvals" in body)
    check("every filter is offered",
          all(label in body for label in approval_web.LOG_LABELS.values()))
    check("there is a search box", 'name="q"' in body or "name='q'" in body)

    # --- filters actually filter -------------------------------------------
    everything = asyncio.run(render("show=all&n=200", session))
    refused = asyncio.run(render("show=refused&n=200", session))
    check("a filter narrows the result",
          refused.count("<tr>") <= everything.count("<tr>"),
          f"all={everything.count('<tr>')} rows, refused={refused.count('<tr>')} rows")
    check("the active filter is marked", "btn on" in refused)

    # --- hostile input ------------------------------------------------------
    nasty = {
        "kind": "blocked", "ts": "2026-08-19T12:00:00", "reason": "destructive",
        "command": "<script>alert(1)</script> echo safe ‮#⁦ rm -rf / ⁩",
    }
    html_out = approval_web._event_summary(nasty)
    check("markup in a logged command cannot become markup on the page",
          "<script>" not in html_out and "&lt;script&gt;" in html_out)
    check("a bidi override is shown as a visible marker, not obeyed",
          "‮" not in html_out and "202E" in html_out,
          html_out[-150:])

    zero = approval_web._event_summary(
        {"kind": "blocked", "reason": "x", "command": "rm​ -rf /"})
    check("a zero-width character is surfaced, not silently dropped",
          "​" not in zero and "ctl" in zero)

    # --- awkward parameters -------------------------------------------------
    for query in ("n=notanumber", "n=-5", "n=999999", "show=../../etc/passwd",
                  "q=" + "x" * 500):
        try:
            out = asyncio.run(render(query, session))
            ok = "<h1>Activity</h1>" in out
        except Exception as exc:  # noqa: BLE001
            ok, out = False, repr(exc)
        check(f"survives ?{query[:28]}", ok, "" if ok else str(out)[:160])

    # --- rows open to show the detail ---------------------------------------
    body = asyncio.run(render("show=calls&n=20", session))
    check("rows are expandable, with no JavaScript involved",
          "<details class='logrow'>" in body and "<summary>" in body)
    check("every row carries a detail pane",
          body.count("<details class='logrow'>") == body.count("class='logdetail'"),
          f"{body.count(chr(60) + chr(100) + 'etails')} rows")
    check("the detail includes the raw record", "Raw log record" in body)

    # A request and its response are two halves of one thing: opening the
    # request should show what came back, not just what was asked.
    import json as _json, shutil as _shutil, tempfile as _tempfile
    from pathlib import Path as _Path
    tmp = _Path(_tempfile.mkdtemp())
    real = approval_web.config.LOG_DIR
    try:
        (tmp / "events.jsonl").write_text("\n".join([
            _json.dumps({"kind": "request", "pid": 7, "request_id": 3,
                         "tool": "trmm_run_command", "ts": "2026-01-01T09:00:00",
                         "epoch": 1, "method": "tools/call",
                         "arguments": '{"agent":"PC-Z","command":"whoami","shell":"cmd"}'}),
            _json.dumps({"kind": "response", "pid": 7, "request_id": 3,
                         "tool": "trmm_run_command", "ts": "2026-01-01T09:00:01",
                         "epoch": 2, "method": "tools/call", "ok": True,
                         "duration_ms": 12,
                         "result": '{"output":"NT AUTHORITY\\\\SYSTEM"}'}),
        ]) + "\n")
        approval_web.config.LOG_DIR = tmp

        events, _, index = approval_web._load_events((), "", 50)
        check("the index pairs a request with its response",
              index.get((7, 3), {}).keys() >= {"request", "response"},
              str(list(index)))

        req_event = [e for e in events if e["kind"] == "request"][0]
        detail = approval_web._event_detail(req_event, index[(7, 3)]["response"])
        check("opening a request shows the verbatim command",
              "whoami" in detail and "Command" in detail)
        check("opening a request also shows what the machine returned",
              "SYSTEM" in detail and "What the machine returned" in detail)
        check("and how it ended", "RAN" in detail)

        # Filtering to requests only must not hide the paired response.
        only_req, _, idx2 = approval_web._load_events(("request",), "", 50)
        check("a filtered view can still reach its partner",
              idx2.get((7, 3), {}).get("response") is not None)
    finally:
        approval_web.config.LOG_DIR = real
        _shutil.rmtree(tmp, ignore_errors=True)

    # --- fact values come from the log, so they get the full treatment -------
    rows = approval_web._fact_rows([["Service", "Spool\u202eer"],
                                    ["Note", "<b>x</b>"]])
    check("a bidi override in a fact value is unmasked",
          "\u202e" not in rows and "202E" in rows)
    check("markup in a fact value cannot become markup",
          "<b>x</b>" not in rows and "&lt;b&gt;" in rows)

    # --- the way in ---------------------------------------------------------
    index = (await_index := asyncio.run(
        approval_web.index(make_request(cookie=session)))).body.decode()
    check("the approvals page offers a button through to it",
          "href='history'" in index and "View activity log" in index)

    print()
    bad = results.count(False)
    if bad:
        print(f"FAILED: {bad} of {len(results)}")
        sys.exit(1)
    print(f"ALL GREEN ({len(results)} checks)")


main()
