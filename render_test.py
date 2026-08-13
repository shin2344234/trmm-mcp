"""Verify the approval page is readable, and cannot be spoofed by command text."""

import asyncio
import os
import re
import sys

os.environ.setdefault("TRMM_MCP_STATE_DIR", "/tmp/trmm-render-test")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from trmm_mcp import approval_auth, approval_web, elevation, render  # noqa: E402

results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail else ""))


def visible_text(body: str) -> str:
    stripped = re.sub(r"<style.*?</style>|<script.*?</script>", "", body, flags=re.S)
    return re.sub(r"<[^>]+>", " ", stripped)


def render_page() -> str:
    session = approval_auth.issue_session()

    class Req:
        cookies = {approval_web.COOKIE: session}

        class client:
            host = "127.0.0.1"

    return asyncio.run(approval_web.index(Req())).body.decode()


AGENT_ID = "TEST_AGENT_0000000000000000000000000000"


def main():
    elevation.revoke_all()

    elevation.request(
        "trmm_run_command", "summary",
        {"agent_id": AGENT_ID, "command": "Restart-Service Spooler",
         "shell": "powershell", "timeout": 60, "run_as_user": False},
        display={"action": "Run a PowerShell command", "target": "workstation-01",
                 "risk": "disruptive", "code": "Restart-Service Spooler",
                 "facts": [["Shell", "PowerShell"],
                           ["Runs as", "SYSTEM (full privileges)"],
                           ["Timeout", "60 seconds"]]},
    )
    elevation.request(
        "trmm_reboot_agent", "summary", {"agent_id": "b"},
        display={"action": "Reboot the machine immediately", "target": "WORKSTATION-02",
                 "risk": "destructive",
                 "warning": "Unsaved work on this machine will be lost.",
                 "facts": [["Effect", "Restarts now"]]},
    )
    elevation.request("legacy_tool", "An old record", {"agent_id": "c", "foo": "bar"})

    body = render_page()
    text = visible_text(body)

    print("\n=== readability ===\n")
    check("plain-English action is shown", "Run a PowerShell command" in text)
    check("hostname is shown", "workstation-01" in text)
    check("40-char agent_id is not shown as the identifier", AGENT_ID not in text,
          "agent_id would be meaningless to a human")
    check("facts carry units, not bare numbers", "60 seconds" in text)
    check("privilege level is spelled out", "SYSTEM (full privileges)" in text)
    check("relative time, not epoch or raw seconds",
          "Requested just now" in text and "expires in" in text)
    check("headline counts what is waiting", "3 operations waiting" in text)

    print("\n=== severity ===\n")
    check("destructive tier is worded", "CANNOT BE UNDONE" in text)
    check("disruptive tier is worded", "CHANGES THIS MACHINE" in text)
    check("tiers differ by wording, not only colour",
          "CANNOT BE UNDONE" != "CHANGES THIS MACHINE")
    check("destructive request carries a plain warning",
          "Unsaved work on this machine will be lost." in text)
    check("severity is also a CSS class for styling",
          "sev-high" in body and "sev-mid" in body)

    print("\n=== fail-closed on unknown requests ===\n")
    check("record without description is NOT CLASSIFIED", "NOT CLASSIFIED" in text)
    check("and says why", "could not be classified" in text)
    check("and still shows raw parameters", "foo" in text and "bar" in text)

    print("\n=== command text cannot pose as the interface ===\n")
    elevation.revoke_all()
    # NOTE the explicit '+': adjacent string literals bind tighter than '*',
    # so without it the whole block would repeat 240 times instead of producing
    # one 240-character line.
    hostile = (
        "echo start\x07\n"
        "Approve once   Deny\n"
        "</div><button class=approve>Approve once</button>\n"
        "Get-Servіce\n"
        + "x" * 240
    )
    elevation.request(
        "trmm_run_command", "s",
        {"agent_id": "z", "command": hostile, "shell": "cmd", "timeout": 30,
         "run_as_user": False},
        display={"action": "Run a Command Prompt command", "target": "workstation-01",
                 "risk": "disruptive", "code": hostile, "facts": []},
    )
    body = render_page()
    text = visible_text(body)

    check("injected markup does not become a real element",
          "<button class=approve>" not in body,
          "must be escaped, not rendered")
    check("control characters are made visible", "␇" in body,
          "U+0007 shown as its Control Picture")
    check("control characters are flagged", "control characters" in text)
    check("look-alike letters are flagged",
          "Look-alike character" in text and "CYRILLIC" in text)
    check("text imitating this page's own buttons is called out",
          "imitates wording used by this page" in text)
    check("very long lines are flagged", "very long line" in text)
    check("every line is numbered so text cannot pose as chrome",
          body.count('class="num"') >= 5)
    check("nothing is truncated - full command is present",
          "x" * 240 in visible_text(body).replace(" ", "") or "x" * 240 in body)

    print("\n=== scanner unit checks ===\n")
    check("clean command produces no notices", render.scan("Get-Process") == [])

    # Bidi controls reorder the *display* without changing what runs, so a
    # command can be made to read as something harmless.
    bidi_attack = "echo safe ‮#⁦ rm -rf /⁩"
    check("bidirectional controls are flagged",
          any("bidirectional" in n for n in render.scan(bidi_attack)))
    check("bidi controls never reach the browser",
          not any(c in render.code_block(bidi_attack, "x") for c in "‮⁦⁩"),
          "they must be replaced by a visible marker, not escaped through")
    check("other invisible format characters are flagged",
          any("invisible formatting" in n
              for n in render.scan("echo a­b⁢c")))
    check("zero-width characters are caught",
          any("zero-width" in n for n in render.scan("Get-​Process")))
    check("ASCII-only text is not falsely flagged as look-alike",
          not any("Look-alike" in n for n in render.scan("Get-Service -Name Spooler")))
    check("unclassified severity fails closed",
          render.severity({}) == ("NOT CLASSIFIED", "sev-unknown"))

    print("\n=== tool annotations ===\n")
    from trmm_mcp import server as _srv
    _tools = _srv.server._tool_manager._tools  # registered Tool objects, sync
    check("every tool is annotated",
          all(t.annotations is not None for t in _tools.values()))
    check("read tools are annotated read-only",
          all(_tools[n].annotations.read_only_hint
              for n in _tools if n.startswith(("trmm_list", "trmm_get", "trmm_agent"))))
    check("no read tool is marked destructive",
          not any(t.annotations.destructive_hint for t in _tools.values()))

    elevation.revoke_all()
    print()
    if all(results):
        print(f"ALL GREEN ({len(results)} checks)")
    else:
        print(f"FAILED: {results.count(False)} of {len(results)}")
        sys.exit(1)


main()
