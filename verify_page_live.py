"""Create real approval requests through the LIVE service, then render the page.

Nothing is approved and nothing executes: every request below is refused by the
server, which is the point. The pending items are left in place so they can be
inspected in a browser, then denied.
"""

import asyncio
import json
import re
import os
import sys

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trmm_mcp import approval_auth, approval_web, elevation  # noqa: E402

URL = os.environ.get("TRMM_MCP_VERIFY_URL", "https://127.0.0.1:8770/mcp")
CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "cert.pem")
TOKEN = ""
for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
    if line.startswith("TRMM_MCP_AUTH_TOKEN="):
        TOKEN = line.split("=", 1)[1].strip()

results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"\n         {detail}" if detail else ""))


def visible(body: str) -> str:
    stripped = re.sub(r"<style.*?</style>|<script.*?</script>", "", body, flags=re.S)
    return re.sub(r"[ \t]+", " ", re.sub(r"<[^>]+>", " ", stripped))


async def main():
    print("\n" + "=" * 70)
    print("LIVE APPROVAL PAGE - real requests through the configured server")
    print("=" * 70 + "\n")

    elevation.revoke_all()

    client = httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, verify=CERT)
    async with streamable_http_client(URL, http_client=client) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=25)

            r = await session.call_tool("trmm_list_agents", {"fields": ["hostname"]})
            hosts = [a["hostname"] for a in json.loads(r.content[0].text)["agents"]]
            print(f"agents: {', '.join(hosts)}\n")
            host = hosts[0]

            # 1. An ordinary command.
            r = await session.call_tool("trmm_run_command", {
                "agent": host, "command": "echo approval-page-demo",
                "shell": "cmd", "timeout": 30})
            check("command was refused, not run",
                  r.is_error and "APPROVAL REQUIRED" in r.content[0].text)

            # 2. A destructive one, to exercise the loud treatment.
            r = await session.call_tool("trmm_reboot_agent", {"agent": host})
            check("reboot was refused, not run",
                  r.is_error and "APPROVAL REQUIRED" in r.content[0].text)

            # 3. A script run, to prove the name lookup happens server-side.
            r = await session.call_tool("trmm_run_script",
                                        {"agent": host, "script_id": 128})
            check("script run was refused, not run",
                  r.is_error and "APPROVAL REQUIRED" in r.content[0].text)
    await client.aclose()

    print()
    pending = [p for p in elevation.snapshot()["pending"] if p["status"] == "pending"]
    check("live server recorded all three", len(pending) == 3, f"{len(pending)} pending")

    by_tool = {p["tool"]: p for p in pending}

    cmd = by_tool.get("trmm_run_command", {})
    disp = cmd.get("display") or {}
    check("live server captured the hostname, not just the agent_id",
          disp.get("target") == host, f"target={disp.get('target')!r}")
    check("live server captured a plain-English action",
          disp.get("action") == "Run a Command Prompt command", disp.get("action"))
    check("live server captured the verbatim command",
          disp.get("code") == "echo approval-page-demo")
    check("facts carry units",
          ["Timeout", "30 seconds"] in (disp.get("facts") or []),
          json.dumps(disp.get("facts")))

    reboot = (by_tool.get("trmm_reboot_agent") or {}).get("display") or {}
    check("reboot is classified destructive", reboot.get("risk") == "destructive")
    check("reboot carries a human warning",
          "Unsaved work" in (reboot.get("warning") or ""), reboot.get("warning"))

    script = (by_tool.get("trmm_run_script") or {}).get("display") or {}
    check("script id was resolved to its real name",
          "Disk" in (script.get("action") or ""), script.get("action"))

    # Render the page exactly as it appears once signed in.
    print()
    session_cookie = approval_auth.issue_session()

    class Req:
        cookies = {approval_web.COOKIE: session_cookie}

        class client:
            host = "127.0.0.1"

    body = (await approval_web.index(Req())).body.decode()
    text = visible(body)
    open("/tmp/approval-live.html", "w").write(body)

    check("page headlines the count", "3 operations waiting for approval" in text)
    check("severity wording present",
          "CANNOT BE UNDONE" in text and "CHANGES THIS MACHINE" in text)
    check("hostname is what you read", f"on {host}" in text)
    check("40-char agent_id is nowhere on the page",
          not re.search(r"[A-Za-z0-9]{40}", text))
    check("command shown in a numbered evidence panel",
          "Exact command to be run" in text and 'class="num"' in body)
    check("script name rendered, not a bare id", "Disk - Check / Repair" in text)
    check("live countdown wired up", "data-expires" in body)

    print("\n--- what the page reads like ---\n")
    lines = [ln.strip() for ln in re.sub(
        r"</div>|</p>|</tr>|</h1>|</h2>|</li>", "\n", body).split("\n")]
    lines = [re.sub(r"<[^>]+>", " ", ln).strip() for ln in lines]
    import html as _h
    shown = [_h.unescape(re.sub(r"[ \t]+", " ", ln)) for ln in lines if ln.strip()]
    print("\n".join(shown[:34]))

    print()
    bad = results.count(False)
    if bad:
        print(f"FAILED: {bad} of {len(results)}")
        sys.exit(1)
    print(f"ALL GREEN - {len(results)} checks against the live service")
    print("\nThree requests are left pending so you can look at them in the "
          "browser. Deny them, or use 'Cancel everything above'.")


asyncio.run(main())
