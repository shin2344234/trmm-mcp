"""Verify the full approval lifecycle using a REAL human decision.

Executes only the harmless echo the operator approved. The other approved item
(a disk check/repair script) is deliberately left untouched - an approval means
the server WOULD permit it, not that it should be triggered unattended.
"""

import asyncio
import json
import re
import os
import sys
import time

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trmm_mcp import elevation  # noqa: E402

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


async def main():
    print("\n" + "=" * 70)
    print("APPROVAL LIFECYCLE - driven by a real human decision")
    print("=" * 70 + "\n")

    before = elevation.snapshot()["pending"]
    approved = {p["tool"] for p in before if p["status"] == "approved"}
    print(f"approved by the operator: {sorted(approved)}")
    check("the denied reboot is gone from the queue",
          not any(p["tool"] == "trmm_reboot_agent" for p in before),
          "deny removes the request outright")

    client = httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, verify=CERT)
    async with streamable_http_client(URL, http_client=client) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=25)

            # --- inspect the other approved item WITHOUT running it ---
            print("\n--- what 'Disk - Check / Repair' would do (read-only) ---")
            r = await session.call_tool("trmm_get_script", {"script_id": 128})
            script = json.loads(r.content[0].text).get("script", {})
            body = script.get("script_body", "") or ""
            print(f"    shell   : {script.get('shell')}")
            print(f"    lines   : {len(body.splitlines())}")
            risky = [ln.strip() for ln in body.splitlines()
                     if re.search(r"chkdsk|/f\b|/r\b|Repair-Volume|sfc |DISM|restart|reboot",
                                  ln, re.I)][:6]
            for ln in risky:
                print(f"    > {ln[:96]}")
            check("script body was readable without approval", bool(body),
                  "reads never need approval")

            # --- the harmless one the operator approved ---
            print("\n--- executing ONLY the echo the operator approved ---")
            args = {"agent": "WORKSTATION-02", "command": "echo approval-page-demo",
                    "shell": "cmd", "timeout": 30}
            r = await session.call_tool("trmm_run_command", args)
            ok = not r.is_error
            out = json.loads(r.content[0].text).get("output", "") if ok else r.content[0].text
            check("approved command runs", ok and "approval-page-demo" in out,
                  f"output={out.strip()!r}")

            # --- and the approval must now be spent ---
            r = await session.call_tool("trmm_run_command", args)
            check("the same command is refused immediately afterwards",
                  r.is_error and "APPROVAL REQUIRED" in r.content[0].text,
                  "single use: approving once does not leave it unlocked")

            # --- the denied reboot must still be blocked ---
            r = await session.call_tool("trmm_reboot_agent", {"agent": "WORKSTATION-02"})
            check("denied reboot is still refused",
                  r.is_error and "APPROVAL REQUIRED" in r.content[0].text,
                  "a denial does not linger as permission, but nor does it whitelist")
    await client.aclose()

    # Clean up the reboot request the check above re-created.
    for p in elevation.snapshot()["pending"]:
        if p["tool"] == "trmm_reboot_agent":
            elevation.deny(p["id"])

    state = elevation.snapshot()
    still = [p for p in state["pending"] if p["status"] == "approved"]
    check("the disk script approval is still armed and untouched",
          any(p["tool"] == "trmm_run_script" for p in still),
          f"{int(still[0]['expires'] - time.time())}s until it lapses on its own"
          if still else "none")

    print("\n--- audit trail of the human decisions ---")
    for e in state["log"][-9:]:
        stamp = time.strftime("%H:%M:%S", time.localtime(e["time"]))
        print(f"    {stamp}  {e['event']:14} {e['detail'][:64]}")

    check("every decision was logged",
          {"approved", "denied", "consumed"} <= {e["event"] for e in state["log"]})

    print()
    bad = results.count(False)
    if bad:
        print(f"FAILED: {bad} of {len(results)}")
        sys.exit(1)
    print(f"ALL GREEN - {len(results)} checks")


asyncio.run(main())
