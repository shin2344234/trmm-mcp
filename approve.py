"""Approve privileged MCP operations from the shell.

The counterpart to the web page, for when you are already on the server or
running the stdio transport.

    ./venv/bin/python approve.py list          show pending requests and windows
    ./venv/bin/python approve.py ok            approve the single pending request
    ./venv/bin/python approve.py ok <id>       approve a specific request
    ./venv/bin/python approve.py no <id>       deny it
    ./venv/bin/python approve.py window 10 5   open a 10-minute, 5-use window
    ./venv/bin/python approve.py revoke        drop every grant now
"""

import json
import sys
import time

from trmm_mcp import elevation


def show() -> None:
    state = elevation.snapshot()
    now = time.time()

    pending = [p for p in state["pending"] if p["status"] == "pending"]
    approved = [p for p in state["pending"] if p["status"] == "approved"]

    print(f"\nPending approval ({len(pending)}):")
    for record in pending:
        print(f"  [{record['id']}] {record['tool']}  ({int(record['expires'] - now)}s left)")
        print(f"      {record['summary']}")
        for key, value in sorted((record.get("params") or {}).items()):
            print(f"        {key} = {json.dumps(value, default=str)}")
    if not pending:
        print("  (none)")

    if approved:
        print(f"\nApproved, awaiting use ({len(approved)}):")
        for record in approved:
            print(f"  [{record['id']}] {record['summary']}")

    print(f"\nOpen windows ({len(state['windows'])}):")
    for window in state["windows"]:
        uses = window.get("uses_left")
        print(
            f"  [{window['id']}] {int(window['expires'] - now)}s left, "
            f"{'unlimited' if uses is None else uses} uses, "
            f"{window.get('agent') or 'any agent'}"
        )
    if not state["windows"]:
        print("  (none)")
    print()


def main() -> None:
    args = sys.argv[1:] or ["list"]
    action = args[0]

    if action in ("list", "ls"):
        show()
        return

    if action in ("ok", "approve"):
        if len(args) > 1:
            target = args[1]
        else:
            pending = [p for p in elevation.snapshot()["pending"] if p["status"] == "pending"]
            if len(pending) != 1:
                print(f"{len(pending)} requests pending - name one explicitly.")
                show()
                sys.exit(1)
            target = pending[0]["id"]
        record = elevation.approve(target)
        if record:
            print(f"Approved: {record['summary']}")
            print("It is single-use and will be consumed on the next matching call.")
        else:
            print(f"No pending request with id {target!r}.")
            sys.exit(1)
        return

    if action in ("no", "deny"):
        if len(args) < 2:
            print("Which request? Use: approve.py no <id>")
            sys.exit(1)
        print("Denied." if elevation.deny(args[1]) else "No such request.")
        return

    if action == "window":
        minutes = int(args[1]) if len(args) > 1 else 10
        uses = int(args[2]) if len(args) > 2 else None
        agent = args[3] if len(args) > 3 else None
        window = elevation.open_window(minutes * 60, uses=uses, agent=agent)
        print(
            f"Window {window['id']} open for {minutes}m, "
            f"{'unlimited' if uses is None else uses} uses, "
            f"{agent or 'any agent'}."
        )
        return

    if action == "revoke":
        elevation.revoke_all()
        print("All grants revoked.")
        return

    print(__doc__)
    sys.exit(1)


main()
