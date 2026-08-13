"""Read the MCP audit trail.

    ./venv/bin/python logs.py                 last 30 events, one line each
    ./venv/bin/python logs.py -n 100          more of them
    ./venv/bin/python logs.py -k error        only one kind
    ./venv/bin/python logs.py -t run_command  only one tool
    ./venv/bin/python logs.py -f              follow, like tail -f
    ./venv/bin/python logs.py --full          full JSON instead of one-liners
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from trmm_mcp import config  # noqa: E402

PATH = config.LOG_DIR / "events.jsonl"

ICON = {
    "startup": "^", "request": ">", "response": "<", "api_call": "~",
    "error": "!", "blocked": "X", "approval": "*", "mutation": "W",
    "elevation_required": "?", "elevation_granted": "+",
}


def summarize(e: dict) -> str:
    kind = e.get("kind", "?")
    mark = ICON.get(kind, " ")
    when = e.get("ts", "")[-8:]
    head = f"{when} {mark} {kind:<19}"

    if kind in ("request", "response"):
        what = e.get("tool") or e.get("method") or ""
        extra = ""
        if kind == "request" and e.get("arguments"):
            extra = f" args={json.dumps(e['arguments'], default=str)[:90]}"
        if kind == "response":
            extra = f" {'ok' if e.get('ok') else 'ERROR'} {e.get('duration_ms')}ms"
            if e.get("result"):
                extra += f" -> {json.dumps(e['result'], default=str)[:70]}"
        return f"{head} {what}{extra}"

    if kind == "api_call":
        return (f"{head} {e.get('method')} {e.get('path')} -> {e.get('status')} "
                f"({e.get('duration_ms')}ms, {e.get('bytes', 0)}B)"
                f"{' [elevated]' if e.get('elevated') else ''}")

    if kind == "error":
        return f"{head} {e.get('tool') or e.get('method')}: {e.get('error_type')}: {str(e.get('error'))[:120]}"

    if kind == "blocked":
        return f"{head} {e.get('reason')}: {str(e.get('command') or e.get('path'))[:90]}"

    if kind in ("elevation_required", "elevation_granted"):
        return f"{head} {e.get('summary', '')[:100]}"

    if kind == "approval":
        return f"{head} {e.get('decision')}: {str(e.get('detail'))[:90]}"

    if kind == "mutation":
        return f"{head} {e.get('method')} {e.get('path')} -> {e.get('outcome')}"

    return f"{head} {json.dumps({k: v for k, v in e.items() if k not in ('ts', 'kind', 'epoch', 'pid', 'mode')}, default=str)[:120]}"


def load(path: Path):
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", type=int, default=30, help="how many events")
    ap.add_argument("-k", "--kind", help="filter by kind")
    ap.add_argument("-t", "--tool", help="filter by tool name (substring)")
    ap.add_argument("-f", "--follow", action="store_true", help="keep watching")
    ap.add_argument("--full", action="store_true", help="print whole JSON records")
    args = ap.parse_args()

    def keep(e: dict) -> bool:
        if args.kind and e.get("kind") != args.kind:
            return False
        if args.tool and args.tool not in str(e.get("tool") or ""):
            return False
        return True

    if not PATH.exists():
        print(f"No log yet at {PATH}")
        return

    events = [e for e in load(PATH) if keep(e)]
    for e in events[-args.n:]:
        print(json.dumps(e, indent=2, default=str) if args.full else summarize(e))

    if not args.follow:
        return

    seen = PATH.stat().st_size
    try:
        while True:
            time.sleep(0.5)
            size = PATH.stat().st_size
            if size < seen:  # rotated
                seen = 0
            if size > seen:
                with PATH.open() as fh:
                    fh.seek(seen)
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            e = json.loads(line)
                        except ValueError:
                            continue
                        if keep(e):
                            print(json.dumps(e, indent=2, default=str)
                                  if args.full else summarize(e))
                seen = size
    except KeyboardInterrupt:
        pass



if __name__ == "__main__":
    main()
