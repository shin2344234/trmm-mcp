#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Where does the server decide to keep .env, state/, certs/ and the audit log?

Getting this wrong is quiet and nasty: a pip-installed copy used to resolve its
base directory to site-packages, so `trmm-mcp-setup-auth` would write the
approval password hash and TOTP secret in among the site-packages, and under
uvx - a disposable cache - approval state would not survive a restart.

BASE_DIR is computed at import time, so each case runs in its own interpreter.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"\n         {detail}" if detail else ""))


def base_dir(pythonpath, env=None, cwd=None):
    """Import config in a fresh interpreter and report the BASE_DIR it chose."""
    e = {
        # Enough config to get through the import-time validation.
        "TRMM_API_URL": "https://example.invalid",
        "TRMM_READONLY_API_KEY": "x",
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "PYTHONPATH": str(pythonpath),
    }
    e.update(env or {})
    out = subprocess.run(
        [sys.executable, "-c", "from trmm_mcp import config; print(config.BASE_DIR)"],
        capture_output=True, text=True, env=e, cwd=cwd or tempfile.gettempdir(),
    )
    if out.returncode != 0:
        return f"ERROR: {out.stderr.strip().splitlines()[-1:]}"
    return out.stdout.strip()


def main():
    print("\n" + "=" * 70)
    print("BASE_DIR RESOLUTION")
    print("=" * 70 + "\n")

    tmp = Path(tempfile.mkdtemp())
    try:
        # A convincing installed layout: the package inside a site-packages dir.
        site = tmp / "lib" / "python3.11" / "site-packages"
        site.mkdir(parents=True)
        shutil.copytree(HERE / "trmm_mcp", site / "trmm_mcp")

        xdg = tmp / "xdg"
        home = tmp / "fakehome"

        # --- 1. a clone: unchanged behaviour, the repo root -------------------
        got = base_dir(HERE)
        check("a clone still resolves to the repo root",
              got == str(HERE), f"{got}  (expected {HERE})")

        # --- 2. an installed copy: anywhere but site-packages -----------------
        got = base_dir(site, {"XDG_DATA_HOME": str(xdg)})
        check("an installed copy does NOT write into site-packages",
              "site-packages" not in got, got)
        check("an installed copy uses XDG_DATA_HOME",
              got == str(xdg / "trmm-mcp"), got)

        mode = oct((xdg / "trmm-mcp").stat().st_mode & 0o777)
        check("the created directory is private (it holds credentials)",
              mode == "0o700", f"mode={mode}")

        # --- 3. installed with no XDG_DATA_HOME -------------------------------
        got = base_dir(site, {"HOME": str(home), "XDG_DATA_HOME": ""})
        check("falls back to ~/.local/share when XDG_DATA_HOME is unset",
              got == str(home / ".local" / "share" / "trmm-mcp"), got)

        # --- 4. the explicit override beats both -----------------------------
        custom = tmp / "custom"
        got = base_dir(site, {"TRMM_MCP_BASE_DIR": str(custom),
                              "XDG_DATA_HOME": str(xdg)})
        check("TRMM_MCP_BASE_DIR overrides an installed copy",
              got == str(custom), got)

        got = base_dir(HERE, {"TRMM_MCP_BASE_DIR": str(custom)})
        check("TRMM_MCP_BASE_DIR overrides a clone too",
              got == str(custom), got)

        got = base_dir(site, {"TRMM_MCP_BASE_DIR": "~/somewhere",
                              "HOME": str(home), "XDG_DATA_HOME": str(xdg)})
        check("the override expands ~", got == str(home / "somewhere"), got)

        # --- 5. .env is actually read from wherever BASE_DIR landed ----------
        (custom).mkdir(parents=True, exist_ok=True)
        (custom / ".env").write_text("TRMM_MCP_AGENT_ALLOWLIST=only-this-host\n")
        out = subprocess.run(
            [sys.executable, "-c",
             "from trmm_mcp import config; print(config.AGENT_ALLOWLIST)"],
            capture_output=True, text=True, cwd=tempfile.gettempdir(),
            env={"TRMM_API_URL": "https://example.invalid",
                 "TRMM_READONLY_API_KEY": "x",
                 "PATH": os.environ.get("PATH", ""),
                 "HOME": str(home),
                 "PYTHONPATH": str(site),
                 "TRMM_MCP_BASE_DIR": str(custom)},
        )
        check("the .env at the resolved BASE_DIR is the one that gets loaded",
              "only-this-host" in out.stdout, out.stdout.strip() or out.stderr.strip())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    bad = results.count(False)
    if bad:
        print(f"FAILED: {bad} of {len(results)}")
        sys.exit(1)
    print(f"ALL GREEN ({len(results)} checks)")


main()
