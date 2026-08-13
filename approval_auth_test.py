"""Verify password + TOTP protection on the approval page."""

import os
import subprocess
import sys
import time

import httpx
import pyotp

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PORT = "8777"
from trmm_mcp import config as _cfg
BASE = f"{_cfg.SCHEME}://127.0.0.1:{PORT}"
VERIFY = _cfg.TLS_CERT if _cfg.TLS_ENABLED else True
PASSWORD = "correct-horse-battery-staple"

results = []


def check(label, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail else ""))


def main():
    from trmm_mcp import approval_auth

    print("\n=== password hashing ===\n")
    digest = approval_auth.hash_password(PASSWORD)
    check("hash is not the password", PASSWORD not in digest, digest[:34] + "...")
    check("correct password verifies", approval_auth.verify_password(PASSWORD, digest))
    check("wrong password rejected", not approval_auth.verify_password("nope", digest))
    check("salted: two hashes of the same password differ",
          approval_auth.hash_password(PASSWORD) != digest)

    secret = pyotp.random_base32()

    print("\n=== live server with password + 2FA ===\n")
    env = {
        **os.environ,
        "TRMM_MCP_MODE": "elevate",
        "TRMM_MCP_TRANSPORT": "streamable-http",
        "TRMM_MCP_HTTP_HOST": "127.0.0.1",
        "TRMM_MCP_HTTP_PORT": PORT,
        "TRMM_MCP_APPROVAL_PASSWORD_HASH": digest,
        "TRMM_MCP_APPROVAL_TOTP_SECRET": secret,
        "TRMM_MCP_APPROVAL_MAX_ATTEMPTS": "3",
        "TRMM_MCP_STATE_DIR": "/tmp/trmm-authtest-state",
    }
    subprocess.run(["rm", "-rf", "/tmp/trmm-authtest-state"], check=False)
    proc = subprocess.Popen(
        [sys.executable, "-m", "trmm_mcp.server"],
        cwd=os.path.dirname(os.path.abspath(__file__)), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        up = False
        for _ in range(80):
            try:
                httpx.get(f"{BASE}/approve/", timeout=1, verify=VERIFY)
                up = True
                break
            except httpx.HTTPError:
                time.sleep(0.25)
        check("server up", up)
        if not up:
            raise SystemExit(1)

        r = httpx.get(f"{BASE}/approve/", timeout=5, verify=VERIFY)
        check("page asks for password and code",
              "Password" in r.text and "6-digit code" in r.text)
        check("no longer offers the shared token",
              "TRMM_MCP_AUTH_TOKEN" not in r.text)

        totp = pyotp.TOTP(secret)

        with httpx.Client(base_url=BASE, timeout=5, follow_redirects=True, verify=VERIFY) as c:
            r = c.post("/approve/login",
                       data={"password": PASSWORD, "code": "000000"})
            check("right password + wrong code is rejected",
                  "Incorrect password or code" in r.text)

        with httpx.Client(base_url=BASE, timeout=5, follow_redirects=True, verify=VERIFY) as c:
            r = c.post("/approve/login",
                       data={"password": "wrong", "code": totp.now()})
            check("wrong password + right code is rejected",
                  "Incorrect password or code" in r.text)

        with httpx.Client(base_url=BASE, timeout=5, follow_redirects=True, verify=VERIFY) as c:
            code = totp.now()
            r = c.post("/approve/login", data={"password": PASSWORD, "code": code})
            check("password + code together sign in", "Sign out" in r.text)
            check("session cookie is not the password or secret",
                  all(PASSWORD not in v and secret not in v
                      for v in c.cookies.values()))

            r = c.get("/approve/")
            check("session persists across requests", "Sign out" in r.text)

            r = c.post("/approve/logout")
            check("sign out ends the session", "Sign in" in r.text)

            # A code already spent must not work again.
            r = c.post("/approve/login", data={"password": PASSWORD, "code": code})
            check("TOTP code cannot be replayed",
                  "Incorrect password or code" in r.text)

        # Lockout after repeated failures.
        with httpx.Client(base_url=BASE, timeout=5, follow_redirects=True, verify=VERIFY) as c:
            last = ""
            for _ in range(4):
                last = c.post("/approve/login",
                              data={"password": "bad", "code": "111111"}).text
            check("repeated failures trigger a lockout",
                  "Too many failed attempts" in last)

            # Even correct credentials are refused while locked out.
            r = c.post("/approve/login",
                       data={"password": PASSWORD, "code": totp.now()})
            check("correct credentials refused during lockout",
                  "Too many failed attempts" in r.text)

        # An unauthenticated request must not be able to approve anything.
        r = httpx.post(f"{BASE}/approve/approve/anything", timeout=5, verify=VERIFY)
        check("cannot approve without signing in",
              "Sign in" in r.text or r.status_code in (303, 401, 403),
              f"HTTP {r.status_code}")

        # And the MCP endpoint keeps its own separate bearer auth.
        r = httpx.post(f"{BASE}/mcp", verify=VERIFY, json={"jsonrpc": "2.0", "id": 1,
                                            "method": "initialize"}, timeout=5)
        check("mcp endpoint still bearer-protected", r.status_code == 403,
              f"HTTP {r.status_code}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        subprocess.run(["rm", "-rf", "/tmp/trmm-authtest-state"], check=False)

    print()
    if all(results):
        print(f"ALL GREEN ({len(results)} checks)")
    else:
        print(f"FAILED: {results.count(False)} of {len(results)}")
        sys.exit(1)


main()
