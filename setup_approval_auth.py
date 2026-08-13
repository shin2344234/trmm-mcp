"""Set the password and second factor for the MCP approval page.

    ./venv/bin/python setup_approval_auth.py

Prompts for a password, generates a TOTP secret, shows a QR code to scan, and
writes the credentials to .env. The password itself is never stored - only a
PBKDF2 hash. Re-running replaces both and signs out every existing session.
"""

import getpass
import io
import os
import re
import sys

import pyotp
import qrcode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trmm_mcp import approval_auth  # noqa: E402

ENV = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


def read_password() -> str:
    # Allows non-interactive use for testing; interactive is the normal path.
    preset = os.environ.get("TRMM_APPROVAL_SETUP_PASSWORD")
    if preset:
        return preset
    while True:
        first = getpass.getpass("New approval-page password: ")
        if len(first) < 10:
            print("  Too short - use at least 10 characters.")
            continue
        second = getpass.getpass("Repeat it: ")
        if first != second:
            print("  Those did not match.")
            continue
        return first


def upsert(lines: list[str], key: str, value: str) -> list[str]:
    pattern = re.compile(rf"^{re.escape(key)}=")
    out = [line for line in lines if not pattern.match(line)]
    out.append(f"{key}={value}\n")
    return out


def main() -> None:
    password = read_password()
    secret = pyotp.random_base32()
    digest = approval_auth.hash_password(password)
    uri = approval_auth.provisioning_uri(secret)

    with open(ENV) as fh:
        lines = fh.readlines()
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"

    lines = upsert(lines, "TRMM_MCP_APPROVAL_PASSWORD_HASH", digest)
    lines = upsert(lines, "TRMM_MCP_APPROVAL_TOTP_SECRET", secret)

    with open(ENV, "w") as fh:
        fh.writelines(lines)
    os.chmod(ENV, 0o600)

    # Sign out anything already holding a session under the old credentials.
    approval_auth.bump_epoch()

    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.make(fit=True)
    buf = io.StringIO()
    qr.print_ascii(out=buf, invert=True)

    print("\nScan this with your authenticator app:\n")
    print(buf.getvalue())
    print(f"  Or enter the key manually: {secret}\n")
    print("Written to .env. Restart the server for it to take effect:")
    print("  sudo systemctl restart trmm-mcp\n")
    print("Every existing approval-page session has been signed out.")


main()
