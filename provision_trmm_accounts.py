"""
Provision dedicated TacticalRMM service accounts + API keys for the MCP server.

Creates two roles / users / keys so that read-only is enforced by TRMM itself,
not only by the MCP server's own gating:

  mcp-readonly : list/view permissions only. Cannot execute anything.
  mcp-command  : the read-only set plus agent command/script execution.

Deliberately withheld from BOTH roles:
  can_list_api_keys      - the API key list endpoint returns key values (escalation)
  can_view_global_keystore - holds script secrets
  can_use_mesh / can_use_registry / can_use_terminal / can_use_webterm
  can_run_server_scripts - executes on the TRMM server itself
  can_run_bulk           - fleet-wide fan-out, returns no output
  every can_manage_* / can_edit_* / uninstall / update / install perm

Idempotent. Run again with --rotate to issue fresh keys.

Usage (from /rmm/api/tacticalrmm):
    /rmm/api/env/bin/python /opt/trmm-mcp/provision_trmm_accounts.py [--rotate]
"""

import os
import sys

import django

sys.path.insert(0, "/rmm/api/tacticalrmm")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tacticalrmm.settings")
django.setup()

from django.utils.crypto import get_random_string  # noqa: E402

from accounts.models import APIKey, Role, User  # noqa: E402

READ_PERMS = [
    "can_list_agents",
    "can_view_eventlogs",
    "can_list_agent_history",
    "can_list_notes",
    "can_view_core_settings",
    "can_view_customfields",
    "can_view_schedules",
    "can_list_checks",
    "can_list_clients",
    "can_list_sites",
    "can_list_deployments",
    "can_list_automation_policies",
    "can_list_autotasks",
    "can_view_auditlogs",
    "can_list_pendingactions",
    "can_view_debuglogs",
    "can_list_scripts",
    "can_list_alerts",
    "can_list_alerttemplates",
    "can_list_software",
    "can_list_accounts",
    "can_list_roles",
    "can_view_reports",
]

EXEC_PERMS = [
    "can_send_cmd",
    "can_run_scripts",
    "can_reboot_agents",
    "can_send_wol",
    "can_run_checks",
    "can_run_autotasks",
]

# TRMM has no view-only permission for services, processes or Windows updates:
# GET and the mutating verbs on those endpoints are gated by the SAME can_manage_*
# flag (services/permissions.py, agents/permissions.py, winupdate/permissions.py).
# Without these the read-only role cannot see running services or processes at
# all, which guts diagnosis. Granted so reads work; the read-only MCP server
# still refuses every non-GET request client-side, so the mutating half of these
# permissions is unreachable through it.
VIEW_REQUIRES_MANAGE_PERMS = [
    "can_manage_procs",
    "can_manage_winsvcs",
    "can_manage_winupdates",
]

READ_ROLE_PERMS = READ_PERMS + VIEW_REQUIRES_MANAGE_PERMS
COMMAND_ROLE_PERMS = READ_ROLE_PERMS + EXEC_PERMS

ROTATE = "--rotate" in sys.argv


def sync_role(name, perms):
    role, created = Role.objects.get_or_create(name=name)
    for field in Role._meta.get_fields():
        fname = getattr(field, "name", "")
        if fname.startswith("can_") and not field.many_to_many:
            setattr(role, fname, fname in perms)
    role.is_superuser = False
    role.save()
    print(f"  role  {name!r:22} {'created' if created else 'updated'}")
    return role


def sync_user(username, role):
    user, created = User.objects.get_or_create(
        username=username,
        defaults={"is_active": True, "block_dashboard_login": True},
    )
    user.role = role
    user.is_active = True
    user.is_superuser = False
    user.block_dashboard_login = True  # API-key use only, no UI login
    user.set_unusable_password()
    user.save()
    print(f"  user  {username!r:22} {'created' if created else 'updated'}")
    return user


def sync_key(name, user):
    existing = APIKey.objects.filter(name=name).first()
    if existing and not ROTATE:
        print(f"  key   {name!r:22} kept existing")
        return existing.key
    key = get_random_string(length=32).upper()
    if existing:
        existing.key = key
        existing.user = user
        existing.save()
        print(f"  key   {name!r:22} ROTATED")
    else:
        APIKey.objects.create(name=name, key=key, user=user, expiration=None)
        print(f"  key   {name!r:22} created")
    return key


print("Provisioning TacticalRMM MCP service accounts")

ro_role = sync_role("MCP Read Only", READ_ROLE_PERMS)
ro_user = sync_user("mcp-readonly", ro_role)
ro_key = sync_key("mcp-readonly", ro_user)

cmd_role = sync_role("MCP Command", COMMAND_ROLE_PERMS)
cmd_user = sync_user("mcp-command", cmd_role)
cmd_key = sync_key("mcp-command", cmd_user)

env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

# Preserve settings this script does not own. Rewriting .env from scratch and
# re-emitting only the keys we know about would silently delete the approval
# page's password + TOTP, downgrading elevate mode to bearer-token-only login
# without any error - the exact failure this comment exists to prevent.
PRESERVE = (
    "TRMM_MCP_APPROVAL_PASSWORD_HASH",
    "TRMM_MCP_APPROVAL_TOTP_SECRET",
    "TRMM_MCP_APPROVAL_SESSION",
    "TRMM_MCP_APPROVAL_MAX_ATTEMPTS",
    "TRMM_MCP_AGENT_ALLOWLIST",
    # Where this install binds and how the operator reaches it. These live in
    # .env so the shipped systemd unit can stay generic; losing them here would
    # silently drop the server back to loopback on the next restart.
    "TRMM_MCP_HTTP_HOST",
    "TRMM_MCP_PUBLIC_URL",
    "TRMM_MCP_HTTP_PORT",
    "TRMM_MCP_TRANSPORT",
    "TRMM_MCP_ALLOWED_HOSTS",
    "TRMM_MCP_TLS",
    "TRMM_MCP_TLS_CERT",
    "TRMM_MCP_TLS_KEY",
    "TRMM_MCP_STATELESS_HTTP",
    "TRMM_HTTP_TIMEOUT",
    "TRMM_HTTP_READ_TIMEOUT",
)

auth_token = ""
preserved: list[str] = []
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            if line.startswith("TRMM_MCP_AUTH_TOKEN="):
                auth_token = line.split("=", 1)[1].strip()
            elif line.split("=", 1)[0].strip() in PRESERVE and "=" in line:
                preserved.append(line.rstrip("\n"))

if not auth_token or ROTATE:
    auth_token = get_random_string(length=44)

with open(env_path, "w") as f:
    f.write(
        "# TacticalRMM MCP server configuration.\n"
        "# Generated by provision_trmm_accounts.py. Contains live credentials.\n\n"
        "TRMM_API_URL=https://api.example.com\n\n"
        "# Read-only key: bound to the 'MCP Read Only' TRMM role.\n"
        f"TRMM_READONLY_API_KEY={ro_key}\n\n"
        "# Command key: adds agent command/script execution.\n"
        "# Only consulted when TRMM_MCP_MODE=command.\n"
        f"TRMM_COMMAND_API_KEY={cmd_key}\n\n"
        "# Mode is deliberately NOT set here. systemd's EnvironmentFile= overrides\n"
        "# Environment=, so an active value in this file would silently win over\n"
        "# the mode chosen in the unit file or by run.sh.\n"
        "# readonly (default) | elevate | command\n"
        "# TRMM_MCP_MODE=readonly\n\n"
        "# Bearer token for the HTTP listener. Required to bind anywhere other\n"
        "# than loopback. Clients send: Authorization: Bearer <token>\n"
        f"TRMM_MCP_AUTH_TOKEN={auth_token}\n"
        + (
            "\n# Preserved from the previous .env (not owned by this script).\n"
            + "\n".join(preserved) + "\n"
            if preserved else ""
        )
    )
os.chmod(env_path, 0o600)

print(f"\nWrote {env_path} (mode 600)")
print(f"  readonly key : {ro_key}")
print(f"  command  key : {cmd_key}")
print(f"  http token   : {auth_token}")
if preserved:
    kept = ", ".join(line.split("=", 1)[0] for line in preserved)
    print(f"  preserved    : {kept}")
