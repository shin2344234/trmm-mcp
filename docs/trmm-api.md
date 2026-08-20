# TacticalRMM API — independent reference

Documented directly from the running source at `/rmm/api/tacticalrmm` on
`rmm-server`, cross-checked against upstream docs. Everything here was verified
against **TRMM 1.5.1 / web 0.0.203 / agent 2.11.0** (git `54eab4c9`, 2026-06-16).

Upstream's own position is that the API exists to serve their Vue frontend and is
under-documented; there is **no hosted API reference**. This file is the
substitute.

---

## 1. Authentication

```
X-API-KEY: <32-char uppercase key>
Content-Type: application/json
```

- Base URL is your backend host: `https://api.example.com`.
- Keys are generated server-side as `get_random_string(32).upper()`.
- A key belongs to a **user**, and inherits that user's **role** permissions.
- `expiration` is optional and unset by default — keys do not expire on their own.
- **API keys bypass 2FA.** Treat one as a full credential for its user.
- Managed at **Settings → Global Settings → API Keys**, or over the API at
  `/accounts/apikeys/`.

Auth is implemented in `tacticalrmm/auth.py::APIAuthentication`; the header is
read as `request.META["HTTP_X_API_KEY"]`. Knox token auth (the UI's session
mechanism) coexists on the same endpoints.

> Do not grant `can_list_api_keys` to a service role: `GET /accounts/apikeys/`
> returns key **values**, which turns any read-only key into every other key.

## 2. Conventions and traps

These cost real debugging time. All confirmed on this install.

1. Every URL needs a trailing slash. Django's `APPEND_SLASH` turns a slashless
   POST into a redirected GET, which surfaces as
   `{"detail": "Method \"GET\" not allowed."}`.
2. Several read endpoints use PATCH, not GET. `/alerts/` and `/logs/audit/` are
   queried with a PATCH filter body; `GET /alerts/` returns 405. Any "read-only
   means GET-only" assumption breaks here.
3. No pagination anywhere in the main API. There is no `DEFAULT_PAGINATION_CLASS`,
   so list endpoints serialize entire tables. `/logs/audit/` paginates internally
   via its own `pagination` body field. Only `/beta/v1/` (off by default) has
   real pagination.
4. Missing request fields return HTTP 500, not 400. Views index
   `request.data["x"]` directly with no serializer validation, so a `KeyError`
   escapes as an unhandled 500. Send every documented field, including no-op ones
   like `args: []` and `env_vars: []`.
5. `agent_id` is a ~40-char opaque string, not the numeric `id`. The URL
   converter regex is `[^/]{20}[^/]+`. Scripts, checks, tasks, notes, custom
   fields and roles use integer pks instead, and both appear in the same
   responses.
6. Command responses are bare JSON strings, not objects. `POST .../cmd/` returns
   e.g. `"workstation-01\r\n"`: stderr if non-empty, otherwise stdout.
7. No rate limiting on API-key traffic. Throttles are defined only for the login
   endpoints, so throttle yourself.
8. Agents must be online. There is no queueing for `cmd/` or `runscript/`; an
   offline agent yields `"Unable to contact the agent"`.
9. Responses can be enormous. Measured on one ordinary workstation here,
   `GET /agents/<id>/` returned 192 KB (`services` 118 KB, `wmi_detail` 60 KB,
   `all_timezones` 11 KB). By contrast `GET /agents/` (the whole list) was 1.2 KB
   per agent. Fetch detail deliberately.

## 3. Route index

Complete route table as mounted in `tacticalrmm/urls.py`. `<agent>` is the
string `agent_id`; `<pk>` is an integer.

### `/agents/`
| Route | Notes |
|---|---|
| `GET /agents/` | All agents. `?detail=false` gives a 5-field summary; `?client=`, `?site=`, `?monitoring_type=` filter |
| `GET/PUT/DELETE /agents/<agent>/` | Agent detail (huge — see trap 9) |
| `POST /agents/<agent>/cmd/` | Raw shell command |
| `POST /agents/<agent>/runscript/` | Run a saved script |
| `GET /agents/<agent>/ping/` | Liveness |
| `POST /agents/<agent>/reboot/` · `/shutdown/` | Power control |
| `GET /agents/<agent>/processes/` · `DELETE .../processes/<pid>/` | Process list / kill |
| `GET /agents/<agent>/eventlog/<logtype>/<days>/` | `logtype` = Application, System, Security |
| `GET /agents/<agent>/checks/` · `/tasks/` · `/pendingactions/` · `/notes/` | Per-agent collections |
| `GET /agents/<agent>/history/` · `GET /agents/history/` · `GET /agents/scripthistory/` | Command/script history **with captured output** |
| `POST /agents/<agent>/wol/` | Wake-on-LAN |
| `GET /agents/<agent>/wmi/` · `/registry/` · `/meshcentral/` | Inventory, registry browse, mesh handoff |
| `POST /agents/actions/bulk/` | Fleet-wide command/script/patch. Async, **returns no output** |
| `GET /agents/versions/` · `POST /agents/update/` | Agent version management |

### `/clients/`
`GET/POST /clients/`, `/clients/<pk>/`, `/clients/sites/`, `/clients/sites/<pk>/`,
`/clients/deployments/`, `/clients/<uid>/deploy/`

### `/checks/`
`GET/POST /checks/`, `/checks/<pk>/`, `POST /checks/<pk>/reset/`,
`POST /checks/<agent>/run/`, `GET /checks/<pk>/history/`

### `/services/`
`GET /services/<agent>/` — all Windows services.
`GET/POST/PUT /services/<agent>/<svcname>/` — POST body `{"sv_action": "start"|"stop"|"restart"}`;
PUT body `{"startType": "..."}`. Windows only; POSIX agents are rejected.

### `/software/`, `/winupdate/`
`GET /software/<agent>/`, `POST /software/<agent>/uninstall/`, `GET /software/chocos/`
`GET /winupdate/<agent>/`, `POST /winupdate/<agent>/scan/`, `POST /winupdate/<agent>/install/`

### `/scripts/`
`GET/POST /scripts/`, `GET/PUT/DELETE /scripts/<pk>/` (includes source code),
`/scripts/snippets/`, `POST /scripts/<agent>/test/`, `GET /scripts/<pk>/download/`

### `/tasks/` (automated tasks)
`GET/POST /tasks/`, `/tasks/<pk>/`, `POST /tasks/<pk>/run/`

### `/alerts/`
`PATCH /alerts/` (query — see §4), `GET/PUT/DELETE /alerts/<pk>/`,
`POST /alerts/bulk/`, `/alerts/templates/`

### `/logs/`
`PATCH /logs/audit/` (see §4), `GET /logs/debug/`,
`GET /logs/pendingactions/`, `/logs/pendingactions/<pk>/`

### `/core/`
`GET/PATCH /core/settings/`, `GET /core/version/`, `GET /core/dashinfo/`
(UI preferences, not fleet stats), `/core/customfields/`, `/core/keystore/`
(**secrets**), `/core/urlaction/`, `/core/schedules/`, `GET /core/status/`,
`POST /core/servermaintenance/`, `POST /core/clearcache/`

### `/automation/`
`/automation/policies/`, `/automation/policies/<pk>/related/`,
`/automation/policies/overview/`, `/automation/policies/<policy>/checks/`,
`/automation/policies/<policy>/tasks/`, `/automation/patchpolicy/`

### `/accounts/`
`/accounts/users/`, `/accounts/roles/`, `/accounts/apikeys/` (**returns key
values**), `POST /accounts/resetpw/`, `POST /accounts/reset2fa/`

### Not for API consumers
`/api/v3/`, `/api/v4/` are the agent↔server channel. `/reporting/` is the EE
reporting module. `/beta/v1/` is off unless `BETA_API_ENABLED = True`.

## 4. Verified request bodies

### Run a command — `POST /agents/<agent>/cmd/`
```json
{"cmd": "hostname", "shell": "cmd", "timeout": 60, "run_as_user": false}
```
All four fields are **required** (`custom_shell` is additionally required when
`shell` is `"custom"`). `shell` is `cmd` or `powershell` on Windows; on
Linux/macOS it is passed to the agent. Returns a bare string. Upstream's own
example omits `run_as_user` and will 500 on this version.

### Run a script — `POST /agents/<agent>/runscript/`
```json
{"script": 89, "output": "wait", "args": [], "env_vars": [],
 "run_as_user": false, "timeout": 90, "emails": [], "emailMode": "default",
 "custom_field": null, "save_all_output": false}
```
`output` drives the response shape:
`wait`/`note`/`collector` → synchronous bare string (stdout+stderr concatenated);
`email` → queued, returns immediately; anything else → async, returns a status
sentence. `run_on_server: true` is the only variant returning a structured
`{stdout, stderr, execution_time, retcode}` — and it is disabled by default.

Structured results (including `retcode`) always land in `AgentHistory`; retrieve
them from `GET /agents/<agent>/history/`. Async runs return **no correlation
handle**, so you must match on script + user + time.

### Query alerts — `PATCH /alerts/`
```json
{"top": 25}
```
returns `{"alerts_count": N, "alerts": [...]}` (newest unresolved). Or filter:
```json
{"timeFilter": 30, "severityFilter": ["error","warning"],
 "resolvedFilter": false, "snoozedFilter": false}
```
⚠️ Quirk: `resolvedFilter`/`snoozedFilter` are applied **only when false**
(`if "resolvedFilter" in data and not data["resolvedFilter"]`). Passing `true` is
a silent no-op, not "show only resolved".

### Query the audit log — `PATCH /logs/audit/`
```json
{"pagination": {"page": 1, "rowsPerPage": 50, "sortBy": "entry_time", "descending": true},
 "timeFilter": 7, "agentFilter": ["<agent_id>"], "userFilter": ["someuser"]}
```
`pagination` is **required** (indexed directly → 500 if absent). Returns
`{"audit_logs": [...], "total": N}`.

## 5. Role permission flags

Roles are boolean flags on `accounts.models.Role`. A request needs the flag
**and** `_has_perm_on_agent()` must pass for that agent's client/site.

Empty `can_view_clients` **and** empty `can_view_sites` means **all agents** —
scoping is opt-in, not default-deny.

Read: `can_list_agents`, `can_list_agent_history`, `can_view_eventlogs`,
`can_list_checks`, `can_list_clients`, `can_list_sites`, `can_list_autotasks`,
`can_list_scripts`, `can_list_alerts`, `can_list_software`,
`can_view_auditlogs`, `can_view_debuglogs`, `can_list_pendingactions`,
`can_view_core_settings`, `can_view_customfields`, `can_list_accounts`,
`can_list_roles`, `can_view_reports`, `can_list_deployments`,
`can_list_automation_policies`, `can_list_alerttemplates`, `can_view_schedules`,
`can_list_notes`

Execute: `can_send_cmd`, `can_run_scripts`, `can_reboot_agents`,
`can_manage_procs`, `can_manage_winsvcs`, `can_send_wol`, `can_run_checks`,
`can_run_autotasks`, `can_run_bulk`, `can_run_server_scripts`, `can_use_terminal`,
`can_use_webterm`, `can_use_mesh`, `can_use_registry`, `can_run_urlactions`

Administer: every `can_manage_*` / `can_edit_*`, plus `can_install_agents`,
`can_update_agents`, `can_uninstall_agents`, `can_recover_agents`,
`can_do_server_maint`, `can_code_sign`

Sensitive even though nominally read-only: `can_list_api_keys` (returns key
values) and `can_view_global_keystore` (script secrets).

## 6. Enabling Swagger (optional)

Add to `/rmm/api/tacticalrmm/tacticalrmm/local_settings.py`:

```python
SWAGGER_ENABLED = True
```

then `sudo systemctl restart rmm.service`. Serves `/api/schema/` and
`/api/schema/swagger-ui/`. Quality is poor — most views are plain `APIView`s
with hand-rolled `request.data` access, so request bodies cannot be inferred.
Treat it as a route index, not a contract; §4 above is more accurate.

## 7. Key source files

| Concern | File |
|---|---|
| Route mounting | `tacticalrmm/urls.py` |
| API key auth | `tacticalrmm/auth.py` |
| Permission helpers | `tacticalrmm/permissions.py` |
| Command / script execution | `agents/views.py` (`send_raw_cmd`, `run_script`) |
| Agent model, NATS bridge | `agents/models.py` |
| Roles, users, API keys | `accounts/models.py`, `accounts/views.py` |
| Alert queries | `alerts/views.py::GetAddAlerts` |
| Audit queries | `logs/views.py::GetAuditLogs` |
| Service control | `services/views.py::GetEditActionService` |
| Shell/type enums | `tacticalrmm/constants.py` |
