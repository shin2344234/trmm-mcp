# SPDX-License-Identifier: AGPL-3.0-or-later
"""Browser approval page for pending privileged operations.

Deliberately plain: no external assets, no JS frameworks, one form per action.
The point is that a human reads the exact command and clicks a button, in a
channel the model has no way to reach.
"""

from __future__ import annotations

import html
import json
import time
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from . import approval_auth, config, elevation, observability, render

COOKIE = "trmm_mcp_approval"

STYLE = """
:root {
  color-scheme: light dark;
  --line: #8884; --dim: #8889; --panel: #8881;
  --high: #b42318; --mid: #9a6700; --low: #1a7f37;
}
* { box-sizing: border-box; }
body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
       max-width: 54rem; margin: 1.5rem auto 4rem; padding: 0 1rem; line-height: 1.5; }
h1 { font-size: 1.35rem; margin: 0 0 .2rem; }
h2 { font-size: .82rem; text-transform: uppercase; letter-spacing: .07em;
     color: var(--dim); margin: 2.2rem 0 .6rem; }
a { color: inherit; }

/* --- request card --- */
.req { border: 1px solid var(--line); border-radius: 10px; margin: 1rem 0;
       overflow: hidden; }
.req-top { padding: .9rem 1rem .8rem; }
.sev { display: inline-block; font-size: .68rem; font-weight: 700;
       letter-spacing: .09em; padding: .2rem .5rem; border-radius: 4px;
       border: 1.5px solid currentColor; margin-bottom: .5rem; }
.sev-high { color: var(--high); }
.sev-mid { color: var(--mid); }
.sev-low { color: var(--low); }
.sev-unknown { color: var(--high); border-style: dashed; }
.req.sev-high { border-color: var(--high); border-left-width: 5px; }
.req.sev-unknown { border-color: var(--high); border-left-width: 5px;
                   border-left-style: dashed; }
.req.sev-mid { border-left: 5px solid var(--mid); }
.req.sev-low { border-left: 5px solid var(--low); }
.title { font-size: 1.12rem; font-weight: 620; margin: 0; }
.target { font-size: 1.12rem; margin: .1rem 0 0; }
.target b { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-weight: 700; }
.alert { margin: .7rem 0 0; padding: .5rem .7rem; border-radius: 6px;
         background: color-mix(in srgb, var(--high) 12%, transparent);
         border: 1px solid color-mix(in srgb, var(--high) 45%, transparent);
         font-size: .9rem; }
.when { font-size: .82rem; color: var(--dim); margin-top: .6rem; }

/* --- facts --- */
table.facts { width: 100%; border-collapse: collapse; margin: .8rem 0 0;
              font-size: .9rem; }
table.facts th { text-align: left; font-weight: 500; color: var(--dim);
                 padding: .22rem .8rem .22rem 0; white-space: nowrap;
                 vertical-align: top; width: 1%; }
table.facts td { padding: .22rem 0; word-break: break-word; }

/* --- verbatim evidence --- */
.evidence { margin: .9rem 1rem 0; border: 1px solid var(--line);
            border-radius: 8px; overflow: hidden; }
.evhead { display: flex; flex-wrap: wrap; gap: .5rem; align-items: baseline;
          justify-content: space-between; padding: .4rem .6rem;
          background: var(--panel); font-size: .8rem; font-weight: 600; }
.evtag { font-weight: 400; color: var(--dim); font-size: .72rem; }
.code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: .84rem; overflow-x: auto; padding: .4rem 0; }
.ln { display: flex; white-space: pre; }
.num { flex: 0 0 2.6rem; text-align: right; padding-right: .8rem;
       color: var(--dim); user-select: none; position: sticky; left: 0;
       background: inherit; }
.src { white-space: pre; padding-right: 1rem; }
.ctl { background: var(--high); color: #fff; border-radius: 2px;
       padding: 0 .1rem; font-size: .78em; }
.evfoot { padding: .3rem .6rem; font-size: .74rem; color: var(--dim);
          border-top: 1px solid var(--line); }
ul.notices { margin: 0; padding: .5rem .6rem .5rem 1.8rem; font-size: .82rem;
             border-top: 1px solid var(--line);
             background: color-mix(in srgb, var(--mid) 10%, transparent); }
ul.notices li { margin: .15rem 0; }

/* --- actions --- */
.actions { display: flex; flex-wrap: wrap; gap: .6rem; padding: .9rem 1rem 1rem;
           align-items: center; }
button { font: inherit; padding: .5rem 1.1rem; border-radius: 7px;
         border: 1px solid var(--line); cursor: pointer; min-height: 2.6rem;
         background: transparent; color: inherit; }
.approve { background: var(--low); color: #fff; border-color: transparent;
           font-weight: 600; }
.req.sev-high .approve, .req.sev-unknown .approve { background: var(--high); }
form { display: inline; margin: 0; }
.hint { font-size: .78rem; color: var(--dim); }

/* --- misc --- */
.card { border: 1px solid var(--line); border-radius: 8px; padding: .8rem 1rem;
        margin: .7rem 0; }
.meta { color: var(--dim); font-size: .84rem; }
.empty { color: var(--dim); font-style: italic; }
.warn { border-left: 3px solid var(--high); padding-left: .8rem; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
input[type=password], input[type=text], input[type=number] {
  font: inherit; padding: .55rem; border-radius: 7px;
  border: 1px solid var(--line); background: transparent; color: inherit;
  min-height: 2.6rem; }
input[type=number] { width: 5.5rem; }
/* --- activity log --- */
.nav { display: flex; gap: .45rem; flex-wrap: wrap; align-items: center;
       margin: .7rem 0 0; }
.btn { display: inline-block; font-size: .85rem; padding: .45rem .9rem;
       border: 1px solid var(--line); border-radius: 7px; cursor: pointer;
       text-decoration: none; color: inherit; min-height: 2.2rem; }
.btn:hover { background: var(--panel); }
.btn.on { background: var(--panel); font-weight: 640; border-color: var(--dim); }
table.log { width: 100%; border-collapse: collapse; font-size: .86rem;
            margin: .6rem 0 0; }
table.log th { text-align: left; font-weight: 500; color: var(--dim);
               font-size: .72rem; text-transform: uppercase;
               letter-spacing: .06em; padding: .3rem .7rem .3rem 0;
               border-bottom: 1px solid var(--line); }
table.log td { padding: .38rem .7rem .38rem 0; vertical-align: top;
               border-bottom: 1px solid var(--panel); }
td.t { white-space: nowrap; color: var(--dim); width: 1%;
       font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
       font-size: .79rem; }
td.k { white-space: nowrap; width: 1%; }
td.d { word-break: break-word; }
td.d code { font-size: .82rem; }
.kind { display: inline-block; font-size: .66rem; font-weight: 700;
        letter-spacing: .04em; padding: .12rem .4rem; border-radius: 4px;
        border: 1px solid currentColor; white-space: nowrap; }
.k-high { color: var(--high); }
.k-mid { color: var(--mid); }
.k-low { color: var(--low); }
.k-dim { color: var(--dim); }
.ok { color: var(--low); font-weight: 600; }
.bad { color: var(--high); font-weight: 600; }

/* --- commands run --- */
.cmd { border: 1px solid var(--line); border-radius: 10px; margin: 1rem 0;
       overflow: hidden; border-left-width: 5px; }
.cmd-top { padding: .85rem 1rem .7rem; }
.cmd.st-ran { border-left-color: var(--low); }
.cmd.st-failed, .cmd.st-blocked { border-left-color: var(--high); }
.cmd.st-refused { border-left-color: var(--mid); }
.cmd.st-unknown { border-left-color: var(--dim); border-left-style: dashed; }
.st { display: inline-block; font-size: .66rem; font-weight: 700;
      letter-spacing: .08em; padding: .2rem .5rem; border-radius: 4px;
      border: 1.5px solid currentColor; margin-bottom: .5rem; }
.st.st-ran { color: var(--low); }
.st.st-failed, .st.st-blocked { color: var(--high); }
.st.st-refused { color: var(--mid); }
.st.st-unknown { color: var(--dim); border-style: dashed; }
.cmd-facts { padding: 0 1rem; }
.cmd .evidence { margin: .9rem 1rem; }
.cmd .hint { padding: 0 1rem .8rem; margin: 0; }

@media (max-width: 30rem) {
  .actions button { flex: 1 1 100%; }
  .num { flex-basis: 2rem; }
}
"""

COUNTDOWN_JS = """
(function () {
  function plural(n, w) { return n + ' ' + w + (n === 1 ? '' : 's'); }
  function tick() {
    var now = Date.now() / 1000;
    document.querySelectorAll('[data-expires]').forEach(function (el) {
      var left = Math.max(0, Math.round(el.dataset.expires - now));
      if (left <= 0) { el.textContent = 'expired'; el.classList.add('gone'); return; }
      el.textContent = left < 60
        ? 'expires in ' + plural(left, 'second')
        : 'expires in ' + plural(Math.round(left / 60), 'minute');
    });
  }
  tick();
  setInterval(tick, 1000);
  // Refresh so newly requested approvals appear, unless something is being typed.
  setInterval(function () {
    var a = document.activeElement;
    if (a && (a.tagName === 'INPUT' || a.tagName === 'BUTTON')) return;
    location.reload();
  }, 20000);
})();
"""


def _page(title: str, body: str, script: bool = False) -> HTMLResponse:
    tail = f"<script>{COUNTDOWN_JS}</script>" if script else ""
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head>"
        f"<body>{body}{tail}</body></html>"
    )


def _request_card(record: dict[str, Any]) -> str:
    """One pending operation, rendered to be understood at a glance."""
    display = record.get("display") or {}
    params = record.get("params") or {}
    word, sev_class = render.severity(record)

    action = display.get("action")
    target = display.get("target")

    if action:
        heading = (
            f'<p class="title">{html.escape(str(action))}</p>'
            + (f'<p class="target">on <b>{html.escape(str(target))}</b></p>'
               if target else "")
        )
    else:
        # No display metadata: an older record, or one we failed to describe.
        heading = (
            f'<p class="title">{html.escape(str(record.get("tool", "unknown tool")))}</p>'
            f'<p class="target">{html.escape(str(record.get("summary", "")))}</p>'
        )

    blocks = [f'<div class="req-top"><span class="sev {sev_class}">{word}</span>',
              heading]

    if not display:
        blocks.append(
            '<p class="alert">This request carries no description, so it could '
            'not be classified. Read the raw parameters below before approving.</p>'
        )
    elif display.get("warning"):
        blocks.append(f'<p class="alert">{html.escape(str(display["warning"]))}</p>')

    facts = list(display.get("facts") or [])
    if not display:
        facts = [[k, json.dumps(v, default=str)] for k, v in sorted(params.items())]
    blocks.append(render.facts_table(facts))

    expires = float(record.get("expires", 0))
    blocks.append(
        f'<p class="when">Requested {html.escape(_ago(float(record.get("created", 0))))}'
        f' · <span data-expires="{expires:.0f}">expires in '
        f'{html.escape(_duration(expires - time.time()))}</span></p></div>'
    )

    code = display.get("code")
    if code:
        blocks.append(render.code_block(str(code), "Exact command to be run"))

    request_id = html.escape(str(record.get("id", "")))
    blocks.append(
        f'<div class="actions">'
        f'<form method="post" action="approve/{request_id}">'
        f'<button class="approve">Approve once</button></form>'
        f'<form method="post" action="deny/{request_id}">'
        f'<button>Deny</button></form>'
        f'<span class="hint">Runs once, then locks again.</span>'
        f"</div>"
    )

    return f'<div class="req {sev_class}">{"".join(blocks)}</div>'


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _authed(request: Request) -> bool:
    cookie = request.cookies.get(COOKIE)
    if approval_auth.is_configured():
        return approval_auth.valid_session(cookie)
    # Not yet configured: fall back to the bearer token so the page still works.
    if not config.AUTH_TOKEN:
        return True
    return cookie == config.AUTH_TOKEN


def _login_page(message: str = "", locked: int = 0) -> HTMLResponse:
    warn = f"<p class='warn'>{html.escape(message)}</p>" if message else ""

    if locked > 0:
        return _page(
            "TRMM MCP approvals",
            f"<h1>TRMM MCP approvals</h1>"
            f"<p class='warn'>Too many failed attempts. Try again in {locked}s.</p>",
        )

    if approval_auth.is_configured():
        fields = (
            "<p><input type='password' name='password' autofocus "
            "placeholder='Password' autocomplete='current-password'></p>"
            "<p><input type='text' name='code' placeholder='6-digit code' "
            "inputmode='numeric' pattern='[0-9]*' autocomplete='one-time-code'></p>"
        )
        blurb = "<p>Sign in to review operations waiting for approval.</p>"
    else:
        fields = (
            "<p><input type='password' name='token' autofocus "
            "placeholder='TRMM_MCP_AUTH_TOKEN'></p>"
        )
        blurb = (
            "<p>Enter the server token.</p>"
            "<p class='warn'>No password or second factor is configured. Run "
            "<code>setup_approval_auth.py</code> on the server to protect this page "
            "properly - right now it shares a secret with every MCP client.</p>"
        )

    return _page(
        "TRMM MCP approvals",
        f"<h1>TRMM MCP approvals</h1>{warn}{blurb}"
        f"<form method='post' action='login'>{fields}"
        "<button class='approve'>Sign in</button></form>",
    )


async def login(request: Request):
    who = _client(request)
    locked = approval_auth.locked_for(who)
    if locked:
        observability.event("approval_login", result="locked-out", client=who)
        return _login_page(locked=locked)

    form = await request.form()

    if approval_auth.is_configured():
        password = str(form.get("password", ""))
        code = str(form.get("code", ""))
        ok_password = approval_auth.verify_password(
            password, config.APPROVAL_PASSWORD_HASH
        )
        step = approval_auth.check_totp(code)
        ok_code = step is not None
        if not (ok_password and ok_code):
            approval_auth.note_failure(who)
            observability.event(
                "approval_login", result="rejected", client=who,
                # Recorded for triage; never shown to whoever is trying.
                password_ok=ok_password, code_ok=ok_code,
            )
            return _login_page(
                "Incorrect password or code.", locked=approval_auth.locked_for(who)
            )
        # Both factors are good: spend the code so it cannot be reused.
        approval_auth.consume_totp(step)
        approval_auth.note_success(who)
        observability.event("approval_login", result="accepted", client=who)
        response = RedirectResponse(url=".", status_code=303)
        response.set_cookie(
            COOKIE,
            approval_auth.issue_session(),
            httponly=True,
            samesite="strict",
            secure=config.TLS_ENABLED,
            max_age=config.APPROVAL_SESSION_SECONDS,
        )
        return response

    token = str(form.get("token", ""))
    if config.AUTH_TOKEN and token != config.AUTH_TOKEN:
        approval_auth.note_failure(who)
        observability.event("approval_login", result="rejected-token", client=who)
        return _login_page("That token was not correct.",
                           locked=approval_auth.locked_for(who))
    approval_auth.note_success(who)
    observability.event("approval_login", result="accepted-token", client=who)
    response = RedirectResponse(url=".", status_code=303)
    response.set_cookie(
        COOKIE, config.AUTH_TOKEN, httponly=True, samesite="strict",
        secure=config.TLS_ENABLED, max_age=86400,
    )
    return response


async def logout(_request: Request):
    response = RedirectResponse(url=".", status_code=303)
    response.delete_cookie(COOKIE)
    return response


def _duration(seconds: float) -> str:
    """'9 minutes', '45 seconds' - readable, not '583s'."""
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds} second{'' if seconds == 1 else 's'}"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'' if minutes == 1 else 's'}"
    hours = minutes // 60
    remainder = minutes % 60
    text = f"{hours} hour{'' if hours == 1 else 's'}"
    return f"{text} {remainder} min" if remainder else text


def _ago(timestamp: float) -> str:
    delta = time.time() - timestamp
    return "just now" if delta < 5 else f"{_duration(delta)} ago"


async def index(request: Request):
    if not _authed(request):
        return _login_page()

    state = elevation.snapshot()
    pending = [p for p in state["pending"] if p["status"] == "pending"]
    approved = [p for p in state["pending"] if p["status"] == "approved"]
    windows = state["windows"]
    now = time.time()

    count = len(pending)
    headline = (
        "Nothing is waiting for you." if not count
        else f"{count} operation{'' if count == 1 else 's'} waiting for approval"
    )
    parts = [
        f"<h1>{headline}</h1>",
        f"<p class='meta'>TacticalRMM · mode: {html.escape(config.MODE)}</p>",
        "<p class='nav'>"
        "<a class='btn' href='commands'>Review commands run</a>"
        "<a class='btn' href='history'>View activity log</a></p>",
    ]

    if not pending:
        parts.append(
            "<p class='empty'>When the assistant asks to change something, it "
            "will appear here.</p>"
        )
    for record in pending:
        parts.append(_request_card(record))

    if approved:
        parts.append("<h2>Approved · waiting for the assistant to run it</h2>")
        for record in approved:
            display = record.get("display") or {}
            what = display.get("action") or record.get("summary", "")
            target = display.get("target")
            parts.append(
                f"<div class='card'><strong>{html.escape(str(what))}</strong>"
                + (f" on <code>{html.escape(str(target))}</code>" if target else "")
                + "<p class='meta'>Single use — it stops working once it runs, "
                  "or when it expires.</p></div>"
            )

    parts.append("<h2>Standing permission</h2>")
    if not windows:
        parts.append(
            "<p class='empty'>None — every execution needs approving one at a time.</p>"
        )
    for window in windows:
        uses = window.get("uses_left")
        scope = window.get("agent") or "any machine"
        parts.append(
            f"<div class='card'><strong>Anything may run without asking</strong>"
            f"<p class='meta'>"
            f"<span data-expires='{float(window['expires']):.0f}'>expires in "
            f"{html.escape(_duration(window['expires'] - now))}</span> &middot; "
            f"{'unlimited uses' if uses is None else f'{uses} use(s) left'} &middot; "
            f"{html.escape(scope)}</p></div>"
        )

    parts.append(
        "<p class='meta'>Skip individual approvals for a burst of work:</p>"
        "<form method='post' action='window'>"
        "<input type='number' name='minutes' value='10' min='1' max='60'> minutes, "
        "<input type='number' name='uses' value='5' min='1' max='50'> uses "
        "<button>Allow without asking</button></form>"
    )

    if pending or approved or windows:
        parts.append(
            "<h2>Panic button</h2><form method='post' action='revoke'>"
            "<button>Cancel everything above</button></form>"
        )

    auth_note = (
        "password + 2FA" if approval_auth.is_configured() else "shared token only"
    )
    parts.append(
        f"<h2>Session</h2><p class='meta'>Signed in with {auth_note}.</p>"
        "<form method='post' action='logout'><button>Sign out</button>"
        "</form>"
    )

    return _page("TRMM MCP approvals", "".join(parts), script=True)


async def approve(request: Request):
    if not _authed(request):
        return _login_page()
    elevation.approve(request.path_params["request_id"])
    return RedirectResponse(url="../", status_code=303)


async def deny(request: Request):
    if not _authed(request):
        return _login_page()
    elevation.deny(request.path_params["request_id"])
    return RedirectResponse(url="../", status_code=303)


async def window(request: Request):
    if not _authed(request):
        return _login_page()
    form = await request.form()
    minutes = int(str(form.get("minutes", "10")) or 10)
    uses = int(str(form.get("uses", "5")) or 5)
    elevation.open_window(minutes * 60, uses=uses)
    return RedirectResponse(url=".", status_code=303)


async def revoke(request: Request):
    if not _authed(request):
        return _login_page()
    elevation.revoke_all()
    return RedirectResponse(url=".", status_code=303)


# --- activity log -----------------------------------------------------------
#
# The approval page answers "what is being asked of me right now". This answers
# "what has this server actually been doing" - the question you ask after the
# fact, when something looks wrong. It reads the same events.jsonl the CLI
# reads, so there is one audit trail, not two.

# Which event kinds sit behind each filter chip. Empty tuple means "no filter".
LOG_GROUPS: dict[str, tuple[str, ...]] = {
    "all": (),
    "approvals": ("approval", "elevation_required", "elevation_granted"),
    "executions": ("mutation",),
    "refused": ("blocked",),
    "problems": ("error", "startup_warning"),
    "signins": ("approval_login",),
    "calls": ("request", "response"),
    "api": ("api_call",),
}

LOG_LABELS = {
    "all": "Everything",
    "approvals": "Approvals",
    "executions": "Changes made",
    "refused": "Refused",
    "problems": "Problems",
    "signins": "Sign-ins",
    "calls": "Tool calls",
    "api": "TRMM API",
}

# Colour by how much the reader should care, not by alphabet.
KIND_CLASS = {
    "blocked": "k-high", "error": "k-high", "mutation": "k-high",
    "startup_warning": "k-mid", "elevation_required": "k-mid",
    "approval": "k-mid",
    "elevation_granted": "k-low", "approval_login": "k-low",
}

# How far back to look before filtering. A filter that matches nothing recent
# should not turn into a full scan of a log that may be hundreds of MB.
SCAN_LINES = 20000


def _tail_lines(path, wanted: int) -> list[str]:
    """The last `wanted` lines, read backwards so a large log stays cheap."""
    if not path.exists():
        return []
    step = 64 * 1024
    data = b""
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            position = handle.tell()
            while position > 0 and data.count(b"\n") <= wanted:
                back = min(step, position)
                position -= back
                handle.seek(position)
                data = handle.read(back) + data
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()[-wanted:]


def _load_events(kinds: tuple[str, ...], query: str, limit: int):
    """Newest `limit` events matching the filters, plus how many lines we read."""
    lines = _tail_lines(config.LOG_DIR / "events.jsonl", SCAN_LINES)
    needle = query.lower()
    found: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if kinds and record.get("kind") not in kinds:
            continue
        if needle and needle not in json.dumps(record, default=str).lower():
            continue
        found.append(record)
    return found[-limit:], len(lines)


def _mono(text: Any, cap: int = 220) -> str:
    """Model-supplied text. _visible escapes it AND unmasks bidi/zero-width,
    so a command cannot reorder itself into looking harmless in this table."""
    raw = str(text)
    clipped = raw[:cap] + ("…" if len(raw) > cap else "")
    return f"<code>{render._visible(clipped)}</code>"


def _event_summary(record: dict[str, Any]) -> str:
    """One event, in the words you would use to describe it out loud."""
    kind = record.get("kind", "?")

    if kind in ("request", "response"):
        what = record.get("tool") or record.get("method") or ""
        text = f"<b>{render._visible(str(what))}</b>"
        if kind == "request" and record.get("arguments"):
            text += " " + _mono(json.dumps(record["arguments"], default=str))
        if kind == "response":
            ok = record.get("ok")
            text += (f" <span class='{'ok' if ok else 'bad'}'>"
                     f"{'ok' if ok else 'failed'}</span>")
            if record.get("duration_ms") is not None:
                text += f" <span class='meta'>{record['duration_ms']} ms</span>"
        return text

    if kind == "api_call":
        status = record.get("status")
        good = isinstance(status, int) and status < 400
        return (
            f"{html.escape(str(record.get('method', '')))} "
            f"{_mono(record.get('path', ''), 140)} "
            f"<span class='{'ok' if good else 'bad'}'>{html.escape(str(status))}</span> "
            f"<span class='meta'>{record.get('duration_ms')} ms · "
            f"{record.get('bytes', 0)} B</span>"
            + (" <span class='k-high'>elevated</span>" if record.get("elevated") else "")
        )

    if kind == "error":
        return (
            f"<b>{render._visible(str(record.get('tool') or record.get('method') or ''))}</b> "
            f"<span class='bad'>{html.escape(str(record.get('error_type', '')))}</span> "
            + _mono(record.get("error", ""))
        )

    if kind == "blocked":
        return (
            f"<span class='bad'>{html.escape(str(record.get('reason', 'refused')))}</span> "
            + _mono(record.get("command") or record.get("path") or "")
        )

    if kind in ("elevation_required", "elevation_granted"):
        return _mono(record.get("summary", ""), 260)

    if kind == "approval":
        decision = str(record.get("decision", ""))
        css = "ok" if decision in ("approved", "consumed") else "bad"
        return (f"<span class='{css}'>{html.escape(decision)}</span> "
                + _mono(record.get("detail", ""), 260))

    if kind == "mutation":
        return (
            f"{html.escape(str(record.get('method', '')))} "
            f"{_mono(record.get('path', ''), 140)} "
            f"&rarr; {html.escape(str(record.get('outcome', '')))}"
        )

    if kind == "approval_login":
        ok = record.get("ok")
        return (f"<span class='{'ok' if ok else 'bad'}'>"
                f"{'signed in' if ok else 'rejected'}</span> "
                f"<span class='meta'>from "
                f"{html.escape(str(record.get('client', 'unknown')))}</span>")

    if kind in ("startup", "startup_warning"):
        return _mono(record.get("detail") or record.get("message")
                     or json.dumps({k: v for k, v in record.items()
                                    if k not in ("ts", "kind", "epoch", "pid")},
                                   default=str), 260)

    rest = {k: v for k, v in record.items()
            if k not in ("ts", "kind", "epoch", "pid", "mode")}
    return _mono(json.dumps(rest, default=str), 260)


def _event_row(record: dict[str, Any], today: str) -> str:
    kind = record.get("kind", "?")
    stamp = str(record.get("ts", ""))
    date, _, clock = stamp.partition("T")
    when = clock or stamp
    if date and date != today:
        when = f"{date[5:]} {clock}"
    return (
        "<tr>"
        f"<td class='t'>{html.escape(when)}</td>"
        f"<td class='k'><span class='kind {KIND_CLASS.get(kind, 'k-dim')}'>"
        f"{html.escape(kind)}</span></td>"
        f"<td class='d'>{_event_summary(record)}</td>"
        "</tr>"
    )


async def history(request: Request):
    if not _authed(request):
        return _login_page()

    params = request.query_params
    group = params.get("show", "all")
    if group not in LOG_GROUPS:
        group = "all"
    query = (params.get("q") or "").strip()
    try:
        limit = max(10, min(1000, int(params.get("n", "100"))))
    except (TypeError, ValueError):
        limit = 100

    events, scanned = _load_events(LOG_GROUPS[group], query, limit)
    events.reverse()
    today = time.strftime("%Y-%m-%d")

    chips = "".join(
        f"<a class='btn{' on' if key == group else ''}' "
        f"href='history?show={key}&n={limit}"
        + (f"&q={html.escape(query, quote=True)}" if query else "")
        + f"'>{html.escape(LOG_LABELS[key])}</a>"
        for key in LOG_GROUPS
    )

    parts = [
        "<h1>Activity</h1>",
        "<p class='meta'>What this server has actually done. Same record the "
        "<code>trmm-mcp-logs</code> command reads.</p>",
        f"<p class='nav'><a class='btn' href='.'>&larr; Back to approvals</a>"
        f"<a class='btn' href='commands'>Commands run</a>"
        f"<a class='btn' href='history?show={group}&n={limit}"
        + (f"&q={html.escape(query, quote=True)}" if query else "")
        + "'>Refresh</a></p>",
        f"<h2>Filter</h2><p class='nav'>{chips}</p>",
        "<form method='get' action='history' class='nav'>"
        f"<input type='hidden' name='show' value='{html.escape(group, quote=True)}'>"
        f"<input type='hidden' name='n' value='{limit}'>"
        f"<input type='text' name='q' placeholder='search text' "
        f"value='{html.escape(query, quote=True)}'>"
        "<button>Search</button></form>",
    ]

    if not events:
        where = config.LOG_DIR / "events.jsonl"
        parts.append(
            "<p class='empty'>Nothing matches"
            + (" that search." if query or group != "all" else
               f" yet — no events recorded in {html.escape(str(where))}.")
            + "</p>"
        )
    else:
        rows = "".join(_event_row(record, today) for record in events)
        parts.append(
            "<table class='log'><thead><tr><th>Time</th><th>Kind</th>"
            f"<th>What happened</th></tr></thead><tbody>{rows}</tbody></table>"
        )
        note = f"Showing the {len(events)} most recent"
        if scanned >= SCAN_LINES:
            note += (f", found within the last {scanned:,} log lines — older "
                     "entries are not searched here")
        parts.append(f"<p class='meta'>{note}.</p>")

        wider = [n for n in (100, 250, 500, 1000) if n > limit]
        if wider:
            more = "".join(
                f"<a class='btn' href='history?show={group}&n={n}"
                + (f"&q={html.escape(query, quote=True)}" if query else "")
                + f"'>Show {n}</a>"
                for n in wider
            )
            parts.append(f"<p class='nav'>{more}</p>")

    return _page("TRMM MCP activity", "".join(parts))


# --- commands run -----------------------------------------------------------
#
# The activity log is everything; this is the question people actually ask -
# "what has been run on my machines, and what came back". One card per
# execution attempt, correlated request-to-response, with the verbatim command
# and its output. Attempts that were refused are shown too: knowing what was
# asked for and denied is as much of the record as what ran.

EXEC_TOOLS = (
    "trmm_run_command", "trmm_run_script", "trmm_run_task", "trmm_run_checks",
    "trmm_reboot_agent", "trmm_service_action", "trmm_kill_process",
    "trmm_wake_on_lan",
)

# Kept in step with _SHELL_NAMES in server.py. Duplicated rather than imported
# because server.py imports this module.
SHELL_NAMES = {
    "cmd": "Command Prompt", "powershell": "PowerShell", "shell": "shell",
    "python": "Python", "nushell": "Nushell", "deno": "Deno",
}

STATUS_LABEL = {
    "ran": ("RAN", "st-ran"),
    "failed": ("FAILED", "st-failed"),
    "refused": ("NEEDED APPROVAL — DID NOT RUN", "st-refused"),
    "blocked": ("BLOCKED BY A GUARD", "st-blocked"),
    "unknown": ("NO RESULT RECORDED", "st-unknown"),
}

COMMAND_FILTERS = {
    "all": "Everything",
    "ran": "Actually ran",
    "failed": "Failed",
    "refused": "Refused",
    "blocked": "Blocked",
}


def _args_of(record: dict[str, Any]) -> dict[str, Any]:
    """Arguments are logged as a JSON string; older records may be a dict."""
    raw = record.get("arguments")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _describe(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Say what was asked for, in the same words the approval page uses."""
    target = str(args.get("agent") or args.get("agent_id") or "unknown machine")

    if tool == "trmm_run_command":
        shell = str(args.get("shell", "cmd"))
        return {
            "action": f"Run a {SHELL_NAMES.get(shell, shell)} command",
            "target": target,
            "code": str(args.get("command", "")),
            "facts": [
                ["Shell", SHELL_NAMES.get(shell, shell)],
                ["Runs as", "the logged-in user" if args.get("run_as_user")
                            else "SYSTEM (full privileges)"],
                ["Timeout", f"{args.get('timeout', '?')} seconds"],
            ],
        }
    if tool == "trmm_run_script":
        facts = [["Script", str(args.get("script_id", "?"))]]
        if args.get("args"):
            facts.append(["Arguments", json.dumps(args["args"], default=str)])
        if args.get("timeout"):
            facts.append(["Timeout", f"{args['timeout']} seconds"])
        return {"action": "Run a saved script", "target": target, "facts": facts}
    if tool == "trmm_reboot_agent":
        return {"action": "Reboot the machine immediately", "target": target,
                "facts": [["Effect", "Restarts now, without warning the user"]]}
    if tool == "trmm_service_action":
        action = str(args.get("action", "change"))
        return {"action": f"{action.capitalize()} a Windows service",
                "target": target,
                "facts": [["Service", str(args.get("service_name", "?"))]]}
    if tool == "trmm_kill_process":
        return {"action": "Force-kill a running process", "target": target,
                "facts": [["Process ID", str(args.get("pid", "?"))]]}
    if tool == "trmm_wake_on_lan":
        return {"action": "Send a wake-on-LAN packet", "target": target, "facts": []}
    if tool == "trmm_run_checks":
        return {"action": "Run all checks now", "target": target, "facts": []}
    if tool == "trmm_run_task":
        return {"action": "Run an automated task", "target": target,
                "facts": [["Task", str(args.get("task_id", "?"))]]}
    return {"action": tool, "target": target,
            "facts": [[k, json.dumps(v, default=str)[:120]]
                      for k, v in args.items()]}


def _outcome(response: dict[str, Any] | None) -> tuple[str, str, str]:
    """(status, output, error) - what happened, and what came back."""
    if response is None:
        return "unknown", "", ""
    result = response.get("result")
    text = result if isinstance(result, str) else json.dumps(result, default=str)

    if response.get("ok"):
        # A successful run returns a JSON document; the interesting bit is
        # whatever the machine printed.
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return "ran", str(text or ""), ""
        if isinstance(parsed, dict):
            for key in ("output", "result", "detail", "status"):
                if key in parsed:
                    return "ran", str(parsed[key]), ""
            return "ran", json.dumps(parsed, indent=2, default=str), ""
        return "ran", str(parsed), ""

    lowered = (text or "").lower()
    if "approval required" in lowered:
        return "refused", "", str(text or "")
    if "blocked" in lowered or "refuses" in lowered or "not permitted" in lowered:
        return "blocked", "", str(text or "")
    return "failed", "", str(text or "")


def _pair_commands(limit: int, status: str, query: str):
    """Walk the log once, matching each execution response to its request."""
    lines = _tail_lines(config.LOG_DIR / "events.jsonl", SCAN_LINES)
    open_requests: dict[tuple[Any, Any], dict[str, Any]] = {}
    found: list[dict[str, Any]] = []
    needle = query.lower()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        tool = record.get("tool")
        if tool not in EXEC_TOOLS:
            continue
        # request_id restarts from 1 each session, so it is only unique per pid.
        key = (record.get("pid"), record.get("request_id"))
        if record.get("kind") == "request":
            open_requests[key] = record
        elif record.get("kind") == "response":
            request = open_requests.pop(key, None)
            if request is None:
                continue
            found.append(_entry(request, record))

    for request in open_requests.values():  # asked, never answered
        found.append(_entry(request, None))

    found.sort(key=lambda entry: entry["epoch"])

    if status != "all":
        found = [e for e in found if e["status"] == status]
    if needle:
        found = [
            e for e in found
            if needle in e["code"].lower()
            or needle in e["target"].lower()
            or needle in e["action"].lower()
            or needle in e["output"].lower()
        ]
    return found[-limit:], len(lines)


def _entry(request: dict[str, Any], response: dict[str, Any] | None):
    tool = str(request.get("tool", ""))
    args = _args_of(request)
    described = _describe(tool, args)
    status, output, error = _outcome(response)
    return {
        "tool": tool,
        "ts": str(request.get("ts", "")),
        "epoch": float(request.get("epoch") or 0),
        "action": str(described["action"]),
        "target": str(described["target"]),
        "code": str(described.get("code") or ""),
        "facts": described.get("facts") or [],
        "status": status,
        "output": output or "",
        "error": error or "",
        "duration_ms": (response or {}).get("duration_ms"),
    }


def _command_card(entry: dict[str, Any]) -> str:
    label, css = STATUS_LABEL.get(entry["status"], STATUS_LABEL["unknown"])
    date, _, clock = entry["ts"].partition("T")

    head = [
        f"<div class='cmd {css}'><div class='cmd-top'>",
        f"<span class='st {css}'>{html.escape(label)}</span>",
        f"<p class='title'>{html.escape(entry['action'])}</p>",
        f"<p class='target'>on <b>{render._visible(entry['target'])}</b></p>",
    ]
    meta = f"{date} at {clock}" if date else entry["ts"]
    if entry["duration_ms"] is not None:
        meta += f" \u00b7 took {entry['duration_ms']} ms"
    head.append(f"<p class='when'>{html.escape(meta)}</p></div>")

    body = []
    if entry["code"]:
        body.append(render.code_block(entry["code"], "Command"))
    if entry["facts"]:
        body.append("<div class='cmd-facts'>"
                    + render.facts_table(entry["facts"]) + "</div>")
    if entry["output"].strip():
        shown = entry["output"]
        clipped = len(shown) > 4000
        if clipped:
            shown = shown[:4000]
        body.append(render.code_block(shown.rstrip(), "What the machine returned"))
        if clipped:
            body.append("<p class='hint'>Output truncated for display.</p>")
    elif entry["status"] == "ran":
        body.append("<p class='hint'>Ran successfully and returned no output.</p>")
    if entry["error"]:
        first = entry["error"].strip().splitlines()[0][:200]
        body.append(f"<p class='hint'>{render._visible(first)}</p>")

    return "".join(head) + "".join(body) + "</div>"


async def commands(request: Request):
    if not _authed(request):
        return _login_page()

    params = request.query_params
    status = params.get("show", "all")
    if status not in COMMAND_FILTERS:
        status = "all"
    query = (params.get("q") or "").strip()
    try:
        limit = max(5, min(500, int(params.get("n", "25"))))
    except (TypeError, ValueError):
        limit = 25

    entries, scanned = _pair_commands(limit, status, query)
    entries.reverse()

    def link(key: str, count: int) -> str:
        tail = f"&q={html.escape(query, quote=True)}" if query else ""
        return f"commands?show={key}&n={count}{tail}"

    chips = "".join(
        f"<a class='btn{' on' if key == status else ''}' href='{link(key, limit)}'>"
        f"{html.escape(name)}</a>"
        for key, name in COMMAND_FILTERS.items()
    )

    parts = [
        "<h1>Commands run</h1>",
        "<p class='meta'>Every execution this server was asked to perform, what "
        "was asked for verbatim, and what came back. Refused attempts are kept "
        "too.</p>",
        f"<p class='nav'><a class='btn' href='.'>&larr; Back to approvals</a>"
        f"<a class='btn' href='history'>Full activity log</a>"
        f"<a class='btn' href='{link(status, limit)}'>Refresh</a></p>",
        f"<h2>Filter</h2><p class='nav'>{chips}</p>",
        "<form method='get' action='commands' class='nav'>"
        f"<input type='hidden' name='show' value='{html.escape(status, quote=True)}'>"
        f"<input type='hidden' name='n' value='{limit}'>"
        "<input type='text' name='q' placeholder='search command, machine or output' "
        f"value='{html.escape(query, quote=True)}'>"
        "<button>Search</button></form>",
    ]

    if not entries:
        parts.append(
            "<p class='empty'>"
            + ("Nothing matches that search." if query or status != "all"
               else "No commands have been run through this server yet.")
            + "</p>"
        )
    else:
        parts.extend(_command_card(entry) for entry in entries)
        note = f"Showing the {len(entries)} most recent"
        if scanned >= SCAN_LINES:
            note += (f", found within the last {scanned:,} log lines — older "
                     "runs are not searched here")
        parts.append(f"<p class='meta'>{note}.</p>")

        wider = [n for n in (25, 50, 100, 250, 500) if n > limit]
        if wider:
            parts.append(
                "<p class='nav'>"
                + "".join(f"<a class='btn' href='{link(status, n)}'>Show {n}</a>"
                          for n in wider)
                + "</p>"
            )

    return _page("TRMM MCP commands", "".join(parts))
