# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rendering helpers for the approval page.

Two jobs, both about not misleading the person clicking Approve:

1. Turn a request into something readable in about two seconds - what will
   happen, to which machine, and how bad it is if it is wrong.
2. Present the verbatim command so it cannot be mistaken for the page's own
   interface, and point out characters that do not look like what they are.

A command string is attacker-controlled in the meaningful sense: it can come
from a model that has been reading event logs and software inventories off a
possibly-compromised machine. Escaping stops it becoming markup; the framing
here stops it *impersonating* markup.
"""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Any

# Word-shapes are deliberately different lengths and letter patterns, so the
# tiers stay distinguishable in greyscale and for a colour-blind reader.
SEVERITY = {
    "destructive": ("CANNOT BE UNDONE", "sev-high"),
    "disruptive": ("CHANGES THIS MACHINE", "sev-mid"),
    "routine": ("LOW IMPACT", "sev-low"),
}
SEVERITY_UNKNOWN = ("NOT CLASSIFIED", "sev-unknown")

ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿"}

# Bidirectional controls reorder how text *displays* without changing what
# executes, so a command can be made to read as something harmless. These are
# far above the C0 range, so an "ord(c) < 32" check never sees them.
BIDI = (
    set(range(0x202A, 0x202F))   # LRE RLE PDF LRO RLO
    | set(range(0x2066, 0x206A))  # LRI RLI FSI PDI
    | {0x200E, 0x200F, 0x061C}    # LRM RLM ALM
)


def _is_format(char: str) -> bool:
    """Unicode 'format' characters: invisible, but part of the command."""
    return unicodedata.category(char) == "Cf"

# Text that would let a command string cosplay as this page's own chrome.
UI_PHRASES = [
    "approve once", "deny", "sign in", "sign out", "revoke every grant",
    "waiting for you", "cannot be undone", "open approval windows",
]


def severity(record: dict[str, Any]) -> tuple[str, str]:
    """Fail closed: anything we cannot classify gets the loudest treatment."""
    display = record.get("display") or {}
    risk = display.get("risk")
    if not display or risk not in SEVERITY:
        return SEVERITY_UNKNOWN
    return SEVERITY[risk]


def _confusables(text: str) -> list[str]:
    """Non-ASCII letters sitting inside otherwise-ASCII words.

    A Cyrillic 'а' in `Get-Servіce` is invisible to a reader and fatal to an
    assumption about what will run.
    """
    found: list[str] = []
    for word in re.findall(r"\S+", text):
        if word.isascii():
            continue
        for char in word:
            if char.isascii() or not char.isalpha():
                continue
            try:
                name = unicodedata.name(char)
            except ValueError:
                name = f"U+{ord(char):04X}"
            note = f"{char!r} ({name}) inside “{word[:40]}”"
            if note not in found:
                found.append(note)
    return found


def scan(text: str) -> list[str]:
    """Human-readable notices about characters that misrepresent themselves."""
    notices: list[str] = []

    controls = sorted({c for c in text if ord(c) < 32 and c not in "\n\t"} |
                      {c for c in text if ord(c) == 127})
    if controls:
        names = ", ".join(f"U+{ord(c):04X}" for c in controls)
        notices.append(
            f"Contains control characters ({names}). They are shown below as "
            f"visible symbols and are not part of what you can see as text."
        )

    bidi = sorted({c for c in text if ord(c) in BIDI})
    if bidi:
        names = ", ".join(f"U+{ord(c):04X}" for c in bidi)
        notices.append(
            f"Contains bidirectional text controls ({names}). These reorder how "
            f"the text is displayed without changing what actually runs, so what "
            f"you read may not be what executes. Treat this command as hostile."
        )

    zeros = sorted({c for c in text if c in ZERO_WIDTH})
    if zeros:
        names = ", ".join(f"U+{ord(c):04X}" for c in zeros)
        notices.append(
            f"Contains zero-width characters ({names}) that take up no space "
            f"on screen but are part of the command."
        )

    other_format = sorted({
        c for c in text
        if _is_format(c) and ord(c) not in BIDI and c not in ZERO_WIDTH
    })
    if other_format:
        names = ", ".join(f"U+{ord(c):04X}" for c in other_format)
        notices.append(
            f"Contains invisible formatting characters ({names}) that are part "
            f"of the command but cannot be seen."
        )

    for note in _confusables(text):
        notices.append(f"Look-alike character: {note}.")

    lowered = text.lower()
    hits = [p for p in UI_PHRASES if p in lowered]
    if hits:
        notices.append(
            "This text imitates wording used by this page itself "
            f"({', '.join(hits)}). It is command text, not part of the interface, "
            "and clicking it does nothing."
        )

    if any(len(line) > 200 for line in text.splitlines() or [text]):
        notices.append("Contains a very long line; scroll it to read it all.")

    return notices


def _visible(text: str) -> str:
    """Escape, then make invisible characters visible.

    Control characters become their Unicode Control Picture, so the reader sees
    a mark rather than nothing at all.
    """
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\t":
            out.append('<span class="ctl" title="tab">␉</span>')
        elif char in ZERO_WIDTH:
            name = f"U+{code:04X}"
            out.append(f'<span class="ctl" title="{name}">␣</span>')
        elif code < 32:
            out.append(
                f'<span class="ctl" title="U+{code:04X}">{chr(0x2400 + code)}</span>'
            )
        elif code == 127:
            out.append('<span class="ctl" title="U+007F">␡</span>')
        elif code in BIDI or _is_format(char):
            # Never let a formatting character reach the browser: it would
            # reorder or hide the very text the operator is checking.
            out.append(f'<span class="ctl" title="U+{code:04X}">⟦{code:04X}⟧</span>')
        else:
            out.append(html.escape(char))
    return "".join(out)


def code_block(text: str, label: str) -> str:
    """The verbatim command, fenced and numbered so it cannot pose as chrome."""
    lines = text.split("\n") or [""]
    rows = "".join(
        f'<div class="ln"><span class="num">{i}</span>'
        f'<span class="src">{_visible(line)}</span></div>'
        for i, line in enumerate(lines, 1)
    )
    chars = len(text)
    count = (
        f"{len(lines)} line{'' if len(lines) == 1 else 's'} · "
        f"{chars} character{'' if chars == 1 else 's'}"
    )
    notices = "".join(
        f'<li>{html.escape(n)}</li>' for n in scan(text)
    )
    notice_block = f'<ul class="notices">{notices}</ul>' if notices else ""

    return (
        f'<div class="evidence">'
        f'<div class="evhead">{html.escape(label)}'
        f'<span class="evtag">exact text · not part of this page</span></div>'
        f'<div class="code">{rows}</div>'
        f'<div class="evfoot">{count}</div>'
        f"{notice_block}"
        f"</div>"
    )


def facts_table(facts: list[Any]) -> str:
    rows = []
    for entry in facts or []:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            continue
        label, value = entry
        rows.append(
            f'<tr><th>{html.escape(str(label))}</th>'
            f'<td>{html.escape(str(value))}</td></tr>'
        )
    return f'<table class="facts">{"".join(rows)}</table>' if rows else ""
