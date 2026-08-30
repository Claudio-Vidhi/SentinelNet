# -*- coding: utf-8 -*-
"""Accessibility coverage report for templates/dashboard.html (plan item 14).

Checks the two things that were structurally missing and that a human review
cannot count reliably by hand:

  1. every form control has an accessible name (a <label for>, a wrapping
     <label>, or an aria-label);
  2. the sidenav declares tablist/tab/tabpanel semantics.

The dialog semantics and the focus trap live in static/js/ui-modal.js and are
covered by tests/test_ui_modal.py: they are applied at runtime, so they cannot
be counted in the template.

Usage:  uv run python scripts/check_a11y.py [--strict]
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "templates" / "dashboard.html"

CONTROL_RE = re.compile(r"<(input|select|textarea)\b[^>]*>", re.I)
LABEL_FOR_RE = re.compile(r'<label[^>]*\bfor="([^"]+)"')
# Controls that carry their name in their own text or need none.
EXEMPT_TYPES = re.compile(r'type="(hidden|submit|button)"')


def unnamed_controls(html: str):
    labelled = set(LABEL_FOR_RE.findall(html))
    # HTML comments are prose about the markup, not markup.
    html_wo_comments = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    out = []
    for m in CONTROL_RE.finditer(html_wo_comments):
        tag = m.group(0)
        if EXEMPT_TYPES.search(tag) or "aria-label" in tag:
            continue
        # A control deliberately hidden from assistive tech (a mirror of a
        # visible chip selector) must NOT get a name: naming it puts it back
        # in the reading order it was removed from.
        if 'aria-hidden="true"' in tag:
            continue
        cid = re.search(r'\bid="([^"]+)"', tag)
        if cid and cid.group(1) in labelled:
            continue
        # wrapped in a <label> (implicit association)
        opened = html_wo_comments.rfind("<label", 0, m.start())
        closed = html_wo_comments.rfind("</label>", 0, m.start())
        if opened > closed:
            continue
        out.append(cid.group(1) if cid else tag[:70])
    return out


def missing_tablist(html: str):
    missing = []
    if 'role="tablist"' not in html:
        missing.append('la sidenav non dichiara role="tablist"')
    tabs = html.count('role="tab"')
    panels = html.count('role="tabpanel"')
    selected = html.count("aria-selected")
    if not tabs:
        missing.append('nessuna voce di nav con role="tab"')
    if not panels:
        missing.append('nessun pannello con role="tabpanel"')
    if tabs and selected < tabs:
        missing.append("aria-selected assente su %d voci" % (tabs - selected))
    return missing


def main(argv) -> int:
    html = DASHBOARD.read_text(encoding="utf-8")
    unnamed = unnamed_controls(html)
    tablist = missing_tablist(html)

    total = len(CONTROL_RE.findall(html))
    print("Controlli di form: %d" % total)
    print("Senza nome accessibile: %d" % len(unnamed))
    print("Semantica tablist: %s" % ("ok" if not tablist else "; ".join(tablist)))
    if unnamed:
        print("\nControlli da etichettare:")
        for c in unnamed:
            print("  - %s" % c)
        print("\nUn controllo senza nome e' muto per uno screen reader: "
              "aggiungere <label for> oppure aria-label + data-i18n-aria-label.")

    if "--strict" in argv and (unnamed or tablist):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
