# -*- coding: utf-8 -*-
"""A tab whose controls are bound by a lazily-loaded module must load it.

static/js/core.js injects a module the first time its tab is opened. If the
markup of tab X carries a control that only module M binds, and the map does
not send M to tab X, then opening tab X cold leaves every control on it dead:
getElementById(...)?.addEventListener finds nothing, raises nothing, and the
button silently does nothing.

That is what happened to the Sites tab: its whole CRUD lives in settings.js,
which the map only loaded for the Settings tab.
"""
import pathlib
import re
import unittest
from html.parser import HTMLParser

ROOT = pathlib.Path(__file__).resolve().parents[1]

# A module named in a <script src> in the template is always loaded, so it
# owes no entry in the lazy map.
_SCRIPT_SRC = re.compile(r'<script src="/static/js/([a-z0-9_-]+\.js)"')
_TAB_OPEN = re.compile(r'<div id="(tab-[a-z0-9-]+)"[^>]*class="[^"]*tab-content')
_BOUND_ID = re.compile(
    r"getElementById\(['\"]([A-Za-z0-9_-]+)['\"]\)\s*\??\.\s*addEventListener")


def _lazy_map() -> dict:
    """Parse LAZY_TAB_SCRIPTS out of core.js into {tab_id: [module, ...]}."""
    core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")
    block = core[core.index("const LAZY_TAB_SCRIPTS"):]
    block = block[:block.index("\n};")]
    out = {}
    for tab, body in re.findall(r"'(tab-[a-z0-9-]+)':\s*\[([^\]]*)\]", block):
        out[tab] = re.findall(r"/static/js/([a-z0-9_.-]+\.js)", body)
    return out


class _TabOwnership(HTMLParser):
    """Map every id in the template to the tab-content div that encloses it.

    Nesting has to be tracked for real: a line-based scan attributes every
    modal that follows the last tab to that tab, which invents bugs.
    """

    VOID = {"br", "hr", "img", "input", "link", "meta", "source", "col"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.owner = {}
        self._stack = []          # one entry per open element: the tab it opened, or None
        self._tabs = []           # currently open tab-content ids, innermost last

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        found = attr.get("id")
        opened = None
        if (tag == "div" and found and found.startswith("tab-")
                and "tab-content" in (attr.get("class") or "")):
            opened = found
            self._tabs.append(found)
        if found:
            # A tab div belongs to whatever encloses it, not to itself.
            enclosing = self._tabs[:-1] if opened else self._tabs
            self.owner.setdefault(found, enclosing[-1] if enclosing else None)
        if tag not in self.VOID:
            self._stack.append(opened)

    def handle_startendtag(self, tag, attrs):
        attr = dict(attrs)
        if attr.get("id"):
            self.owner.setdefault(attr["id"], self._tabs[-1] if self._tabs else None)

    def handle_endtag(self, tag):
        if not self._stack:
            return
        opened = self._stack.pop()
        if opened and self._tabs and self._tabs[-1] == opened:
            self._tabs.pop()


def _tab_of_each_id(html: str) -> dict:
    parser = _TabOwnership()
    parser.feed(html)
    return parser.owner


class LazyTabScripts(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
        self.eager = set(_SCRIPT_SRC.findall(self.html))
        self.lazy = _lazy_map()
        self.owner = _tab_of_each_id(self.html)

    def _assert_module_reaches_its_controls(self, module: str):
        source = (ROOT / "static/js" / module).read_text(encoding="utf-8")
        tabs = {self.owner.get(i) for i in _BOUND_ID.findall(source)}
        missing = sorted(t for t in tabs if t and module not in self.lazy.get(t, []))
        self.assertEqual(
            missing, [],
            f"{module} binds controls inside {missing}, but core.js never loads "
            f"it for those tabs: opening one cold leaves its controls dead.")

    def test_every_lazy_module_is_loaded_for_each_tab_whose_controls_it_binds(self):
        for module in sorted({m for mods in self.lazy.values() for m in mods}):
            if module in self.eager:
                continue
            with self.subTest(module=module):
                self._assert_module_reaches_its_controls(module)

    def test_every_per_tab_loader_switchtab_calls_is_reachable_from_that_tab(self):
        """switchTab calls a loader per tab; cold, that is a ReferenceError.

        The other half of the same bug: core.js:871 called loadSites() for
        tab-sites while loadSites lived in a module the map never loaded there.
        """
        core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")
        body = core[core.index("async function switchTab("):]
        body = body[:body.index("\n}")]
        calls = re.findall(
            r"tabId === '(tab-[a-z0-9-]+)'[^\n]*?\b([a-zA-Z_][A-Za-z0-9_]*)\s*\(\)",
            body)
        defined_in = {}
        for js in sorted((ROOT / "static/js").glob("*.js")):
            for name in re.findall(r"(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(",
                                   js.read_text(encoding="utf-8")):
                defined_in.setdefault(name, js.name)

        unreachable = []
        for tab, func in calls:
            module = defined_in.get(func)
            if module is None or module in self.eager or module == "core.js":
                continue
            if module not in self.lazy.get(tab, []):
                unreachable.append(f"{tab} -> {func}() in {module}")
        self.assertEqual(
            unreachable, [],
            "switchTab calls these loaders for tabs whose scripts core.js never "
            f"loads, so opening the tab cold throws a ReferenceError: {unreachable}")


if __name__ == "__main__":
    unittest.main()
