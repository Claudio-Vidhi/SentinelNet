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
import functools
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



_FUNC_DEF = re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", re.M)
_CONST_DEF = re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", re.M)
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def _strip_comments(src: str) -> str:
    """Drop comments before scanning for calls: a function name mentioned in
    prose is not a call site."""
    return _COMMENT.sub("", src)


@functools.lru_cache(maxsize=None)
def _stripped_src(path: pathlib.Path) -> str:
    """Comment-free source of one module, read once per run."""
    return _strip_comments(path.read_text(encoding="utf-8"))


@functools.lru_cache(maxsize=None)
def _defined_in(path: pathlib.Path) -> frozenset:
    """The module's callable surface: its `function f()` declarations.

    Only this form, because only a hoisted top-level function is what a bare
    cross-module call would have resolved to. A local `const f = ...` inside
    some other function is not reachable from outside and must not be counted
    as owned, or every one-letter helper becomes a false positive.
    """
    return frozenset(_FUNC_DEF.findall(path.read_text(encoding="utf-8")))


@functools.lru_cache(maxsize=None)
def _declared_in(path: pathlib.Path) -> frozenset:
    """Every name the file binds itself, `function f()` or `const f = ...`.

    Used only to subtract: a module with its own local `const sevColor = s =>`
    is not calling the same-named function of another module.
    """
    src = path.read_text(encoding="utf-8")
    return frozenset(_FUNC_DEF.findall(src)) | frozenset(_CONST_DEF.findall(src))


_BARE_CALL = re.compile(r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(")
_TYPEOF_GUARD = re.compile(r"typeof\s+([A-Za-z_$][\w$]*)\s*===")


@functools.lru_cache(maxsize=None)
def _call_surface(src: str) -> frozenset:
    """Every name ``src`` calls as a bare identifier, minus the typeof-guarded.

    One pass over the file, not one compiled lookbehind per candidate name
    rescanning the whole file: that form was 26 of the suite's ~80 seconds.
    JS keywords (`if (`, `for (`) match too and are harmless — callers
    intersect this with a set of declared function names.
    """
    return frozenset(_BARE_CALL.findall(src)) - frozenset(_TYPEOF_GUARD.findall(src))


def _bare_calls(src: str, names) -> set:
    """Names in ``names`` that ``src`` calls as bare identifiers.

    window.NAME(...), obj.NAME(...) and window.NAME?.(...) do not count: those
    are undefined rather than a ReferenceError when the module is absent. A
    `typeof NAME === 'function'` guard makes a bare call safe too.
    """
    return set(names) & _call_surface(src)


class CrossModuleCallsMustBeOptional(unittest.TestCase):
    """A function owned by a lazily-loaded module is not there until its tab
    has been opened.

    devices.js called topology.js's updateTopologyMapNodeStatus as a bare
    identifier. On a session that never opened the map tab that is a
    ReferenceError, and it aborted the caller mid-way: a triage that had just
    succeeded got repainted OFFLINE by its own catch block, and the button was
    left spinning forever. Calling through `window.` makes the dependency
    optional, which is what these call sites actually want.
    """

    # core.js is exempt as a caller: it IS the loader, and switchTab awaits
    # loadTabScripts(tabId) before calling that tab's entry point.
    EXEMPT_CALLERS = {"core.js"}

    def test_an_always_loaded_module_never_bare_calls_a_lazy_one(self):
        """A module in a <script src> is live on every tab, so a bare call into
        a lazily-loaded one is unsafe with no further analysis needed."""
        js_dir = ROOT / "static/js"
        template = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
        always_loaded = set(_SCRIPT_SRC.findall(template)) - self.EXEMPT_CALLERS
        lazy_modules = {m for mods in _lazy_map().values() for m in mods}
        offenders = []
        for owner_name in sorted(lazy_modules - always_loaded):
            owner = js_dir / owner_name
            if not owner.exists():
                continue
            owned = _defined_in(owner)
            for caller_name in sorted(always_loaded):
                caller = js_dir / caller_name
                if not caller.exists():
                    continue
                src = _stripped_src(caller)
                for name in sorted(_bare_calls(src, owned - _declared_in(caller))):
                    offenders.append(f"{caller_name} calls {owner_name}:{name}() bare")
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_modules_that_never_share_a_tab_never_bare_call_each_other(self):
        """Two lazy modules that appear together on some tab always load
        together, so a bare call between them is fine. Two that share no tab
        never do, and the call is a ReferenceError until the user happens to
        have visited the other module's tab first — a control that is dead on
        the first click and works on the second.

        That was observability.js jumping from an anomaly row to the incident:
        it called switchTab('tab-incidents') without awaiting it and then used
        incidents.js straight away.
        """
        js_dir = ROOT / "static/js"
        tabs_of = {}
        for tab, mods in _lazy_map().items():
            for m in mods:
                tabs_of.setdefault(m, set()).add(tab)
        offenders = []
        for caller_name, caller_tabs in sorted(tabs_of.items()):
            caller = js_dir / caller_name
            if not caller.exists() or caller_name in self.EXEMPT_CALLERS:
                continue
            src = _stripped_src(caller)
            local = _declared_in(caller)
            for owner_name, owner_tabs in sorted(tabs_of.items()):
                owner = js_dir / owner_name
                if owner_name == caller_name or (caller_tabs & owner_tabs) or not owner.exists():
                    continue
                for name in sorted(_bare_calls(src, _defined_in(owner) - local)):
                    offenders.append(f"{caller_name} calls {owner_name}:{name}() bare")
        self.assertEqual(offenders, [], "\n".join(offenders))

if __name__ == "__main__":
    unittest.main()
