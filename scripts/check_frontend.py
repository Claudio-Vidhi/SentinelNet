# -*- coding: utf-8 -*-
"""Type check static/js with tsc, filtering out the structural noise, and
refuse a function declared twice in the shared global scope.

In checkJs mode TypeScript holds the DOM to types unannotated JS cannot
satisfy: getElementById() returns HTMLElement rather than HTMLInputElement, so
every `.value` is an error; e.target is EventTarget, so every `.closest()` is
one too. That is ~900 reports matching no actual defect, and letting them
through would make the check unreadable and therefore useless.

Everything else gets through: undeclared names, properties that do not exist on
window (the bug class that kept window.globalDevices undefined), duplicate keys
in object literals, incompatible argument types.

tsc does NOT flag a top-level `function f()` declared twice -- in a classic
script that is legal, and the last declaration silently wins. It cost us a
shipped fix: expandIface() was improved in one place while the older, narrower
copy further down the file kept overriding it, so the browser ran the version
the commit had just replaced. check_redeclarations() below is that check.

Usage:  uv run python scripts/check_frontend.py
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Expected lines with no diagnostic value: DOM subtypes unannotated JS cannot
# express. Do NOT add patterns here that would hide
# 'Window & typeof globalThis': that is the case worth keeping visible.
BENIGN = (
    re.compile(r"does not exist on type '(HTMLElement|Element|EventTarget|HTMLElement \| \{\})'"),
    re.compile(r"'EventTarget' is not assignable to parameter of type 'Node'"),
)


# `function name(` at column 0 -- the only form that lands in the shared global
# scope. Methods, nested functions and `const f = () =>` are all scoped, so a
# repeated name there is not a redeclaration.
TOP_LEVEL_FUNC = re.compile(r"^function\s+([A-Za-z_$][\w$]*)\s*\(", re.M)


def check_redeclarations() -> int:
    """Reports every function declared at top level in more than one place.

    The modules are loaded as classic scripts into one global scope, so this
    holds across files as well as within one: two files declaring the same name
    means whichever <script> tag comes last defines the behaviour.
    """
    seen: dict[str, list[str]] = {}
    for path in sorted((ROOT / "static" / "js").glob("*.js")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in TOP_LEVEL_FUNC.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            seen.setdefault(match.group(1), []).append(
                "static/js/%s:%d" % (path.name, line))

    clashes = {name: spots for name, spots in seen.items() if len(spots) > 1}
    for name in sorted(clashes):
        print("redeclared in the shared global scope: %s() at %s"
              % (name, ", ".join(clashes[name])))
    if clashes:
        print("\n%d redeclared function(s): the last declaration wins and the "
              "others are dead code." % len(clashes))
    return 1 if clashes else 0


def main() -> int:
    tsc = ROOT / "node_modules" / "typescript" / "bin" / "tsc"
    if not tsc.exists():
        print("typescript not installed: run `npm install` in the project root.")
        return 1

    proc = subprocess.run(
        ["node", str(tsc), "-p", str(ROOT / "tsconfig.json")],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    lines = [l for l in (proc.stdout + proc.stderr).splitlines() if "error TS" in l]

    real = [l for l in lines if not any(p.search(l) for p in BENIGN)]
    suppressed = len(lines) - len(real)

    if real:
        print("\n".join(real))
        print("\n%d real problems (%d DOM reports filtered)." % (len(real), suppressed))
        return 1

    if check_redeclarations():
        return 1

    print("Frontend type check: clean (%d DOM reports filtered)." % suppressed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
