# -*- coding: utf-8 -*-
"""Type check static/js with tsc, filtering out the structural noise.

In checkJs mode TypeScript holds the DOM to types unannotated JS cannot
satisfy: getElementById() returns HTMLElement rather than HTMLInputElement, so
every `.value` is an error; e.target is EventTarget, so every `.closest()` is
one too. That is ~900 reports matching no actual defect, and letting them
through would make the check unreadable and therefore useless.

Everything else gets through: undeclared names, properties that do not exist on
window (the bug class that kept window.globalDevices undefined), duplicate keys
in object literals, incompatible argument types.

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

    print("Frontend type check: clean (%d DOM reports filtered)." % suppressed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
