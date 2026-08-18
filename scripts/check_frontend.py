# -*- coding: utf-8 -*-
"""Type check di static/js con tsc, filtrando il rumore strutturale.

TypeScript in modalita' checkJs applica al DOM tipi piu' stretti di quelli che
il JS non annotato puo' soddisfare: getElementById() restituisce HTMLElement e
non HTMLInputElement, quindi ogni `.value` diventa un errore; e.target e'
EventTarget, quindi ogni `.closest()` lo diventa. Sono ~900 segnalazioni che
non corrispondono ad alcun difetto e che, lasciate passare, renderebbero il
controllo illeggibile e quindi inutile.

Tutto il resto passa: nomi non dichiarati, proprieta' inesistenti su window
(la classe di bug che teneva window.globalDevices sempre undefined), chiavi
duplicate negli object literal, tipi di argomento incompatibili.

Uso:  uv run python scripts/check_frontend.py
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Righe attese e prive di valore diagnostico: sottotipi del DOM che il JS non
# annotato non puo' esprimere. NON aggiungere qui pattern che nascondono
# 'Window & typeof globalThis': e' il caso che vogliamo continuare a vedere.
BENIGN = (
    re.compile(r"does not exist on type '(HTMLElement|Element|EventTarget|HTMLElement \| \{\})'"),
    re.compile(r"'EventTarget' is not assignable to parameter of type 'Node'"),
)


def main() -> int:
    tsc = ROOT / "node_modules" / "typescript" / "bin" / "tsc"
    if not tsc.exists():
        print("typescript non installato: esegui `npm install` nella radice del progetto.")
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
        print("\n%d problemi reali (%d segnalazioni DOM filtrate)." % (len(real), suppressed))
        return 1

    print("Frontend type check: nessun problema (%d segnalazioni DOM filtrate)." % suppressed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
