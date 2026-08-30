# -*- coding: utf-8 -*-
"""i18n coverage report for static/js (plan Phase 3 item 13).

Bilingual copy is mandatory (CONTRIBUTING §1), but three mechanisms coexist:
the i18n.js dictionary, JS lookups, and inline `currentLang === 'en' ? ...`
ternaries — plus modules with hardcoded Italian only. With that mix the EN
coverage is structurally unknowable without tooling; this script is the
tooling. Report-only by default; --strict exits 1 for CI-style gating.

Usage:  uv run python scripts/check_i18n_coverage.py [--strict]
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS_DIR = ROOT / "static" / "js"

# The dictionary itself is exempt: it IS the translation store.
EXEMPT = {"i18n.js"}

# Only a ternary that carries a STRING is a missing translation: the ones
# picking between two fields of a metadata object (m.en / m.it) are the
# dictionary done differently, not copy hidden in the code.
TERNARY_RE = re.compile(r"""currentLang\s*===\s*'en'\s*\?\s*[`'"(]""")
# Same thing written through the local flag (const en = currentLang === 'en'):
# it hid 204 ternaries from the first version of this report, which is exactly
# how a monolingual string survives a coverage check.
FLAG_TERNARY_RE = re.compile(r"(?<![\w.])en\s*\?\s*[`'\"]")
FLAG_DECL_RE = re.compile(r"const\s+en\s*=\s*currentLang\s*===\s*'en'")
# alert()/confirm() with Italian text: accented vowels or frequent Italian
# UI words. Line-bounded on purpose (no DOTALL) so one alert cannot drag in
# the whole file. Heuristic on purpose — a false positive costs a look, a
# missed string costs a monolingual tab in production.
ITALIAN_RE = re.compile(
    r"\b(?:alert|confirm)\s*\(\s*[`'\"`][^`'\"\n]*?"
    r"(?:[àèéìòù]|[Ee]rrore|[Ii]mpossibile|salvat[oa]|eliminazione|"
    r"[Aa]ttenzione|[Cc]onferma|[Nn]essun[oa]|[Oo]perazione|riuscit[oa])"
)


def scan_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    flag = len(FLAG_TERNARY_RE.findall(text)) if FLAG_DECL_RE.search(text) else 0
    return {
        "ternaries": len(TERNARY_RE.findall(text)) + flag,
        "italian_alerts": len(ITALIAN_RE.findall(text)),
    }


def main(argv) -> int:
    strict = "--strict" in argv
    if not JS_DIR.is_dir():
        print(f"static/js non trovata sotto {ROOT}")
        return 1

    total_ternaries = 0
    total_italian = 0
    offenders = []
    for path in sorted(JS_DIR.glob("*.js")):
        if path.name in EXEMPT:
            continue
        counts = scan_file(path)
        total_ternaries += counts["ternaries"]
        total_italian += counts["italian_alerts"]
        if counts["ternaries"] or counts["italian_alerts"]:
            offenders.append((path.name, counts))

    print(f"File scansionati: {len(list(JS_DIR.glob('*.js'))) - len(EXEMPT)}")
    print(f"Ternarie inline 'currentLang === en ?': {total_ternaries}")
    print(f"alert/confirm con testo italiano hardcoded: {total_italian}")
    if offenders:
        print("\nPer file:")
        for name, counts in offenders:
            print(f"  {name}: ternarie={counts['ternaries']} "
                  f"italian_alert={counts['italian_alerts']}")
        print("\nObiettivo: zero ternarie inline e zero alert hardcoded — "
              "ogni stringa passa dal dizionario i18n.js (it + en).")
    else:
        print("Copertura completa: nessuna stringa fuori dal dizionario.")

    if strict and offenders:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
