# -*- coding: utf-8 -*-
"""Ogni tr('chiave') usata dai moduli deve esistere in ENTRAMBE le lingue.

La migrazione dalle ternarie inline ha spostato ~700 stringhe nel dizionario:
senza questo controllo una chiave sbagliata non fallisce da nessuna parte,
tr() ricade sull'italiano (o restituisce la chiave) e l'inglese sparisce in
silenzio — esattamente il difetto che la migrazione doveva chiudere.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS_DIR = ROOT / "static" / "js"
I18N = JS_DIR / "i18n.js"

_USE = re.compile(r"""\btr\(\s*['"]([A-Za-z0-9_]+)['"]""")
_ENTRY = re.compile(r"^        (\w+):", re.M)
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def _dicts():
    src = I18N.read_text(encoding="utf-8")
    it_part, en_part = src.split("    en: {", 1)
    return set(_ENTRY.findall(it_part)), set(_ENTRY.findall(en_part))


def _values(part):
    return {m.group(1): m.group(2) for m in
            re.finditer(r"^        (\w+): (.+),\s*$", part, re.M)}


class TestI18nKeys(unittest.TestCase):

    def setUp(self):
        self.it, self.en = _dicts()
        src = I18N.read_text(encoding="utf-8")
        self.it_part, self.en_part = src.split("    en: {", 1)

    def test_every_used_key_exists_in_both_languages(self):
        missing = []
        for path in JS_DIR.glob("*.js"):
            if path.name == "i18n.js":
                continue
            for key in sorted(set(_USE.findall(path.read_text(encoding="utf-8")))):
                if key not in self.it:
                    missing.append(f"{path.name}: {key} manca in 'it'")
                if key not in self.en:
                    missing.append(f"{path.name}: {key} manca in 'en'")
        self.assertEqual(missing, [])

    def test_english_covers_every_italian_key(self):
        self.assertEqual(sorted(self.it - self.en), [],
                         "chiavi senza traduzione inglese")

    def test_placeholders_match_between_languages(self):
        it_vals, en_vals = _values(self.it_part), _values(self.en_part)
        bad = [k for k, v in it_vals.items()
               if k in en_vals
               and set(_PLACEHOLDER.findall(v)) != set(_PLACEHOLDER.findall(en_vals[k]))]
        self.assertEqual(bad, [], "segnaposto {x} diversi fra le due lingue")


class TestNoStringsOutsideTheDictionary(unittest.TestCase):
    """Il report di copertura e' a zero: da qui in avanti e' un cancello.

    Rimetterci una ternaria inline o un alert solo italiano fa fallire questo
    test invece di far sparire l'inglese in silenzio."""

    def test_coverage_report_is_clean(self):
        import subprocess
        import sys
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_i18n_coverage.py"), "--strict"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
