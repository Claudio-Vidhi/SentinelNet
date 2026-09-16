# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Ogni sorgente tracciato porta l'header di copyright.

AGPL-3.0 5(a) e i termini aggiuntivi 7(b)/7(c) in NOTICE obbligano chi
redistribuisce o modifica a conservare le note di copyright presenti nei file.
Un file che non ne ha una non da' niente da conservare: e' esattamente il varco
da cui l'attribuzione sparisce a valle.

L'header e' una policy, e una policy senza un controllo decade al primo file
nuovo. Questo test e' quel controllo.
"""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPDX = "SPDX-License-Identifier: AGPL-3.0-only"
HOLDER = "Claudio Vidhi"
COPYRIGHT = f"Copyright 2026 {HOLDER}"

# Codice di terzi: la sua licenza e la sua attribuzione sono quelle originali,
# sovrascriverle sarebbe la violazione che questo test previene.
EXEMPT_PREFIXES = ("static/vendor/",)


def tracked_sources():
    out = subprocess.run(
        ["git", "ls-files", "*.py", "*.js"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()
    for rel in out:
        if rel.startswith(EXEMPT_PREFIXES):
            continue
        path = ROOT / rel
        # Un __init__.py vuoto non e' opera dell'ingegno: niente da attribuire.
        if not path.read_text(encoding="utf-8", errors="replace").strip():
            continue
        yield rel, path


class SourcesCarryTheLicenseHeader(unittest.TestCase):
    def test_every_tracked_source_has_the_header(self):
        missing = [
            rel for rel, path in tracked_sources()
            if SPDX not in path.read_text(encoding="utf-8", errors="replace")[:500]
        ]
        self.assertEqual(
            missing, [],
            "Sorgenti senza header di licenza (aggiungi le due righe in testa, "
            "vedi CONTRIBUTING.md 9):\n" + "\n".join(f"  {m}" for m in missing))

    def test_the_header_names_the_copyright_holder(self):
        wrong = [
            rel for rel, path in tracked_sources()
            if COPYRIGHT not in path.read_text(encoding="utf-8", errors="replace")[:500]
        ]
        self.assertEqual(
            wrong, [],
            "Header senza il titolare del copyright:\n"
            + "\n".join(f"  {w}" for w in wrong))


class NoticeIsShipped(unittest.TestCase):
    """NOTICE deve raggiungere chi riceve un artefatto, non solo chi clona."""

    def test_notice_exists_and_names_the_holder(self):
        # NOTICE usa la forma GNU "Copyright (C) 2026", gli header la forma
        # breve: quello che deve combaciare e' il titolare, non la sintassi.
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn(HOLDER, notice)
        self.assertIn("GNU Affero General Public License", notice)

    def test_notice_carries_the_section_7_terms(self):
        # Marchio e attribuzione stanno in piedi solo come termini aggiuntivi
        # 7(e)/7(b): senza questa sezione sono richieste non vincolanti.
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("SECTION 7", notice)

    def test_the_exe_bundles_license_and_notice(self):
        spec = (ROOT / "SentinelNet.spec").read_text(encoding="utf-8")
        for f in ("'LICENSE'", "'NOTICE'", "'THIRD_PARTY_LICENSES.md'", "'LICENSES'"):
            self.assertIn(f, spec, f"{f} non e' nei datas di SentinelNet.spec")

    def test_the_root_license_is_the_agpl(self):
        text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("GNU AFFERO GENERAL PUBLIC LICENSE", text)
        self.assertIn("Version 3, 19 November 2007", text)

    def test_the_apache_text_stays_for_the_bundled_components(self):
        # Diverse dipendenze sono Apache-2.0, e la 4(a) vuole che una copia
        # della licenza viaggi con loro: la LICENSE di root non la e' piu'.
        text = (ROOT / "LICENSES" / "Apache-2.0.txt").read_text(encoding="utf-8")
        self.assertIn("Apache License", text)

    def test_the_image_keeps_the_third_party_licenses(self):
        # `*.md` e' escluso in blocco: senza l'eccezione le licenze dei
        # componenti inclusi non viaggiano con l'immagine che li incorpora.
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn("!THIRD_PARTY_LICENSES.md", dockerignore)


if __name__ == "__main__":
    unittest.main()
