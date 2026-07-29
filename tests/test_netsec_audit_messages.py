# -*- coding: utf-8 -*-
"""Test del catalogo messaggi e della guida del motore di audit.

Il motore produce CHIAVI, non frasi: la traduzione avviene al confine. Questo
sposta due difetti dal tempo di scrittura al tempo di esecuzione — una chiave
scritta male e un segnaposto che non esiste nella lingua tradotta — e nessuno
dei due si nota guardando il codice. Da qui i controlli:

  - ogni chiave citata nel codice delle regole esiste nel catalogo (scansione
    statica dei sorgenti: copre anche le varianti che nessuna fixture innesca);
  - ogni voce ha entrambe le lingue e gli STESSI segnaposto;
  - nessun audit reale, in nessuna lingua, lascia trapelare una chiave grezza o
    una graffa non sostituita nel testo mostrato all'utente.
"""

import os
import re
import unittest

from services import netsec_audit
from services.netsec_audit import guidance, ios_rules, messages, rules
from services.netsec_audit.messages import LANGS, MESSAGES, render

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SERVICE_DIR = os.path.dirname(os.path.abspath(rules.__file__))

# Chiave di catalogo citata come stringa letterale, es. "fos.dns.no_section".
_KEY_LITERAL = re.compile(r'"((?:fos|ios|ev|engine)\.[a-z0-9_.]+)"')
_PLACEHOLDER = re.compile(r"\{(\w+)\}")
# Una frase resa che invece e' rimasta una chiave: nessuno spazio, un punto in
# mezzo, tutta minuscola.
_LOOKS_LIKE_KEY = re.compile(r"^[a-z0-9_]+(?:\.[a-z0-9_]+)+$")

FIXTURE_FILES = ("fortigate_clean.conf", "fortigate_violations.conf",
                 "fortigate_partial.conf", "ios_clean.conf",
                 "ios_violations.conf")


def _fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


def _keys_cited_in_source():
    """Chiavi citate come letterali nei moduli delle regole.

    Statica di proposito: le fixture non innescano ogni singola variante di
    ogni regola, e una chiave sbagliata su un ramo raro non verrebbe mai
    eseguita in test.
    """
    found = set()
    for module in (rules, ios_rules):
        path = os.path.abspath(module.__file__)
        with open(path, encoding="utf-8") as fh:
            found.update(_KEY_LITERAL.findall(fh.read()))
    return found


def _flag_prefixes():
    """Prefissi passati a ``rules._flag``, che ne compone quattro varianti."""
    with open(os.path.abspath(rules.__file__), encoding="utf-8") as fh:
        return set(re.findall(r'_flag\(.*?"(fos\.[a-z0-9_]+)"', fh.read(),
                              re.S))


def _variants(prefix):
    """Chiavi di catalogo che ``prefix`` compone a runtime, es. ``fos.cdp.ok``."""
    head = prefix + "."
    return {k for k in MESSAGES if k.startswith(head)}


def _all_rendered_texts():
    """(contesto, testo) di ogni frase prodotta su tutte le fixture e lingue."""
    out = []
    for name in FIXTURE_FILES:
        text = _fixture(name)
        for bench in ("cis", "nist", "pci"):
            for lang in LANGS:
                res = netsec_audit.run_netsec_audit(
                    config_text=text, benchmark=bench, lang=lang)
                for r in res["rules"]:
                    where = "%s/%s/%s/%s" % (name, bench, lang, r["id"])
                    out.append((where + " detail", r["detail"]))
                    out.append((where + " title", r["title"]))
                    for field, value in (r["guidance"] or {}).items():
                        out.append((where + " guidance." + field, value))
                    for e in r["evidence"]:
                        out.append((where + " evidence", e["text"]))
    return out


class TestCatalogIntegrity(unittest.TestCase):
    def test_every_entry_has_every_language(self):
        for key, entry in MESSAGES.items():
            for lang in LANGS:
                self.assertIn(lang, entry, key)
                self.assertTrue(entry[lang].strip(), "%s/%s vuoto" % (key, lang))

    def test_placeholders_match_across_languages(self):
        """Un segnaposto presente solo in una lingua produce, nell'altra, una
        frase che tace il numero di cui parla."""
        for key, entry in MESSAGES.items():
            sets = {lang: set(_PLACEHOLDER.findall(entry[lang]))
                    for lang in LANGS}
            first = sets[LANGS[0]]
            for lang in LANGS[1:]:
                self.assertEqual(first, sets[lang],
                                 "%s: segnaposto divergenti %s" % (key, sets))

    def test_every_key_cited_in_the_rules_exists(self):
        """Alcuni controlli condividono un helper e citano solo il PREFISSO
        (``_flag``, ``_check_service_off``), componendo la variante a runtime:
        vale quindi sia la chiave intera sia un prefisso che ne ha almeno una."""
        missing = [k for k in sorted(_keys_cited_in_source())
                   if k not in MESSAGES and not _variants(k)]
        self.assertEqual([], missing)

    def test_flag_prefixes_define_all_four_outcomes(self):
        """``_flag`` compone quattro varianti fisse dal prefisso. Se ne manca
        una, il ramo corrispondente esce con la chiave grezza — e capita solo
        sulla configurazione che innesca proprio quel ramo, cioe' dal cliente."""
        for prefix in sorted(_flag_prefixes()):
            for variant in ("no_section", "not_set", "bad", "ok"):
                self.assertIn("%s.%s" % (prefix, variant), MESSAGES, prefix)

    def test_catalog_has_no_unused_entry(self):
        """Una voce che nessuna regola cita e' testo morto: o la chiave e'
        cambiata e questa e' rimasta indietro, o il controllo e' sparito."""
        cited = _keys_cited_in_source() | {"engine.nothing_to_assess"}
        used = set(cited)
        for key in cited:
            used |= _variants(key)
        self.assertEqual([], sorted(set(MESSAGES) - used))

    def test_render_falls_back_instead_of_raising(self):
        self.assertEqual("nope.missing", render("nope.missing", "it"))
        # Parametro mancante: si restituisce il testo non interpolato, non
        # un'eccezione che farebbe fallire l'intero audit.
        self.assertIn("{count}", render("fos.any_any.found", "it"))

    def test_unknown_language_falls_back_to_italian(self):
        self.assertEqual("it", messages.normalize_lang("de"))
        self.assertEqual("it", messages.normalize_lang(None))
        self.assertEqual("en", messages.normalize_lang("EN-gb"))


class TestRenderedOutput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texts = _all_rendered_texts()

    def test_no_raw_key_reaches_the_user(self):
        leaked = [(where, text) for where, text in self.texts
                  if _LOOKS_LIKE_KEY.match(text.strip())]
        self.assertEqual([], leaked)

    def test_no_unsubstituted_placeholder_reaches_the_user(self):
        left = [(where, text) for where, text in self.texts
                if _PLACEHOLDER.search(text)]
        self.assertEqual([], left)

    def test_no_empty_detail(self):
        for where, text in self.texts:
            if where.endswith("detail") or where.endswith("title"):
                self.assertTrue(text.strip(), where)

    def test_italian_and_english_reports_differ(self):
        """Regressione: se il rendering ignorasse ``lang``, i due report
        sarebbero identici e il selettore di lingua sarebbe una decorazione."""
        cfg = _fixture("fortigate_violations.conf")
        it = netsec_audit.run_netsec_audit(config_text=cfg, lang="it")
        en = netsec_audit.run_netsec_audit(config_text=cfg, lang="en")
        self.assertEqual([r["status"] for r in it["rules"]],
                         [r["status"] for r in en["rules"]])
        self.assertNotEqual([r["detail"] for r in it["rules"]],
                            [r["detail"] for r in en["rules"]])
        self.assertEqual("en", en["lang"])

    def test_cli_evidence_is_not_translated(self):
        """Una riga citata dalla configurazione deve restare identica nelle due
        lingue: e' una prova, non una frase."""
        cfg = _fixture("ios_violations.conf")
        quoted = {}
        for lang in LANGS:
            res = netsec_audit.run_netsec_audit(config_text=cfg, lang=lang)
            quoted[lang] = [e["text"] for r in res["rules"]
                            for e in r["evidence"] if e["line"] > 0]
        self.assertEqual(quoted["it"], quoted["en"])
        self.assertIn("no aaa new-model", quoted["en"])


class TestGuidance(unittest.TestCase):
    def _checks(self):
        seen = {}
        for entries in netsec_audit.BENCHMARKS.values():
            for tmpl in entries:
                seen[tmpl["check"].__name__] = tmpl["id"]
        return seen

    def test_every_check_has_guidance(self):
        missing = sorted(name for name in self._checks()
                         if not guidance.GUIDANCE.get(name))
        self.assertEqual([], missing)

    def test_guidance_covers_why_and_impact_in_both_languages(self):
        for name in self._checks():
            entry = guidance.GUIDANCE[name]
            for field in ("why", "impact"):
                self.assertIn(field, entry, name)
                for lang in LANGS:
                    self.assertTrue(entry[field].get(lang, "").strip(),
                                    "%s/%s/%s" % (name, field, lang))

    def test_guidance_has_no_entry_for_a_check_that_no_longer_exists(self):
        known = set(self._checks())
        orphans = sorted(n for n in guidance.GUIDANCE if n not in known)
        self.assertEqual([], orphans)

    def test_guidance_for_unknown_check_is_empty_not_an_error(self):
        self.assertEqual({}, guidance.guidance_for("check_nonexistent", "it"))

    def test_guidance_language_selection(self):
        it = guidance.guidance_for("check_ios_cdp", "it")
        en = guidance.guidance_for("check_ios_cdp", "en")
        self.assertTrue(it["why"] and en["why"])
        self.assertNotEqual(it["why"], en["why"])


if __name__ == "__main__":
    unittest.main()
