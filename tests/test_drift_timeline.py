# -*- coding: utf-8 -*-
"""Timeline grafica delle versioni di configurazione (scheda Config Drift).

Si appoggia all'archivio .history, non al mirror git: quello e' ridondanza in
sola scrittura (services/config_drift/mirror.py) e richiede git installato,
mentre /api/drift/{ip}/versions c'e' sempre. Stessa vista, nessuna dipendenza
nuova.
"""

import os
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(BASE, *parts), encoding="utf-8") as fh:
        return fh.read()


class TimelineIsWiredIn(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = _read("static", "js", "config-drift.js")
        cls.html = _read("templates", "dashboard.html")
        cls.css = _read("static", "css", "dashboard.css")

    def test_the_container_exists_in_the_template(self):
        # Un listener agganciato a un id assente non solleva nulla e lascia la
        # vista muta: e' il modo in cui una tab arriva vuota senza un errore.
        self.assertIn('id="driftTimeline"', self.html)

    def test_it_is_drawn_after_the_versions_are_loaded(self):
        self.assertIn("renderDriftTimeline();", self.js)

    def test_it_is_cleared_when_the_selection_changes(self):
        # Altrimenti restano i marcatori dell'apparato precedente sotto le
        # versioni di quello nuovo.
        body = self.js[self.js.index("function clearDriftVersions"):]
        body = body[:body.index("\n    async function onDriftDeviceSelected")]
        self.assertIn("driftTimeline", body)
        self.assertIn("driftPicked = []", body)

    def test_styles_exist_for_every_class_the_js_emits(self):
        for cls in ("drift-timeline-track", "drift-timeline-mark",
                    "drift-timeline-ends", "drift-timeline-hint"):
            self.assertIn(cls, self.js, f"{cls} non usata dal JS")
            self.assertIn("." + cls, self.css, f"{cls} senza CSS")


class BasicIso8601IsParsedExplicitly(unittest.TestCase):
    """history._now() produce la forma BASIC ("20260908T143012.123456Z").

    new Date() parsa solo la forma ESTESA: su questa restituisce Invalid Date
    senza sollevare, quindi ogni marcatore finirebbe alla stessa ascissa e la
    timeline sarebbe una riga di barrette sovrapposte, muta sul perche'.
    """

    def test_the_stamp_format_is_still_what_the_parser_expects(self):
        # Se history._now() cambia forma, cade qui e non nella UI.
        from services.config_drift import history
        self.assertRegex(history._now(), r"^\d{8}T\d{6}\.\d{6}Z$")

    def test_the_js_expands_it_before_handing_it_to_Date(self):
        js = _read("static", "js", "config-drift.js")
        self.assertIn("function driftStampToDate", js)

    def test_the_microseconds_are_optional_in_the_parser(self):
        # Una versione archiviata da una release precedente, senza la parte
        # frazionaria, non deve sparire dalla timeline.
        js = _read("static", "js", "config-drift.js")
        line = next(l for l in js.splitlines() if "exec(stamp" in l)
        self.assertIn("(?:", line, f"gruppo dei microsecondi non opzionale: {line}")

    def test_a_single_version_does_not_divide_by_zero(self):
        # Con una sola versione lo span temporale e' 0: senza il caso a parte
        # ogni marcatore riceverebbe left: NaN% e non si vedrebbe nulla.
        js = _read("static", "js", "config-drift.js")
        self.assertRegex(js, r"span\s*>\s*0")


class TheDiffKeepsOneSourceOfTruth(unittest.TestCase):
    """La timeline pilota le select esistenti invece di rifare la chiamata.

    Due percorsi verso lo stesso diff sono due punti in cui sbagliare l'ordine
    di from/to, e un diff invertito si legge come una modifica mai avvenuta.
    """

    def test_markers_drive_the_selects_then_reuse_showDriftDiff(self):
        js = _read("static", "js", "config-drift.js")
        body = js[js.index("function onDriftMarkerClick"):]
        body = body[:body.index("\n    function paintDriftSelection")]
        self.assertIn("driftFromVersionSelect", body)
        self.assertIn("driftToVersionSelect", body)
        self.assertIn("showDriftDiff()", body)
        # Nessuna seconda fetch del diff dentro il gestore del click.
        self.assertNotIn("apiFetch", body)


if __name__ == "__main__":
    unittest.main()
