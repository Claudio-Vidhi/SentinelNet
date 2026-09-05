# -*- coding: utf-8 -*-
"""Il tab Traffico e' una pill bar su quattro viste, non due tab gemelli.

Prima della fusione la stessa finestra temporale esisteva tre volte
(`#flowsWindow`, `#obsChartWindow`, `#flowSiemWindow`) senza che nessuna
parlasse con le altre: si poteva leggere un top talker su 15 minuti accanto a
un grafico su 24 ore e credere che raccontassero lo stesso momento.

Qui si asserisce la struttura, non l'aspetto: che le pill e i pane esistano,
che i controlli sostituiti siano stati cancellati (un controllo orfano resta
cliccabile e muove una finestra che nessuno legge piu'), e che ogni rotta
chiamata dai due moduli JS del tab sia una rotta davvero registrata.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_traffico_"))

import app_server  # noqa: E402
from tests.routes import iter_routes  # noqa: E402

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _registered_api_paths():
    literal, templated = set(), []
    for route in iter_routes(app_server.app):
        path = getattr(route, "path", "")
        if not path.startswith("/api/"):
            continue
        if "{" in path:
            templated.append(re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", path) + "$"))
        else:
            literal.add(path)
    return literal, templated


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestTrafficoStructure(unittest.TestCase):
    """Pill, pane e header unico del tab Traffico."""

    # Ogni pill ha il suo pane: una pill senza pane e' un pulsante che non apre
    # niente, un pane senza pill e' contenuto irraggiungibile.
    PILLS = ["overview", "flows", "search"]
    HEADER = ["trafWindow", "trafMetric", "trafAutoRefresh",
              "trafHideTelemetry", "trafLastUpdate"]

    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "observability.js")

    def test_pills_and_panes_exist(self):
        for view in self.PILLS:
            self.assertIn(f'id="trafPill-{view}"', self.html,
                          f"manca la pill '{view}' nel tab Traffico")
            self.assertIn(f'id="trafPane-{view}"', self.html,
                          f"manca il pane '{view}' nel tab Traffico")

    def test_header_controls_exist(self):
        for element_id in self.HEADER:
            self.assertIn(f'id="{element_id}"', self.html,
                          f"manca il controllo '{element_id}' nell'header del tab")

    def test_pills_are_wired_to_the_switcher(self):
        for view in self.PILLS:
            self.assertIn(f'data-traf-view="{view}"', self.html,
                          f"la pill '{view}' non ha data-traf-view")
        self.assertIn("function trafSwitchView", self.js)
        self.assertIn("window.trafSwitchView = trafSwitchView", self.js)

    def test_single_state_object(self):
        # Una sola sorgente di verita' per finestra e tenant: e' il motivo per
        # cui la fusione esiste.
        self.assertIn("const trafState", self.js)
        start = self.js.index("const trafState")
        block = self.js[start:start + 400]
        for key in ("window:", "metric:", "autoRefresh:", "hideTelemetry:"):
            self.assertIn(key, block, f"trafState non espone '{key}'")

    def test_the_tab_keeps_its_id(self):
        # Si tiene #tab-flows come contenitore: la voce di nav e ogni
        # switchTab('tab-flows') esistente continuano a funzionare.
        self.assertIn('id="tab-flows"', self.html)

    def test_replaced_controls_are_gone(self):
        # Un controllo sostituito ma non cancellato resta cliccabile e muove
        # una finestra che nessuno legge piu'.
        for element_id in ("flowsWindow", "flowsMetric", "flowsTenantBtn",
                           "flowsAutoRefresh", "flowsHideTelemetry",
                           "flowsLastUpdate", "obsChartWindow",
                           "flowDetailInline", "flowSiemWindow",
                           "flowSiemTenant"):
            self.assertNotIn(f'id="{element_id}"', self.html,
                             f"'{element_id}' e' stato sostituito ma non cancellato")

    def test_the_twin_tab_is_gone_and_nothing_points_at_it(self):
        # Il tab gemello si raggiungeva solo dalla sua stessa subtab bar:
        # cancellare la barra senza cancellare il tab lo rende irraggiungibile.
        self.assertNotIn("tab-flow-siem", self.html)

    def test_the_moved_panels_live_inside_their_pane(self):
        # Spostare un pannello fuori dal suo pane lo renderebbe visibile in
        # tutte e tre le viste.
        for pane, ids in (
            ("overview", ("fgKpiStrip", "fgTalkersTableBody", "obsProtocolCanvas",
                          "fgProtoTableBody", "fgTenantSummary", "flowsObsBanner")),
            ("flows", ("flowsTableBody", "flowsSourceChips", "flowsSyslogAllSection")),
            ("search", ("flowSiemHistCanvas", "flowSiemQueryInput", "flowSiemTableBody",
                        "flowSiemFacets")),
        ):
            start = self.html.index(f'id="trafPane-{pane}"')
            end = self.html.index('id="trafPane-', start + 10) if pane != "search" \
                else self.html.index('id="flowDetailPanel"', start)
            body = self.html[start:end]
            for element_id in ids:
                self.assertIn(f'id="{element_id}"', body,
                              f"'{element_id}' non e' dentro il pane '{pane}'")


class TestTrafficoCallsRealRoutes(unittest.TestCase):
    """Ogni apiFetch dei moduli del tab deve colpire una rotta registrata.

    E' la rete di sicurezza dell'intera fusione: spostare markup non deve
    cambiare nessuna rotta, e una URL storpiata durante lo spostamento
    tornerebbe 404 in silenzio, con il pannello semplicemente vuoto."""

    MODULES = ["observability.js", "flow-analytics.js"]

    @classmethod
    def setUpClass(cls):
        cls.literal, cls.templated = _registered_api_paths()

    def _is_registered(self, path):
        return path in self.literal or any(rx.match(path) for rx in self.templated)

    def test_every_apifetch_path_exists(self):
        for module in self.MODULES:
            src = _read("static", "js", module)
            calls = re.findall(r"apiFetch\(\s*[`'\"](/api/[^`'\"?]*)", src)
            self.assertTrue(calls, f"nessuna chiamata apiFetch trovata in {module}")
            for raw in calls:
                probe = re.sub(r"\$\{[^}]*\}", "X", raw).rstrip("/")
                self.assertTrue(
                    self._is_registered(probe),
                    f"{module} chiama {raw!r}, che non e' una rotta registrata",
                )


class PerIpViewIsWiredEndToEnd(unittest.TestCase):
    """La pill "Per IP" e i suoi controlli.

    Una pill aggiunta senza il suo pane, o un pane senza la sua voce in
    TRAF_VIEWS, non da' errore: lascia visibile la vista precedente sotto
    quella nuova. E un listener agganciato a un id che nel template non esiste
    non solleva niente e lascia il controllo muto.
    """

    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "observability.js")

    def test_the_pill_and_its_pane_both_exist(self):
        self.assertIn('id="trafPill-hosts"', self.html)
        self.assertIn('data-traf-view="hosts"', self.html)
        self.assertIn('id="trafPane-hosts"', self.html)

    def test_the_view_is_declared_where_the_panes_are_toggled(self):
        # Senza questo, aprire la pill mostra il pane nuovo e NON nasconde
        # quello vecchio.
        self.assertIn("const TRAF_VIEWS = ['overview', 'flows', 'search', 'hosts', 'policies']", self.js)
        self.assertIn("for (const v of TRAF_VIEWS)", self.js)
        self.assertIn("hosts:     () => loadTrafHosts()", self.js)

    def test_every_bound_id_exists_in_the_template(self):
        for element_id in ("trafHostSearch", "trafHostSeriesSelect",
                           "trafHostsBody", "trafHostsCount",
                           "trafHostSeriesCanvas", "trafHostSeriesEmpty",
                           "trafHostSeriesLegend"):
            self.assertIn(f'id="{element_id}"', self.html,
                          f"{element_id} e' usato da observability.js ma non "
                          "esiste nel template")

    def test_the_search_reloads_from_the_server(self):
        # Filtrare in locale farebbe divergere il conteggio mostrato accanto
        # al titolo da quello che il server ha davvero contato.
        self.assertIn("setTimeout(loadTrafHosts", self.js)
        self.assertIn("&q=${encodeURIComponent(q.trim())}", self.js)


class TriageFlowLogRowOpens(unittest.TestCase):
    """La riga del Triage Flow Log ha cursor:pointer: al clic deve succedere
    qualcosa. Non apriva niente perche' l'id confrontato era una stringa da un
    lato e un intero dall'altro, e il sorgente conteneva comunque tutte le
    parole giuste — quindi il controllo esegue il renderer, non lo legge."""

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_the_detail_drawer_opens_on_click(self):
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_siem_row_click.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
