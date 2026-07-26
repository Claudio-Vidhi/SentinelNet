# -*- coding: utf-8 -*-
"""Test del router Flow SIEM.

Copre i difetti della versione precedente, che costruiva gli eventi da
``flow_aggregates`` (volumi NetFlow/IPFIX, privi di verdetti):
  - id posizionale ``siem-fl-<indice>`` derivato dal rango per byte: al
    refresh lo stesso id puntava a un'altra connessione;
  - azione ALLOW/DENY inventata con ``idx % 5``;
  - istogramma prodotto da ``sin()`` senza interrogare il database;
  - nessuno scoping per tenant (una sede vedeva gli eventi delle altre);
  - soppressione allerta che rispondeva "success" senza scrivere nulla.
"""

import os
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_siem_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402

PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}
NOW = int(time.time())


class TestFlowSiem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()
        for user, role, groups in (("adm_siem", "admin", None),
                                   ("op_a_siem", "operator", ["sede-a"])):
            try:
                user_manager.create_user(user, PASS, role=role, groups=groups)
            except Exception:
                pass

        conn = db.get_observability_connection()
        conn.execute("DELETE FROM syslog_events")
        conn.execute("DELETE FROM siem_suppressions")
        rows = [
            # sede-a: un deny FortiGate con kv completo
            (NOW - 60, "sede-a", "10.0.1.1", 4, "deny",
             'srcip=10.0.1.5 dstip=203.0.113.9 srcport=51000 dstport=445 '
             'proto=6 sentbyte=800 rcvdbyte=200'),
            # sede-a: un accept
            (NOW - 120, "sede-a", "10.0.1.1", 6, "accept",
             'srcip=10.0.1.6 dstip=8.8.8.8 dstport=53 proto=17 '
             'sentbyte=60 rcvdbyte=140'),
            # sede-b: deve restare invisibile all'operatore di sede-a
            (NOW - 90, "sede-b", "10.0.2.1", 3, "blocked",
             'srcip=10.0.2.9 dstip=185.10.10.10 dstport=22 proto=6'),
            # evento senza IP nel messaggio: i campi restano vuoti, non finti
            (NOW - 30, "sede-a", "10.0.1.1", 5, "accept",
             'interfaccia port2 attivata'),
        ]
        conn.executemany(
            "INSERT INTO syslog_events (ts, tenant, device_ip, severity, "
            "action, message) VALUES (?, ?, ?, ?, ?, ?)", rows)
        conn.commit()
        conn.close()

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200, r.text
        return c

    # --- id stabili ---------------------------------------------------------

    def test_event_ids_are_database_primary_keys_not_positions(self):
        """L'id deve identificare l'evento, non il suo posto in classifica."""
        c = self._client("adm_siem")
        r = c.get("/api/flow-siem/events?window=24h&limit=50")
        self.assertEqual(r.status_code, 200, r.text)
        events = r.json()["events"]
        self.assertTrue(events)
        for e in events:
            self.assertIsInstance(e["id"], int)
            self.assertFalse(str(e["id"]).startswith("siem-fl-"))
        self.assertEqual(len(events), len({e["id"] for e in events}))

    def test_same_id_refers_to_same_event_across_calls(self):
        """Regressione del bug segnalato: il dettaglio aperto cambiava
        connessione perche' l'id seguiva il rango per byte."""
        c = self._client("adm_siem")
        first = {e["id"]: (e["src_ip"], e["dst_ip"], e["ts"])
                 for e in c.get("/api/flow-siem/events?window=24h").json()["events"]}
        second = {e["id"]: (e["src_ip"], e["dst_ip"], e["ts"])
                  for e in c.get("/api/flow-siem/events?window=24h").json()["events"]}
        self.assertTrue(first)
        for eid, payload in first.items():
            self.assertEqual(second.get(eid), payload)

    # --- dati reali, niente invenzioni -------------------------------------

    def test_action_comes_from_the_device_not_from_row_position(self):
        c = self._client("adm_siem")
        events = c.get("/api/flow-siem/events?window=24h").json()["events"]
        by_src = {e["src_ip"]: e for e in events if e["src_ip"]}
        self.assertTrue(by_src["10.0.1.5"]["is_deny"])
        self.assertFalse(by_src["10.0.1.6"]["is_deny"])

    def test_fields_absent_from_the_message_stay_empty(self):
        """Un evento senza IP nel corpo non deve ricevere IP/porte inventate."""
        c = self._client("adm_siem")
        events = c.get("/api/flow-siem/events?window=24h").json()["events"]
        bare = [e for e in events if "interfaccia port2" in (e["message"] or "")]
        self.assertEqual(len(bare), 1)
        e = bare[0]
        for field in ("src_ip", "dst_ip", "src_port", "dst_port", "bytes"):
            self.assertIsNone(e[field], f"{field} inventato: {e[field]!r}")

    def test_bytes_are_summed_from_the_message(self):
        c = self._client("adm_siem")
        events = c.get("/api/flow-siem/events?window=24h").json()["events"]
        deny = [e for e in events if e["src_ip"] == "10.0.1.5"][0]
        self.assertEqual(deny["bytes"], 1000)      # 800 sent + 200 rcvd
        self.assertEqual(deny["proto"], "TCP")     # proto=6
        self.assertEqual(deny["dst_port"], 445)

    # --- scoping per tenant ------------------------------------------------

    def test_operator_does_not_see_other_sites_events(self):
        c = self._client("op_a_siem")
        events = c.get("/api/flow-siem/events?window=24h").json()["events"]
        self.assertTrue(events)
        self.assertEqual({e["tenant"] for e in events}, {"sede-a"})

    def test_admin_sees_every_site(self):
        c = self._client("adm_siem")
        events = c.get("/api/flow-siem/events?window=24h").json()["events"]
        self.assertIn("sede-b", {e["tenant"] for e in events})

    def test_facets_are_tenant_scoped(self):
        c = self._client("op_a_siem")
        f = c.get("/api/flow-siem/facets?window=24h").json()
        srcs = {x["value"] for x in f["top_src_ips"]}
        self.assertNotIn("10.0.2.9", srcs)

    # --- istogramma reale ---------------------------------------------------

    def test_histogram_counts_real_events(self):
        c = self._client("adm_siem")
        h = c.get("/api/flow-siem/histogram?window=24h&buckets=30").json()
        self.assertEqual(len(h["buckets"]), 30)
        self.assertEqual(sum(b["count"] for b in h["buckets"]), 4)
        self.assertEqual(sum(b["deny_count"] for b in h["buckets"]), 2)

    def test_histogram_has_empty_buckets_where_nothing_happened(self):
        """Discriminante rispetto alla vecchia sinusoide: quella valeva
        ``abs(sin(i*0.4))*45 + (10 o 25)``, quindi NESSUN bucket poteva essere
        zero. Qui i quattro eventi sono tutti negli ultimi due minuti, per cui
        su una finestra di 24h la quasi totalita' dei bucket deve valere 0."""
        c = self._client("adm_siem")
        h = c.get("/api/flow-siem/histogram?window=24h&buckets=30").json()
        counts = [b["count"] for b in h["buckets"]]
        self.assertIn(0, counts, "nessun bucket vuoto: valori sintetici?")
        self.assertGreaterEqual(counts.count(0), 25, f"bucket: {counts}")
        self.assertEqual(sum(counts), 4)

    def test_histogram_is_tenant_scoped(self):
        c = self._client("op_a_siem")
        h = c.get("/api/flow-siem/histogram?window=24h&buckets=30").json()
        self.assertEqual(sum(b["count"] for b in h["buckets"]), 3)

    # --- filtri ------------------------------------------------------------

    def test_action_filter_selects_denies(self):
        c = self._client("adm_siem")
        events = c.get("/api/flow-siem/events?window=24h&action=DENY").json()["events"]
        self.assertTrue(events)
        self.assertTrue(all(e["is_deny"] for e in events))

    def test_query_filter_matches_ip(self):
        c = self._client("adm_siem")
        events = c.get("/api/flow-siem/events?window=24h&q=203.0.113.9").json()["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["dst_ip"], "203.0.113.9")

    # --- soppressione persistente ------------------------------------------

    def test_suppression_persists_and_hides_the_event(self):
        c = self._client("adm_siem")
        events = c.get("/api/flow-siem/events?window=24h").json()["events"]
        target = [e for e in events if e["src_ip"] == "10.0.1.5"][0]

        r = c.post("/api/flow-siem/alerts/suppress", headers=CSRF,
                   json={"event_id": target["id"]})
        self.assertEqual(r.status_code, 200, r.text)
        db.stop_writer()          # drena la coda di scrittura asincrona
        db.start_writer()

        after = c.get("/api/flow-siem/events?window=24h").json()["events"]
        self.assertNotIn(target["id"], {e["id"] for e in after})

    def test_cannot_suppress_an_event_outside_your_scope(self):
        adm = self._client("adm_siem")
        sede_b = [e for e in adm.get("/api/flow-siem/events?window=24h").json()["events"]
                  if e["tenant"] == "sede-b"][0]
        op = self._client("op_a_siem")
        r = op.post("/api/flow-siem/alerts/suppress", headers=CSRF,
                    json={"event_id": sede_b["id"]})
        self.assertEqual(r.status_code, 404, r.text)

    def test_suppressing_a_nonexistent_event_is_rejected(self):
        c = self._client("adm_siem")
        r = c.post("/api/flow-siem/alerts/suppress", headers=CSRF,
                   json={"event_id": 999999})
        self.assertEqual(r.status_code, 404, r.text)


class TestFlowSiemDeepScan(unittest.TestCase):
    """Un IP presente nelle faccette deve essere raggiungibile dalla tabella.

    src_ip/dst_ip non sono colonne: il filtro e' in Python. Prima veniva
    applicato a un solo blocco di ``limit * 4`` righe recenti, mentre le
    faccette ne scandiscono 2000: un IP raro compariva nella colonna faccette
    ma cliccarlo non mostrava alcuna riga.
    """

    RARE = "192.168.194.254"

    @classmethod
    def setUpClass(cls):
        conn = db.get_observability_connection()
        # L'evento raro e' il piu' VECCHIO: sepolto sotto 800 righe recenti.
        conn.execute(
            "INSERT INTO syslog_events (ts, tenant, device_ip, severity, "
            "action, message) VALUES (?, 'sede-a', '10.0.1.1', 6, 'accept', ?)",
            (NOW - 3000, f"srcip={cls.RARE} dstip=10.0.1.9 dstport=443 proto=6"))
        conn.executemany(
            "INSERT INTO syslog_events (ts, tenant, device_ip, severity, "
            "action, message) VALUES (?, 'sede-a', '10.0.1.1', 6, 'accept', ?)",
            [(NOW - 100 - i, f"srcip=10.0.1.2 dstip=10.0.1.9 dstport=8765 proto=6")
             for i in range(800)])
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        conn = db.get_observability_connection()
        conn.execute("DELETE FROM syslog_events WHERE ts <= ?", (NOW - 100,))
        conn.commit()
        conn.close()

    def _client(self):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login",
                   json={"username": "adm_siem", "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def test_facet_ip_is_reachable_from_the_table(self):
        c = self._client()
        facets = c.get("/api/flow-siem/facets?window=24h").json()
        self.assertIn(self.RARE, [f["value"] for f in facets["top_src_ips"]])

        events = c.get(
            f"/api/flow-siem/events?window=24h&limit=100&q={self.RARE}"
        ).json()["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["src_ip"], self.RARE)

    def test_unfiltered_query_still_returns_the_newest_page(self):
        c = self._client()
        events = c.get("/api/flow-siem/events?window=24h&limit=100").json()["events"]
        self.assertEqual(len(events), 100)
        self.assertEqual(events, sorted(events, key=lambda e: e["ts"], reverse=True))


if __name__ == "__main__":
    unittest.main()
