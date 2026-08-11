# -*- coding: utf-8 -*-
"""Test unitari di wlc_service (AireOS / Catalyst 9800, SSH mockato).

Copre anche il motivo per cui il tab Live restava vuoto: il servizio tornava
solo il testo CLI grezzo, mai le liste aps/clients/wlans/rogues che la UI
legge. Tutti gli output sono di esempio (RFC 5737, MAC AA:BB:CC:...).
"""
import unittest
from contextlib import contextmanager
from unittest import mock

from services import wlc_service as wlc

AIREOS = {"IP": "192.0.2.10", "Vendor": "cisco_wlc", "Profile": "custom"}
C9800 = {"IP": "192.0.2.11", "Vendor": "cisco_9800", "Profile": "custom"}
CISCO = {"IP": "192.0.2.12", "Vendor": "cisco", "Profile": "custom"}

SYSINFO = """Manufacturer's Name.............................. Cisco Systems Inc.
Product Name..................................... Cisco Controller
Product Version.................................. 8.5.999.0
System Up Time................................... 10 days 4 hrs 12 mins 3 secs
"""

IOSXE_REJECT = """             ^
% Invalid input detected at '^' marker.
"""


def _table(cols, rows):
    """Tabella in stile AireOS: righello di trattini spezzato per colonna."""
    head = "".join(n.ljust(w) for n, w in cols).rstrip()
    ruler = "".join(("-" * (w - 2)).ljust(w) for _, w in cols).rstrip()
    body = ["".join(str(v).ljust(w) for v, (_, w) in zip(r, cols)).rstrip()
            for r in rows]
    return "\n".join([head, ruler] + body) + "\n"


def _table_long_ruler(cols, rows):
    """Tabella in stile IOS-XE: un unico righello lungo, niente colonne."""
    head = "".join(n.ljust(w) for n, w in cols).rstrip()
    body = ["".join(str(v).ljust(w) for v, (_, w) in zip(r, cols)).rstrip()
            for r in rows]
    return "\n".join([head, "-" * len(head)] + body) + "\n"


AP_COLS = [("AP Name", 20), ("Slots", 7), ("AP Model", 22),
           ("Ethernet MAC", 19), ("Location", 18), ("Country", 9),
           ("IP Address", 17), ("Clients", 7)]
AP_SUMMARY = "Number of APs.................................... 2\n\n" + _table(
    AP_COLS,
    [("ap-01", 2, "AIR-EXAMPLE-1", "aa:bb:cc:dd:ee:01", "default location",
      "IT", "192.0.2.21", 4),
     ("ap-02", 2, "AIR-EXAMPLE-2", "aa:bb:cc:dd:ee:02", "lab", "IT",
      "192.0.2.22", 0)])

CLIENT_COLS = [("MAC Address", 19), ("AP Name", 20), ("WLAN", 6),
               ("Status", 14), ("Auth", 6), ("Protocol", 18)]
CLIENT_SUMMARY = "Number of Clients................................ 2\n\n" + _table(
    CLIENT_COLS,
    [("aa:bb:cc:11:22:01", "ap-01", 1, "Associated", "Yes", "802.11ac(5 GHz)"),
     ("aa:bb:cc:11:22:02", "ap-02", 2, "Associated", "Yes", "802.11n(2.4 GHz)")])

WLAN_COLS = [("WLAN ID", 9), ("WLAN Profile Name / SSID", 34), ("Status", 10),
             ("Interface Name", 22)]
WLAN_SUMMARY = "Number of WLANs.................................. 2\n\n" + _table(
    WLAN_COLS,
    [(1, "corp / corp-ssid", "Enabled", "management"),
     (2, "guest / guest-ssid", "Disabled", "guest-vlan")])

ROGUE_COLS = [("MAC Address", 19), ("Classification", 20), ("# APs", 7),
              ("# Clients", 11), ("Last Heard", 22), ("Status", 8)]
ROGUE_SUMMARY = _table(
    ROGUE_COLS,
    [("aa:bb:cc:99:88:01", "Unclassified", 1, 0, "Mon Jan  1 10:00:00", "Alert")])


AP_AUTORF = """AP Name.......................................... ap-01
MAC Address...................................... aa:bb:cc:dd:ee:01
  Radio Type..................................... RADIO_TYPE_80211a
  Noise Information
    Noise Profile................................ PASSED
  Load Information
    Channel Utilization.......................... 12 %
    Attached Client Count........................ 4
  Channel Assignment Information
    Current Channel.............................. 36
    Channel Width................................ 40 Mhz
    Current Channel Average Energy............... -83 dBm
    Recommended Best Channel..................... 36
"""


class PlatformTest(unittest.TestCase):
    def test_vendor_hint(self):
        self.assertEqual(wlc.platform_of(AIREOS), "aireos")
        self.assertEqual(wlc.platform_of(C9800), "iosxe")
        self.assertEqual(wlc.platform_of(CISCO), "iosxe")

    def test_detect_from_output_beats_vendor(self):
        # Un 5508 inventariato come 'cisco' generico veniva interrogato con la
        # CLI del 9800: comandi rifiutati, tabelle vuote.
        self.assertEqual(wlc.detect_platform(SYSINFO, CISCO), "aireos")
        self.assertEqual(wlc.detect_platform(IOSXE_REJECT, CISCO), "iosxe")

    def test_detect_falls_back_to_vendor(self):
        self.assertEqual(wlc.detect_platform("", AIREOS), "aireos")
        self.assertEqual(wlc.detect_platform("", C9800), "iosxe")


class MacTest(unittest.TestCase):
    def test_normalize_formats(self):
        for raw in ("AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff",
                    "aabbccddeeff"):
            self.assertEqual(wlc.normalize_mac(raw, "aireos"),
                             "aa:bb:cc:dd:ee:ff")

    def test_invalid_mac(self):
        with self.assertRaises(wlc.WlcError):
            wlc.normalize_mac("not-a-mac", "aireos")


class _FakeConn:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.sent = []

    def send_command(self, command, read_timeout=None):
        self.sent.append(command)
        return self.outputs.get(command, "out")

    def send_command_timing(self, command):
        self.sent.append(command)
        return ""

    def enable(self):
        pass


def _patch_session(platform, conn, sysinfo=""):
    @contextmanager
    def fake(device, timeout=30):
        yield conn, platform, sysinfo
    return mock.patch.object(wlc, "_session", fake)


class QueryTest(unittest.TestCase):
    def test_command_per_platform(self):
        conn = _FakeConn()
        with _patch_session("aireos", conn):
            r = wlc.query(AIREOS, "client_summary")
        self.assertEqual(r["command"], "show client summary")
        self.assertEqual(r["platform"], "aireos")

        conn = _FakeConn()
        with _patch_session("iosxe", conn):
            r = wlc.query(C9800, "client_summary")
        self.assertEqual(r["command"], "show wireless client summary")
        self.assertEqual(r["platform"], "iosxe")

    def test_platform_follows_detection_not_vendor(self):
        conn = _FakeConn()
        with _patch_session("aireos", conn):
            r = wlc.query(CISCO, "client_summary")
        self.assertEqual(r["command"], "show client summary")

    def test_client_detail_substitutes_mac(self):
        conn = _FakeConn()
        with _patch_session("iosxe", conn):
            r = wlc.query(C9800, "client_detail", mac="AABB.CCDD.EEFF")
        self.assertEqual(
            r["command"],
            "show wireless client mac-address aa:bb:cc:dd:ee:ff detail")

    def test_client_detail_requires_mac(self):
        # Deve fallire prima di aprire la sessione SSH.
        with mock.patch.object(wlc, "_session", side_effect=AssertionError):
            with self.assertRaises(wlc.WlcError):
                wlc.query(AIREOS, "client_detail")

    def test_unknown_service(self):
        with self.assertRaises(wlc.WlcError):
            wlc.query(AIREOS, "nope")

    def test_status_reuses_sysinfo(self):
        conn = _FakeConn()
        with _patch_session("aireos", conn, SYSINFO):
            r = wlc.query(AIREOS, "status")
        self.assertIn("Product Version", r["data"])
        self.assertEqual(conn.sent, [])  # nessun comando in piu'


class TableParsingTest(unittest.TestCase):
    def test_ap_summary(self):
        aps = wlc._table_rows(AP_SUMMARY, wlc._AP_FIELDS)
        self.assertEqual([a["name"] for a in aps], ["ap-01", "ap-02"])
        self.assertEqual(aps[0]["ip"], "192.0.2.21")
        self.assertEqual(aps[0]["mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(aps[0]["model"], "AIR-EXAMPLE-1")
        self.assertEqual(aps[0]["clients"], "4")

    def test_client_summary(self):
        clients = wlc._table_rows(CLIENT_SUMMARY, wlc._CLIENT_FIELDS)
        self.assertEqual(len(clients), 2)
        self.assertEqual(clients[0]["mac"], "aa:bb:cc:11:22:01")
        self.assertEqual(clients[0]["ap_name"], "ap-01")
        self.assertEqual(clients[0]["wlan"], "1")
        self.assertEqual(clients[0]["status"], "Associated")

    def test_wlan_summary(self):
        wlans = wlc._table_rows(WLAN_SUMMARY, wlc._WLAN_FIELDS)
        self.assertEqual([w["id"] for w in wlans], ["1", "2"])
        self.assertEqual(wlans[0]["ssid"], "corp / corp-ssid")
        self.assertEqual(wlans[1]["status"], "Disabled")

    def test_rogue_summary(self):
        rogues = wlc._table_rows(ROGUE_SUMMARY, wlc._ROGUE_FIELDS)
        self.assertEqual(rogues[0]["mac"], "aa:bb:cc:99:88:01")
        self.assertEqual(rogues[0]["status"], "Alert")

    def test_iosxe_single_ruler(self):
        # Il 9800 stampa un solo trattino lungo: i confini di colonna vengono
        # dalle posizioni delle intestazioni.
        text = _table_long_ruler(
            [("AP Name", 14), ("Slots", 7), ("AP Model", 12),
             ("Ethernet MAC", 18), ("IP Address", 14), ("State", 12)],
            [("ap-01", 2, "EXAMPLE-1", "aabb.ccdd.ee01", "192.0.2.21",
              "Registered")])
        aps = wlc._table_rows(text, wlc._AP_FIELDS)
        self.assertEqual(aps[0]["name"], "ap-01")
        self.assertEqual(aps[0]["ip"], "192.0.2.21")
        self.assertEqual(aps[0]["status"], "Registered")

    def test_values_not_aligned_with_the_header(self):
        # Modello e location piu' larghi del titolo spingono a destra tutte le
        # colonne dopo di loro: tagliando a posizione fissa l'IP arrivava
        # spezzato ("T 172.20" nella colonna IP, il resto sotto Client).
        text = (AP_SUMMARY.splitlines()[2] + "\n"
                + AP_SUMMARY.splitlines()[3] + "\n"
                + "ap-03  2  C9130-EXAMPLE-LONG-MODEL  aa:bb:cc:dd:ee:03  "
                  "una location molto lunga  IT  198.51.100.11  7\n")
        aps = wlc._table_rows(text, wlc._AP_FIELDS)
        self.assertEqual(aps[0]["ip"], "198.51.100.11")
        self.assertEqual(aps[0]["model"], "C9130-EXAMPLE-LONG-MODEL")
        self.assertEqual(aps[0]["clients"], "7")

    def test_no_table(self):
        self.assertEqual(wlc._table_rows("Incorrect usage. Use the '?'",
                                         wlc._AP_FIELDS), [])
        self.assertEqual(wlc._table_rows("", wlc._AP_FIELDS), [])

    def test_sysinfo(self):
        info = wlc.parse_sysinfo(SYSINFO)
        self.assertEqual(info["product version"], "8.5.999.0")
        self.assertIn("10 days", info["system up time"])


CLIENT_DETAIL_AIREOS = """Client MAC Address............................... aa:bb:cc:11:22:01
Client Username ................................. N/A
AP Name.......................................... ap-01
Client State..................................... Associated
Wireless LAN Id.................................. 1
IP Address....................................... 192.0.2.51
        Radio Signal Strength Indicator.......... -58 dBm
        Signal to Noise Ratio.................... 34 dB
"""

CLIENT_DETAIL_IOSXE = """Client MAC Address : aabb.cc11.2201
Client IPv4 Address : 192.0.2.52
Client IPv6 Addresses : fe80::1
AP Name: ap-01
Radio Signal Strength Indicator : -61 dBm
Signal to Noise Ratio : 30 dB
"""


class ClientDetailTest(unittest.TestCase):
    def test_aireos_dotted(self):
        d = wlc.parse_client_detail(CLIENT_DETAIL_AIREOS)
        self.assertEqual(d, {"ip": "192.0.2.51", "rssi": "-58", "snr": "34"})

    def test_iosxe_colon(self):
        d = wlc.parse_client_detail(CLIENT_DETAIL_IOSXE)
        self.assertEqual(d["ip"], "192.0.2.52")  # l'IPv6 non deve vincere
        self.assertEqual(d["rssi"], "-61")
        self.assertEqual(d["snr"], "30")

    def test_empty(self):
        self.assertEqual(wlc.parse_client_detail(""), {})


class ApAutoRfTest(unittest.TestCase):
    """Canale e larghezza di canale: 'show ap summary' non li ha, l'auto-RF
    della radio 5 GHz si."""

    def test_parses_channel_width_and_load(self):
        out = wlc.parse_ap_autorf(AP_AUTORF)
        self.assertEqual(out["channel"], "36")
        self.assertEqual(out["channel_width"], "40 Mhz")
        self.assertEqual(out["channel_utilization"], "12 %")
        self.assertEqual(out["noise_profile"], "PASSED")

    def test_average_energy_is_not_the_current_channel(self):
        # 'Current Channel Average Energy' contiene 'current channel': senza
        # l'esclusione il canale diventava '-83 dBm'.
        out = wlc.parse_ap_autorf(
            "    Current Channel Average Energy............... -83 dBm\n"
            "    Current Channel.............................. 149\n")
        self.assertEqual(out["channel"], "149")

    def test_empty(self):
        self.assertEqual(wlc.parse_ap_autorf(""), {})


class OverviewTest(unittest.TestCase):
    def _conn(self):
        return _FakeConn({"show ap summary": AP_SUMMARY,
                          "show client summary": CLIENT_SUMMARY,
                          "show wlan summary": WLAN_SUMMARY,
                          "show rogue ap summary": ROGUE_SUMMARY,
                          "show client detail aa:bb:cc:11:22:01":
                              CLIENT_DETAIL_AIREOS,
                          "show ap auto-rf 802.11a ap-01": AP_AUTORF})

    def test_clients_get_ip_rssi_snr_from_detail(self):
        # 'show client summary' non ha quelle colonne: senza il dettaglio per
        # client il tab mostrava '-' su IP, RSSI e SNR.
        conn = self._conn()
        with _patch_session("aireos", conn, SYSINFO):
            out = wlc.overview(AIREOS)
        first = out["clients"][0]
        self.assertEqual(first["ip"], "192.0.2.51")
        self.assertEqual(first["rssi"], "-58")
        self.assertEqual(first["snr"], "34")

    def test_wlan_id_becomes_ssid(self):
        # La colonna si chiama WLAN / SSID ma il summary da' solo il numero.
        conn = self._conn()
        with _patch_session("aireos", conn, SYSINFO):
            out = wlc.overview(AIREOS)
        self.assertEqual(out["clients"][0]["wlan"], "1 - corp-ssid")
        self.assertEqual(out["clients"][1]["wlan"], "2 - guest-ssid")

    def test_detail_is_capped(self):
        conn = self._conn()
        with mock.patch.object(wlc, "_CLIENT_DETAIL_LIMIT", 1):
            with _patch_session("aireos", conn, SYSINFO):
                out = wlc.overview(AIREOS)
        self.assertEqual(len(out["clients"]), 2)
        self.assertNotIn("rssi", out["clients"][1])
        self.assertEqual(
            sum(1 for c in conn.sent if c.startswith("show client detail")), 1)

    def test_aps_get_channel_and_width_from_autorf(self):
        conn = self._conn()
        with _patch_session("aireos", conn, SYSINFO):
            out = wlc.overview(AIREOS)
        self.assertEqual(out["aps"][0]["channel"], "36")
        self.assertEqual(out["aps"][0]["channel_width"], "40 Mhz")

    def test_autorf_is_capped_and_skipped_on_iosxe(self):
        conn = self._conn()
        with mock.patch.object(wlc, "_AP_AUTORF_LIMIT", 1):
            with _patch_session("aireos", conn, SYSINFO):
                wlc.overview(AIREOS)
        self.assertEqual(
            sum(1 for c in conn.sent if c.startswith("show ap auto-rf")), 1)

        # Il comando e' della CLI AireOS: un 9800 risponderebbe con un errore.
        conn = self._conn()
        with _patch_session("iosxe", conn, ""):
            wlc.overview(C9800)
        self.assertFalse([c for c in conn.sent if c.startswith("show ap auto-rf")])

    def test_ap_name_is_not_pasted_into_the_command_unchecked(self):
        # Il nome arriva dall'output del controller: una riga malformata non
        # deve poter allungare la CLI con un secondo comando.
        conn = _FakeConn({"show ap summary": _table(
            AP_COLS, [("ap-01;show run", 2, "AIR-EXAMPLE-1",
                       "aa:bb:cc:dd:ee:01", "loc", "IT", "192.0.2.21", 0)])})
        with _patch_session("aireos", conn, SYSINFO):
            wlc.overview(AIREOS)
        self.assertFalse([c for c in conn.sent if c.startswith("show ap auto-rf")])

    def test_aireos_overview(self):
        conn = self._conn()
        with _patch_session("aireos", conn, SYSINFO):
            out = wlc.overview(AIREOS)
        self.assertEqual(out["platform"], "aireos")
        self.assertEqual(out["version"], "8.5.999.0")
        self.assertEqual(out["ap_count"], 2)
        self.assertEqual(out["client_count"], 2)
        self.assertEqual(len(out["wlans"]), 2)
        self.assertEqual(len(out["rogues"]), 1)

    def test_one_failing_command_does_not_empty_the_rest(self):
        conn = self._conn()
        outputs = dict(conn.outputs)

        def boom(command, read_timeout=None):
            if command == "show rogue ap summary":
                raise RuntimeError("permission denied")
            conn.sent.append(command)
            return outputs.get(command, "")
        conn.send_command = boom
        with _patch_session("aireos", conn, SYSINFO):
            out = wlc.overview(AIREOS)
        self.assertEqual(out["ap_count"], 2)
        self.assertEqual(out["rogues"], [])
        self.assertIn("rogue_aps_error", out["raw"])


class DiagnoseTest(unittest.TestCase):
    def test_best_effort_sections(self):
        conn = _FakeConn()

        def boom(command, read_timeout=None):
            if command == "show rogue ap summary":
                raise RuntimeError("permission denied")
            conn.sent.append(command)
            return "ok"
        conn.send_command = boom
        with _patch_session("aireos", conn, SYSINFO):
            out = wlc.diagnose_wifi_client(AIREOS, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(out["platform"], "aireos")
        self.assertEqual(out["sections"]["client_detail"]["data"], "ok")
        self.assertIn("error", out["sections"]["rogue_aps"])
        # Una sola sessione, MAC normalizzato nel comando.
        self.assertIn("show client detail aa:bb:cc:dd:ee:ff", conn.sent)


if __name__ == "__main__":
    unittest.main()
