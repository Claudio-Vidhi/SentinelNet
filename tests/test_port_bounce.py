# -*- coding: utf-8 -*-
"""Port bounce: l'unica scrittura della diagnosi.

I cancelli non sono formalita'. La porta arriva da una MAC table scansionata a
mano: su un dato vecchio la porta di oggi puo' essere di un altro utente, e
staccare quello sbagliato e' un guasto causato dallo strumento che doveva
ripararne uno.
"""

import unittest
from unittest.mock import patch

from services import client_diagnosis, port_action

SWITCH = {"IP": "192.0.2.20", "Vendor": "cisco", "Group": "sede-a"}


def _pos(age_s, switch_ip="192.0.2.20", port="GigabitEthernet1/0/5"):
    import datetime
    ts = (datetime.datetime.now() - datetime.timedelta(seconds=age_s)).isoformat()
    return {"known": True, "mac": "aa:bb:cc:dd:ee:ff", "switch_ip": switch_ip,
            "switch_port": port, "port_last_seen": ts, "binding_last_seen": ts}


class TestVerifyPort(unittest.TestCase):

    def _verify(self, pos, **kw):
        with patch.object(client_diagnosis, "_position", return_value=pos):
            return client_diagnosis.verify_port(
                "aa:bb:cc:dd:ee:ff", kw.pop("switch_ip", "192.0.2.20"),
                kw.pop("interface", "GigabitEthernet1/0/5"),
                max_age_s=kw.pop("max_age_s", 900))

    def test_fresh_and_matching_passes(self):
        self.assertTrue(self._verify(_pos(60))["ok"])

    def test_abbreviated_interface_still_matches(self):
        # La diagnosi mostra 'GigabitEthernet1/0/5', l'operatore digita
        # 'Gi1/0/5': e' la stessa porta, e rifiutarla sarebbe solo pedanteria.
        self.assertTrue(self._verify(_pos(60), interface="Gi1/0/5")["ok"])

    def test_stale_position_is_refused(self):
        out = self._verify(_pos(7200))
        self.assertFalse(out["ok"])
        self.assertIn("scansione MAC", out["reason"])

    def test_a_client_that_moved_port_is_refused(self):
        out = self._verify(_pos(60, port="GigabitEthernet1/0/9"))
        self.assertFalse(out["ok"])
        self.assertIn("rilancia la diagnosi", out["reason"])

    def test_a_client_on_another_switch_is_refused(self):
        out = self._verify(_pos(60, switch_ip="192.0.2.30"))
        self.assertFalse(out["ok"])
        self.assertIn("192.0.2.30", out["reason"])

    def test_an_unknown_client_is_refused(self):
        out = self._verify({"known": False})
        self.assertFalse(out["ok"])
        self.assertIn("sconosciuta", out["reason"])


class TestBounceCommands(unittest.TestCase):

    def test_cisco_pair(self):
        down, up = port_action._build("cisco_ios", "Gi1/0/5")
        self.assertEqual(down, ["interface Gi1/0/5", "shutdown"])
        self.assertEqual(up, ["interface Gi1/0/5", "no shutdown"])

    def test_procurve_uses_disable_enable(self):
        down, up = port_action._build("hp_procurve", "A7")
        self.assertEqual(down[-1], "disable")
        self.assertEqual(up[-1], "enable")

    def test_an_unverified_vendor_is_refused_not_guessed(self):
        # Indovinare la sintassi su uno switch in produzione e' peggio che
        # dire di no: e' la stessa regola che il progetto applica ai sottotipi
        # di log e agli intervalli di date.
        with self.assertRaises(port_action.PortActionError) as e:
            port_action._build("juniper_junos", "ge-0/0/5")
        self.assertIn("non è verificata", str(e.exception))

    def test_an_interface_name_cannot_smuggle_a_second_command(self):
        # L'interfaccia arriva da un JSON: senza questo controllo un a capo
        # infilerebbe un comando arbitrario dentro la sessione di config.
        for bad in ("Gi1/0/5\nshutdown", "Gi1/0/5; reload", "", "../x",
                    "1/0/5", "Gi1/0/5 no shutdown"):
            with self.subTest(bad=bad), self.assertRaises(port_action.PortActionError):
                port_action._build("cisco_ios", bad)

    def test_a_failed_no_shutdown_is_reported_loudly(self):
        # E' l'unico esito che lascia la rete peggio di come l'ha trovata:
        # deve uscire dalla funzione, non restare in un log.
        class _Conn:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def enable(self): pass
            def send_config_set(self, cmds):
                if cmds[-1] == "no shutdown":
                    raise OSError("sessione caduta")
                return "ok"

        with patch("netmiko.ConnectHandler", return_value=_Conn()), \
             patch("core.core_engine.get_device_credentials",
                   return_value=("u", "p", "s")):
            res = port_action.bounce(SWITCH, "Gi1/0/5", wait_s=0)
        self.assertTrue(res["down_ok"])
        self.assertFalse(res["up_ok"])
        self.assertIn("NON riaccesa", res["error"])


if __name__ == "__main__":
    unittest.main()
