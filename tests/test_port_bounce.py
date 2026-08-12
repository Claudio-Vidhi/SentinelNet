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


class TestPortIsolation(unittest.TestCase):
    """L'isolamento persistente: stessi cancelli del bounce, ma la porta resta
    giu'. Un rifiuto qui e' sempre meglio di un ramo di rete staccato."""

    def _call(self, action="shutdown", client_mac="aa:bb:cc:dd:ee:ff",
              port="GigabitEthernet1/0/5", uplinks=None, verify=None):
        from fastapi import HTTPException
        from routers import mac as mac_router
        from services import client_diagnosis as cd, port_action as pa

        payload = mac_router.PortControlSchema(
            ip="192.0.2.20", port=port, action=action, client_mac=client_mac)
        sent = {}

        def _fake_set(device, interface, up):
            sent.update(interface=interface, up=up)
            return {"output": "ok", "admin_up": up}

        with patch.object(mac_router, "assert_device_allowed", return_value=SWITCH), \
             patch.object(mac_router, "log_audit"), \
             patch.object(mac_router, "user_group_scope", return_value=None), \
             patch.object(mac_router.mac_history, "topology_uplinks",
                          return_value=(uplinks or {}, set())), \
             patch.object(cd, "verify_port",
                          return_value=verify or {"ok": True, "age_s": 30}) as vp, \
             patch.object(pa, "set_admin_state", side_effect=_fake_set):
            try:
                out = mac_router.mac_port_control(payload, {"sub": "adm"})
            except HTTPException as e:
                return e, sent, vp
        return out, sent, vp

    def test_an_uplink_is_refused(self):
        # Spegnere una porta che va verso un altro apparato non isola un
        # client: stacca tutto quello che ci sta dietro.
        from core import core_engine
        uplinks = {"192.0.2.20": {
            core_engine._normalize_iface("GigabitEthernet1/0/48"): "switch-02"}}
        err, sent, _ = self._call(port="Gi1/0/48", uplinks=uplinks)
        self.assertEqual(err.status_code, 409)
        self.assertIn("uplink", err.detail)
        self.assertIn("switch-02", err.detail)
        self.assertEqual(sent, {})          # niente e' arrivato all'apparato

    def test_shutdown_without_the_client_mac_is_refused(self):
        # Senza MAC non c'e' nulla da verificare: la porta sarebbe spenta
        # sulla fiducia in una MAC table di eta' ignota.
        err, sent, _ = self._call(client_mac=None)
        self.assertEqual(err.status_code, 400)
        self.assertIn("client_mac", err.detail)
        self.assertEqual(sent, {})

    def test_a_stale_position_is_refused(self):
        err, sent, _ = self._call(
            verify={"ok": False, "reason": "posizione vecchia di 7200s "
                                           "(soglia 900s): rilancia una scansione MAC"})
        self.assertEqual(err.status_code, 409)
        self.assertIn("scansione MAC", err.detail)
        self.assertEqual(sent, {})

    def test_shutdown_reaches_the_device_when_both_gates_pass(self):
        out, sent, _ = self._call()
        self.assertEqual(out["action"], "shutdown")
        self.assertEqual(sent, {"interface": "GigabitEthernet1/0/5", "up": False})

    def test_reenabling_asks_neither_mac_nor_freshness(self):
        # E' la via di ritorno: deve funzionare anche quando la posizione del
        # client non si sa piu'. Un isolamento che non si toglie e' un guasto.
        out, sent, vp = self._call(action="no-shutdown", client_mac=None)
        self.assertEqual(out["action"], "no-shutdown")
        self.assertEqual(sent, {"interface": "GigabitEthernet1/0/5", "up": True})
        vp.assert_not_called()

    def test_the_route_is_admin_only(self):
        # Entra in modalita' di configurazione e lascia la porta giu': stessa
        # categoria del bounce, non quella di una lettura.
        import inspect
        from routers import mac as mac_router
        from routers.deps import require_admin

        dep = inspect.signature(
            mac_router.mac_port_control).parameters["current_user"].default
        self.assertIs(dep.dependency, require_admin)


if __name__ == "__main__":
    unittest.main()
