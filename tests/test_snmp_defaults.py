# -*- coding: utf-8 -*-
"""Community SNMP gerarchica: default di tenant, override per apparato.

La regola in una riga: l'apparato vince sul tenant, e il flag di esclusione
vince su entrambi. "Non impostata" e "spenta di proposito" sono due cose
diverse — prima coincidevano, ed e' il motivo per cui il flag esiste:
altrimenti attivare un default comincerebbe a interrogare apparati che erano
volutamente fuori.
"""

import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_snmpdef_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from security import snmp_defaults  # noqa: E402
from security.crypto_vault import encrypt_password  # noqa: E402


def _device(ip="192.0.2.1", group="sede-a", community=None, disabled=""):
    d = {"IP": ip, "Group": group, "SNMP Disabled": disabled}
    if community is not None:
        d["SNMP Community"] = encrypt_password(community)
    return d


class _Base(unittest.TestCase):
    def setUp(self):
        # "Generale" compreso: TENANT_SNMP_JSON e' fissata all'import del
        # modulo (come identities.json), quindi lo stato lasciato qui vive
        # anche per i moduli di test importati dopo questo.
        snmp_defaults.set_tenant_community("sede-a", "")
        snmp_defaults.set_tenant_community("sede-b", "")
        snmp_defaults.set_tenant_community("Generale", "")


class TestStore(_Base):

    def test_scrittura_e_rilettura(self):
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")

        self.assertEqual(snmp_defaults.get_tenant_community("sede-a"),
                         "esempio-community")

    def test_tenant_senza_default(self):
        self.assertEqual(snmp_defaults.get_tenant_community("sede-b"), "")

    def test_stringa_vuota_rimuove(self):
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")
        snmp_defaults.set_tenant_community("sede-a", "")

        self.assertEqual(snmp_defaults.get_tenant_community("sede-a"), "")
        self.assertNotIn("sede-a", snmp_defaults.tenants_with_default())

    def test_il_segreto_non_e_in_chiaro_su_disco(self):
        """Cifrata nel vault come ogni altra credenziale del progetto."""
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")

        with open(snmp_defaults.TENANT_SNMP_JSON, encoding="utf-8") as fh:
            self.assertNotIn("esempio-community", fh.read())

    def test_l_elenco_espone_i_nomi_non_i_segreti(self):
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")

        self.assertEqual(snmp_defaults.tenants_with_default(), {"sede-a"})


class TestPrecedenza(_Base):

    def test_l_apparato_vince_sul_tenant(self):
        snmp_defaults.set_tenant_community("sede-a", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community(_device(community="propria")),
            "propria")

    def test_senza_community_eredita_dal_tenant(self):
        snmp_defaults.set_tenant_community("sede-a", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community(_device(community="")),
            "del-tenant")

    def test_campo_assente_eredita_come_campo_vuoto(self):
        """Le righe di hosts.csv scritte prima di questa colonna non hanno la
        chiave: assente e vuoto devono comportarsi uguale."""
        snmp_defaults.set_tenant_community("sede-a", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community({"IP": "192.0.2.1", "Group": "sede-a"}),
            "del-tenant")

    def test_senza_niente_non_si_interroga(self):
        self.assertEqual(
            snmp_defaults.resolve_snmp_community(_device(community="")), "")

    def test_il_flag_di_esclusione_vince_su_tutto(self):
        """Anche con una community propria: 'mai interrogare' e' un'istruzione
        esplicita, non un ripiego."""
        snmp_defaults.set_tenant_community("sede-a", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community(
                _device(community="propria", disabled="1")), "")

    def test_il_default_e_per_tenant_non_globale(self):
        """Un tenant non eredita il default di un altro: sono reti diverse."""
        snmp_defaults.set_tenant_community("sede-a", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community(
                _device(group="sede-b", community="")), "")

    def test_tenant_mancante_sul_device(self):
        """Group vuoto = 'Generale', come ovunque nell'inventario."""
        snmp_defaults.set_tenant_community("Generale", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community({"IP": "192.0.2.1"}),
            "del-tenant")


class TestPollerUsaLaRisoluzione(_Base):
    """Il poller e' l'unico consumatore runtime della community: se non passa
    dalla risoluzione condivisa, l'ereditarieta' non esiste per nessuno."""

    def test_il_poller_include_un_apparato_che_eredita(self):
        from unittest.mock import patch
        from observability.ingesters import snmp_poller

        snmp_defaults.set_tenant_community("sede-a", "del-tenant")
        devices = [_device(ip="192.0.2.1", group="sede-a", community="")]

        with patch("services.inventory_manager.get_all_devices",
                   return_value=devices):
            out = snmp_poller._snmp_devices()

        self.assertEqual([d["ip"] for d in out], ["192.0.2.1"])
        self.assertEqual(out[0]["community"], "del-tenant")

    def test_il_poller_salta_un_apparato_escluso(self):
        from unittest.mock import patch
        from observability.ingesters import snmp_poller

        snmp_defaults.set_tenant_community("sede-a", "del-tenant")
        devices = [_device(ip="192.0.2.1", group="sede-a",
                           community="propria", disabled="1")]

        with patch("services.inventory_manager.get_all_devices",
                   return_value=devices):
            self.assertEqual(snmp_poller._snmp_devices(), [])


class TestRotte(_Base):
    """La community non esce MAI da un'API di lettura, nemmeno cifrata."""

    def setUp(self):
        super().setUp()
        from routers import settings as settings_router
        self.router = settings_router

    def test_la_lettura_espone_solo_i_nomi(self):
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")

        out = self.router.snmp_defaults_get(
            current_user={"sub": "a", "role": "admin"})

        self.assertEqual(out["tenants"], ["sede-a"])
        # Ne' in chiaro ne' cifrata: la risposta e' fatta di soli nomi.
        self.assertNotIn("esempio-community", repr(out))
        self.assertEqual(set(out.keys()), {"tenants"})

    def test_la_lettura_e_ristretta_ai_tenant_dell_utente(self):
        from unittest.mock import patch
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")
        snmp_defaults.set_tenant_community("sede-b", "altra-community")

        with patch("routers.settings.user_group_scope", return_value={"sede-a"}):
            out = self.router.snmp_defaults_get(
                current_user={"sub": "v", "role": "viewer"})

        self.assertEqual(out["tenants"], ["sede-a"])

    def test_la_scrittura_imposta_il_default(self):
        from routers.settings import SnmpDefaultSchema

        self.router.snmp_defaults_set(
            SnmpDefaultSchema(tenant="sede-a", community="esempio-community"),
            current_user={"sub": "a", "role": "admin"})

        self.assertEqual(snmp_defaults.get_tenant_community("sede-a"),
                         "esempio-community")

    def test_la_scrittura_vuota_rimuove(self):
        from routers.settings import SnmpDefaultSchema
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")

        self.router.snmp_defaults_set(
            SnmpDefaultSchema(tenant="sede-a", community=""),
            current_user={"sub": "a", "role": "admin"})

        self.assertEqual(snmp_defaults.get_tenant_community("sede-a"), "")

    def test_tenant_fuori_scope_e_403(self):
        from fastapi import HTTPException
        from routers.settings import SnmpDefaultSchema
        from unittest.mock import patch

        with patch("routers.settings.user_group_scope", return_value={"sede-a"}):
            with self.assertRaises(HTTPException) as ctx:
                self.router.snmp_defaults_set(
                    SnmpDefaultSchema(tenant="sede-b", community="x"),
                    current_user={"sub": "a", "role": "operator"})
        self.assertEqual(ctx.exception.status_code, 403)


class TestRotteSmoke(unittest.TestCase):
    """Regola di .agents/AGENTS.md: una rotta nuova va colpita DAVVERO via
    TestClient — chiamare la funzione del handler non esegue i Depends e
    nasconde NameError/ImportError. 401 basta: prova che il codice gira
    (precedente: tests/test_ai_conversations.py, stesso pattern)."""

    def test_le_rotte_rispondono_anche_senza_autenticazione(self):
        from fastapi.testclient import TestClient
        import app_server

        client = TestClient(app_server.app)
        self.assertEqual(401, client.get(
            "/api/settings/snmp-defaults").status_code)
        self.assertEqual(401, client.post(
            "/api/settings/snmp-defaults",
            json={"tenant": "sede-a", "community": "x"}).status_code)


if __name__ == "__main__":
    unittest.main()
