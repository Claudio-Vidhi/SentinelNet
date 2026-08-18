# -*- coding: utf-8 -*-
"""Unit test per la modalità sito 'jump' (data model, Task 1 del piano
jump-host-sites). Nessun tunnel qui: solo i campi del bastion sul dict sito.

Isola SENTINELNET_DATA_DIR in una dir temporanea PRIMA di importare
site_manager, come test_sites.py / test_remote_site.py: SITES_JSON è risolto
via core.data_config.get_path all'import del modulo, quindi impostare la env
var dopo non avrebbe effetto.
"""
import os
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="sentinelnet_jump_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from services import site_manager  # noqa: E402


class JumpSiteModel(unittest.TestCase):
    def test_create_jump_site_keeps_fields_and_issues_no_token(self):
        site, token = site_manager.create_site(
            "Customer A", "jump", subnets=["192.0.2.0/24"],
            jump_host="198.51.100.10", jump_port=22, jump_identity="id-1")
        self.assertIsNone(token)
        self.assertEqual(site["mode"], "jump")
        self.assertEqual(site["jump_host"], "198.51.100.10")
        self.assertEqual(site["jump_port"], 22)
        self.assertEqual(site["jump_identity"], "id-1")

    def test_jump_site_without_host_is_rejected(self):
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer B", "jump", jump_identity="id-1")


if __name__ == "__main__":
    unittest.main()
