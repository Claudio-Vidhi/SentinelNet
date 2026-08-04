# -*- coding: utf-8 -*-
"""La suite non deve MAI scrivere nella cartella ``data/`` del repository.

Questo test e' la rete che mancava quando ``test_remote_site`` ha sovrascritto
l'hash della password dell'amministratore reale: i moduli risolvono i propri
percorsi a import time, quindi un solo file di test che importi l'app senza
aver impostato ``SENTINELNET_DATA_DIR`` dirotta l'INTERA suite sui dati veri.
Il guard sta in ``tests/__init__.py``; qui si verifica che regga.
"""
import os
import unittest

from core import data_config
from security import security_manager, user_manager

REAL_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"
)


def _inside_real_data(path: str) -> bool:
    return os.path.abspath(path).startswith(os.path.abspath(REAL_DATA_DIR) + os.sep)


class TestDataIsolation(unittest.TestCase):

    def test_state_paths_resolved_at_import_are_isolated(self):
        # Costanti legate all'import del modulo: sono quelle che si sono
        # rivelate pericolose, perche' il primo import vince per tutto il processo.
        for name, path in (("USERS_JSON", user_manager.USERS_JSON),
                           ("AUDIT_LOG_FILE", security_manager.AUDIT_LOG_FILE)):
            with self.subTest(constant=name):
                self.assertFalse(
                    _inside_real_data(path),
                    f"{name} punta ai dati reali ({path}): l'isolamento della "
                    "suite e' saltato, un test puo' sovrascrivere le credenziali "
                    "di produzione."
                )

    def test_paths_resolved_at_call_time_are_isolated(self):
        self.assertFalse(_inside_real_data(data_config.get_path("users.json")))


if __name__ == "__main__":
    unittest.main()
