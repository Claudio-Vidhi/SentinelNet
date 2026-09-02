# -*- coding: utf-8 -*-
"""L'albero tracciato non contiene dati di un cliente reale.

Questo test esiste perche' `master` e `Dev` hanno lo stesso contenuto: non c'e'
piu' uno strip che, di sponda, teneva fuori dal pubblico i file di sviluppo.
Il confine della privacy e' `git add`, e un confine senza un controllo che lo
sorvegli si sposta da solo.

La logica sta in scripts/check_no_private_data.py, che si esegue anche a mano.
"""
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_no_private_data as checker  # noqa: E402


class TrackedTreeIsClean(unittest.TestCase):
    def test_no_private_data_in_the_tracked_tree(self):
        problems = checker.scan()
        self.assertEqual(
            problems, [],
            "Dati privati nell'albero tracciato:\n"
            + "\n".join(f"  {rel}:{line}: {what}" for rel, line, what in problems))

    def test_the_state_files_are_ignored_not_merely_absent(self):
        # Un file di stato assente oggi ma NON ignorato torna tracciabile al
        # primo `git add -A` dopo che lo strumento ha girato sulla rete di un
        # cliente. La domanda giusta e' "git lo ignorerebbe?", non "c'e'?".
        for name in ("data/sites.json", "data/users.json", "network_hosts.csv",
                     "data/mac_history.db", "data/identities.json",
                     "agent-data/network_hosts.csv", "data/security/x.md"):
            r = subprocess.run(["git", "check-ignore", "-q", name],
                               cwd=ROOT, capture_output=True)
            self.assertEqual(r.returncode, 0, f"{name} non e' ignorato da git")

    def test_the_scanner_recognises_a_real_looking_address(self):
        # Se il riconoscitore smettesse di funzionare, il test sopra passerebbe
        # sempre e non direbbe piu' nulla.
        self.assertFalse(checker._is_allowed_ip("93.184.216.34"))
        self.assertTrue(checker._is_allowed_ip("192.0.2.10"))
        self.assertTrue(checker._is_allowed_ip("10.9.0.1"))
        self.assertTrue(checker._is_allowed_ip("198.51.100.7"))


if __name__ == "__main__":
    unittest.main()
