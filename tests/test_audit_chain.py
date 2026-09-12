# -*- coding: utf-8 -*-
"""S2 — evidenza di manomissione del registro di audit.

Il registro era un file di testo in append senza niente che legasse la riga
n alla n-1: chi poteva scriverci poteva riscriverlo. Ogni riga porta adesso
un HMAC-SHA256 della riga precedente piu' la propria, con una chiave derivata
dal segreto JWT (che sta in un file con ACL al solo proprietario).

Cosa prova e cosa NON prova, dichiarato: rileva la MODIFICA di una riga, non
il troncamento della coda ne' la cancellazione del file. Per quello serve un
sink esterno, che e' un'altra funzionalita'.
"""

import os
import shutil
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_auditchain_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from security import security_manager  # noqa: E402


class TestAuditChain(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def _path(self):
        return security_manager.AUDIT_LOG_FILE

    def _write(self, *messages):
        for m in messages:
            security_manager.log_audit(m)
        for h in security_manager.audit_logger.handlers:
            h.flush()

    def _lines(self):
        with open(self._path(), "r", encoding="utf-8") as f:
            return f.read().splitlines()

    def _rewrite(self, lines):
        with open(self._path(), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def test_every_line_carries_a_chain_tag(self):
        self._write("LOGIN: utente 'mario'")
        self.assertRegex(self._lines()[-1], r"\[chain:[0-9a-f]{64}\]$")

    def test_an_untouched_log_verifies(self):
        self._write("primo", "secondo", "terzo")
        self.assertIsNone(security_manager.verify_audit_chain(self._path()))

    def test_a_modified_line_is_named(self):
        self._write("prima", "DA-CAMBIARE", "dopo")
        lines = self._lines()
        target = next(i for i, l in enumerate(lines) if "DA-CAMBIARE" in l)
        lines[target] = lines[target].replace("DA-CAMBIARE", "innocuo")
        self._rewrite(lines)
        self.assertEqual(security_manager.verify_audit_chain(self._path()),
                         target + 1)

    def test_a_forged_timestamp_is_caught_too(self):
        """Il tag copre la riga RESA, timestamp compreso: spostare l'ora di un
        evento e' una manomissione come cambiarne il testo."""
        self._write("evento con ora")
        lines = self._lines()
        lines[-1] = "1999-01-01 00:00:00,000" + lines[-1][23:]
        self._rewrite(lines)
        self.assertEqual(security_manager.verify_audit_chain(self._path()),
                         len(lines))

    def test_a_line_dropped_from_the_middle_is_caught(self):
        self._write("uno", "due", "tre")
        lines = self._lines()
        del lines[-2]
        self._rewrite(lines)
        self.assertEqual(security_manager.verify_audit_chain(self._path()),
                         len(lines))

    def test_legacy_lines_without_a_tag_are_skipped_not_failed(self):
        """Un registro esistente non ha tag: dichiararlo manomesso sarebbe un
        falso positivo su ogni installazione aggiornata."""
        with open(self._path(), "w", encoding="utf-8") as f:
            f.write("2026-01-01 00:00:00,000 - [AUDIT] - riga vecchia\n")
        security_manager._chain_prev = None
        self._write("riga nuova")
        self.assertIsNone(security_manager.verify_audit_chain(self._path()))

    def test_the_chain_resumes_from_the_file_after_a_restart(self):
        self._write("prima del restart")
        security_manager._chain_prev = None       # come un processo appena avviato
        self._write("dopo il restart")
        self.assertIsNone(security_manager.verify_audit_chain(self._path()))

    def test_a_missing_log_is_not_an_error(self):
        self.assertIsNone(security_manager.verify_audit_chain(
            os.path.join(_TMP_DATA_DIR, "non-esiste.log")))

    def setUp(self):
        # Ogni test parte da un registro proprio: la catena e' per-file. Su
        # Windows il file non si cancella mentre l'handler lo tiene aperto,
        # quindi lo stream va chiuso PRIMA e riaperto dopo.
        for h in security_manager.audit_logger.handlers:
            if getattr(h, "stream", None):
                h.close()
        if os.path.exists(self._path()):
            os.remove(self._path())
        security_manager._chain_prev = None


if __name__ == "__main__":
    unittest.main()
