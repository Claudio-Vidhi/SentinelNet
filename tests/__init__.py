# -*- coding: utf-8 -*-
"""Isolamento dei dati per l'intera suite: nessun test tocca mai ``data/`` reale.

I moduli dell'app legano i propri percorsi a import time
(``user_manager.USERS_JSON``, ``security_manager.AUDIT_LOG_FILE``, ...): il
PRIMO import vince per tutto il processo. La convenzione "ogni file di test
imposta SENTINELNET_DATA_DIR prima degli import" non basta, perche' basta UN
file che importi l'app senza averlo fatto — a quel punto l'intera suite scrive
nella cartella reale, anche i file che si isolano correttamente.

E' successo davvero: ``test_remote_site`` ha sovrascritto l'hash bcrypt
dell'account admin di produzione con la propria password di test, chiudendo
fuori l'utente. Qui la directory viene imposta prima di qualunque import di
modulo dell'app, perche' unittest importa il pacchetto ``tests`` per primo in
entrambe le forme documentate (``discover -s tests`` e ``-m tests.test_x``).

Sovrascrittura incondizionata, non ``setdefault``: una variabile ereditata
dall'ambiente punterebbe ai dati veri proprio su una macchina di produzione.
I file che si impostano una propria temporanea continuano a funzionare — il
loro import avviene dopo questo.
"""
import atexit
import os
import shutil
import tempfile
import bcrypt

# Every test module makes its own mkdtemp and none clean up: %TEMP% had ~44k
# leftover dirs, and mkdtemp slows down as that directory fills. This module is
# imported before any test module, so pointing tempfile here catches all of
# them, and one sweep at exit removes the run. Best-effort: a run that leaves a
# SQLite handle open keeps its dir.
_RUN_TMP = tempfile.mkdtemp(prefix="sentinelnet_run_")
tempfile.tempdir = _RUN_TMP


@atexit.register
def _sweep_run_tmp():
    # ignore_errors: the observability writer is a daemon thread and may still
    # hold a WAL file open, which Windows refuses to unlink.
    shutil.rmtree(_RUN_TMP, ignore_errors=True)


os.environ["SENTINELNET_DATA_DIR"] = tempfile.mkdtemp(prefix="sentinelnet_tests_")
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-suite")

# rounds=12 is the production work factor and costs ~180ms per hash by design;
# rounds=4 costs under 1ms. The suite creates users in most of its files, so
# that difference was most of the wall time. Safe here because no test asserts
# on a production hash: every hash a test verifies is one the same test made.
# The override ignores the caller's rounds on purpose — security/user_manager.py
# passes rounds=12 explicitly, and honouring it would exempt the hot path.
_orig_gensalt = bcrypt.gensalt


def _fast_gensalt(rounds=4, prefix=b"2b"):
    return _orig_gensalt(rounds=4, prefix=prefix)


bcrypt.gensalt = _fast_gensalt

