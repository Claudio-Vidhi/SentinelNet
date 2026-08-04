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
import os
import tempfile

os.environ["SENTINELNET_DATA_DIR"] = tempfile.mkdtemp(prefix="sentinelnet_tests_")
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-suite")
