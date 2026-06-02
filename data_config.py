import os

# Leggi la directory dati dall'ambiente (es. '/app/data' in Docker)
DATA_DIR = os.getenv("SENTINELNET_DATA_DIR", "")

def get_path(filename: str) -> str:
    """
    Risolve il percorso assoluto o relativo di un file di configurazione o database.
    Se SENTINELNET_DATA_DIR è definita, crea la cartella se non esiste e vi posiziona il file.
    Altrimenti, mantiene il comportamento locale classico (relativo alla directory corrente).
    """
    if DATA_DIR:
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
        except Exception:
            pass
        return os.path.join(DATA_DIR, filename)
    return filename
