# -*- coding: utf-8 -*-
"""Parser Cisco IOS / IOS-XE con tracciamento di riga per il motore di audit.

IOS non e' key/value come FortiOS: una riga di configurazione E' il comando.
Fingere una struttura ``set <chiave> <valore>`` costringerebbe ogni regola a
disfarla di nuovo, quindi qui si conserva la riga com'e' e si aggiunge l'unica
struttura che IOS ha davvero: il rientro, che lega un comando al blocco che lo
contiene (``interface``, ``line``, ``router``, ...).

Non esiste un marcatore "questa riga apre un blocco": lo si sa solo perche'
qualcosa la segue con rientro maggiore. Quindi ogni riga e' un potenziale
header e ``blocks`` la mappa alle sue figlie dirette — quasi sempre nessuna.

Tollerante come il parser FortiOS: nessuna riga malformata solleva eccezioni.

Due costrutti richiedono attenzione perche' il loro CONTENUTO non e'
configurazione e verrebbe letto come tale:

  - ``banner motd ^C ... ^C`` — testo libero delimitato da un carattere scelto
    dall'operatore; dentro puo' esserci qualunque cosa, comprese righe che
    iniziano per ``no `` o ``ip ``.
  - ``crypto pki certificate chain`` — dump esadecimale chiuso da ``quit``.

Di entrambi resta la sola riga di apertura, che e' quanto serve alle regole
(CIS 1.3.x verifica che il banner ESISTA, non cosa dice).
"""

import re
from typing import Dict, List, NamedTuple, Optional, Tuple

_WS = re.compile(r"\s+")

# Un banner privo di delimitatore di chiusura mangerebbe tutto il resto del
# file e produrrebbe un audit tutto UNKNOWN. Oltre questo numero di righe si
# assume che il delimitatore manchi e si riprende a parsare: meglio qualche
# riga di testo interpretata male che l'intera configurazione persa.
_MAX_BANNER_LINES = 100


class IosLine(NamedTuple):
    """Una riga di configurazione con la sua posizione e il suo blocco."""
    line: int                  # 1-based, per l'evidenza nel report
    text: str                  # riga ripulita, maiuscole/minuscole originali
    lower: str                 # ``text`` minuscolo con spazi normalizzati
    path: Tuple[str, ...]      # header dei blocchi contenitori, minuscoli
    raw: str                   # riga originale, senza newline finale

    @property
    def parent(self) -> str:
        return self.path[-1] if self.path else ""

    @property
    def words(self) -> List[str]:
        return self.lower.split()


class IosConfig(NamedTuple):
    lines: List[IosLine]
    blocks: Dict[str, List[IosLine]]   # header minuscolo -> figlie dirette


def _norm(s: str) -> str:
    return _WS.sub(" ", s.strip()).lower()


def parse_ios(text: Optional[str]) -> IosConfig:
    lines: List[IosLine] = []
    blocks: Dict[str, List[IosLine]] = {}
    # (indent, header) dei blocchi aperti: l'indent e' quello dell'HEADER, le
    # figlie hanno indent maggiore.
    stack: List[Tuple[int, str]] = []
    banner_delim: Optional[str] = None
    banner_lines = 0
    in_cert = False

    for lineno, raw in enumerate((text or "").splitlines(), start=1):
        body = raw.rstrip("\r\n")
        stripped = body.strip()

        # --- corpi da saltare -------------------------------------------
        if banner_delim is not None:
            banner_lines += 1
            if banner_delim in body or banner_lines >= _MAX_BANNER_LINES:
                banner_delim = None
            continue
        if in_cert:
            if stripped.lower() == "quit":
                in_cert = False
            continue

        if not stripped or stripped.startswith("!"):
            continue

        low = _norm(stripped)
        indent = len(body) - len(body.lstrip(" \t"))

        # Chiude i blocchi il cui contenuto e' finito.
        while stack and indent <= stack[-1][0]:
            stack.pop()

        entry = IosLine(line=lineno, text=stripped, lower=low,
                        path=tuple(h for _, h in stack), raw=body)
        lines.append(entry)
        if stack:
            blocks.setdefault(stack[-1][1], []).append(entry)

        # --- apertura di costrutti a corpo libero ------------------------
        if low.startswith("banner "):
            # 'banner motd ^C' -> delimitatore '^C'. Puo' anche chiudersi
            # sulla stessa riga: 'banner motd #testo#'.
            parts = stripped.split(None, 2)
            if len(parts) >= 3 and parts[2]:
                delim = parts[2][:2] if parts[2].startswith("^") else parts[2][:1]
                if parts[2].count(delim) < 2:
                    banner_delim, banner_lines = delim, 0
            continue
        if low.startswith("certificate "):
            in_cert = True
            continue

        blocks.setdefault(low, [])
        stack.append((indent, low))

    return IosConfig(lines=lines, blocks=blocks)


# --- interrogazioni -----------------------------------------------------------

def is_empty(cfg: IosConfig) -> bool:
    return not cfg.lines


def find(cfg: IosConfig, *prefixes: str) -> List[IosLine]:
    """Righe (a qualunque livello) che iniziano con uno dei prefissi."""
    pref = tuple(_norm(p) for p in prefixes)
    return [l for l in cfg.lines if l.lower.startswith(pref)]


def find_top(cfg: IosConfig, *prefixes: str) -> List[IosLine]:
    """Come ``find`` ma solo sui comandi globali (fuori da ogni blocco)."""
    pref = tuple(_norm(p) for p in prefixes)
    return [l for l in cfg.lines if not l.path and l.lower.startswith(pref)]


def first_top(cfg: IosConfig, *prefixes: str) -> Optional[IosLine]:
    hits = find_top(cfg, *prefixes)
    return hits[0] if hits else None


def has_top(cfg: IosConfig, *prefixes: str) -> bool:
    return bool(find_top(cfg, *prefixes))


def blocks_matching(cfg: IosConfig,
                    prefix: str) -> List[Tuple[str, List[IosLine]]]:
    """(header, figlie) di ogni blocco il cui header inizia con ``prefix``.

    Ordinati per riga dell'header, cosi' il report cita i blocchi nell'ordine
    in cui compaiono nel file.
    """
    p = _norm(prefix)
    out = [(h, kids) for h, kids in cfg.blocks.items() if h.startswith(p)]
    out.sort(key=lambda hk: block_header_line(cfg, hk[0]))
    return out


def block_header_line(cfg: IosConfig, header: str) -> int:
    """Numero di riga dell'header di blocco, 0 se non trovato."""
    h = _norm(header)
    for l in cfg.lines:
        if l.lower == h:
            return l.line
    return 0


def child(kids: List[IosLine], *prefixes: str) -> Optional[IosLine]:
    """Prima figlia che inizia con uno dei prefissi."""
    pref = tuple(_norm(p) for p in prefixes)
    for k in kids:
        if k.lower.startswith(pref):
            return k
    return None
