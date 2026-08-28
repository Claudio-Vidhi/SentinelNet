# -*- coding: utf-8 -*-
"""Parser dell'artefatto di backup Linux, con tracciamento di riga.

L'artefatto non e' una configurazione unica come su IOS o FortiOS: e' la
concatenazione di piu' file di sistema, prodotta da ``drivers/linux.py``, dove
ogni file e' introdotto da un marcatore ``--- <percorso> ---``. Quindi qui non
si interpreta una grammatica — si RIDIVIDE l'artefatto nei file che lo
compongono, e ogni regola guarda solo il file che la riguarda: una direttiva
``PermitRootLogin`` letta da ``/etc/hosts`` non significherebbe niente.

Non c'e' la macchina dei blocchi rientrati del parser IOS: nessuno di questi
file usa il rientro per legare una direttiva a un contenitore.

Tollerante come gli altri due parser: nessuna riga malformata solleva
eccezioni, e un marcatore sconosciuto crea semplicemente una sezione in piu'.

SEZIONI NON-FILE — la stessa sessione di triage appende anche l'esito di alcuni
comandi (``--- HOSTNAME ---``, ``--- SSHD EFFECTIVE CONFIG ---``). Restano
raggiungibili con la loro chiave: ``sshd -T`` e' la configurazione EFFETTIVA di
sshd, e quando c'e' vale piu' del file, perche' tiene conto delle direttive
``Include``.
"""

import re
from typing import Dict, List, NamedTuple, Optional

_WS = re.compile(r"\s+")
_MARKER = re.compile(r'^---\s+(\S.*?)\s+---\s*$')

# Chiave sotto cui finisce la sezione dell'output di ``sshd -T``.
SSHD_EFFECTIVE = "sshd -T"
_SECTION_ALIASES = {"SSHD EFFECTIVE CONFIG": SSHD_EFFECTIVE}


class LinuxLine(NamedTuple):
    """Una riga di un file di configurazione, con la sua posizione."""
    line: int                  # 1-based nell'ARTEFATTO, per l'evidenza
    text: str                  # riga ripulita, maiuscole/minuscole originali
    lower: str                 # ``text`` minuscolo con spazi normalizzati
    raw: str                   # riga originale, senza newline finale

    @property
    def words(self) -> List[str]:
        return self.lower.split()


class LinuxConfig(NamedTuple):
    lines: List[LinuxLine]                 # tutte le righe utili dell'artefatto
    files: Dict[str, List[LinuxLine]]      # percorso (o comando) -> sue righe


def _norm(s: str) -> str:
    return _WS.sub(" ", s.strip()).lower()


def parse_linux(text: Optional[str]) -> LinuxConfig:
    lines: List[LinuxLine] = []
    files: Dict[str, List[LinuxLine]] = {}
    current: Optional[List[LinuxLine]] = None

    for lineno, raw in enumerate((text or "").splitlines(), start=1):
        body = raw.rstrip("\r\n")
        stripped = body.strip()

        marker = _MARKER.match(stripped)
        if marker:
            name = marker.group(1)
            name = _SECTION_ALIASES.get(name.upper(), name)
            current = files.setdefault(name, [])
            continue

        # Commenti: una direttiva commentata NON e' impostata — tenerla
        # produrrebbe un PASS su un file dove non c'e' scritto niente.
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        entry = LinuxLine(line=lineno, text=stripped, lower=_norm(stripped),
                          raw=body)
        lines.append(entry)
        if current is not None:
            current.append(entry)

    return LinuxConfig(lines=lines, files=files)


# --- interrogazioni -----------------------------------------------------------

def is_empty(cfg: LinuxConfig) -> bool:
    return not cfg.lines


def file_lines(cfg: LinuxConfig, path: str) -> List[LinuxLine]:
    """Righe del file indicato, [] se il file non e' nell'artefatto."""
    return cfg.files.get(path, [])


def has_file(cfg: LinuxConfig, path: str) -> bool:
    """Il file compare fra le sezioni (anche se vuoto: esiste ed e' vuoto)."""
    return path in cfg.files


def directives(lines: List[LinuxLine], keyword: str) -> List[LinuxLine]:
    """Righe la cui PRIMA parola e' ``keyword`` (confronto minuscolo).

    Prima parola e non sottostringa: ``PermitRootLogin`` non deve pescare
    ``PermitRootLoginSomethingElse``, e ``ip_forward`` non deve pescare la riga
    di un altro parametro che lo nomina in un commento gia' scartato.
    """
    k = keyword.lower()
    return [l for l in lines if l.words[:1] == [k]]


def last_directive(lines: List[LinuxLine], keyword: str) -> Optional[LinuxLine]:
    """Ultima occorrenza della direttiva, ``None`` se assente.

    ``login.defs`` e ``sysctl.conf`` applicano l'ULTIMA assegnazione; sshd
    applica la PRIMA. La differenza la conosce la regola, non il parser: qui
    esistono entrambe le forme.
    """
    hits = directives(lines, keyword)
    return hits[-1] if hits else None


def first_directive(lines: List[LinuxLine], keyword: str) -> Optional[LinuxLine]:
    hits = directives(lines, keyword)
    return hits[0] if hits else None


def sysctl_value(lines: List[LinuxLine], key: str) -> Optional[LinuxLine]:
    """Riga ``chiave = valore`` di sysctl, l'ultima se ripetuta."""
    k = key.lower()
    hits = [l for l in lines if l.lower.split("=")[0].strip() == k]
    return hits[-1] if hits else None


def fstab_entry(lines: List[LinuxLine], mount_point: str) -> Optional[LinuxLine]:
    """Riga di ``fstab`` il cui punto di mount e' quello richiesto."""
    for l in lines:
        fields = l.text.split()
        if len(fields) >= 4 and fields[1] == mount_point:
            return l
    return None


def fstab_options(entry: LinuxLine) -> List[str]:
    fields = entry.text.split()
    return fields[3].lower().split(",") if len(fields) >= 4 else []
