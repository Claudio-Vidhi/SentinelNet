# -*- coding: utf-8 -*-
"""Parser FortiOS con tracciamento di riga per il motore di audit.

Riusa la tokenizzazione di ``fw_analyzers.fortios`` (che gestisce le stringhe
tra apici) ma produce record PIATTI con numero di riga, invece dell'albero di
``_forti_tree``: le regole hanno bisogno sia del contesto strutturale (il path
del blocco) sia dell'evidenza (la riga esatta da citare nel report).

Tollerante quanto ``_forti_tree``: blocchi non chiusi, annidamenti anomali e
righe malformate vengono saltati, mai sollevati.
"""

from typing import Dict, List, NamedTuple, Optional, Set, Tuple

from fw_analyzers.fortios import _forti_tokens


class ConfigRecord(NamedTuple):
    """Una direttiva ``set`` con il suo contesto e la sua posizione."""
    path: Tuple[str, ...]   # es. ("system interface", "port1")
    key: str                # es. "allowaccess" (sempre minuscolo)
    values: List[str]       # es. ["ping", "https", "telnet"]
    line: int               # 1-based, per l'evidenza nel report
    raw: str                # riga originale, senza newline finale


class ParsedConfig(NamedTuple):
    records: List[ConfigRecord]
    # Ogni path di blocco incontrato, anche se privo di 'set'. Serve a
    # distinguere "sezione assente" (UNKNOWN) da "sezione presente e vuota".
    sections: Set[Tuple[str, ...]]


def parse_with_lines(text: Optional[str]) -> ParsedConfig:
    records: List[ConfigRecord] = []
    sections: Set[Tuple[str, ...]] = set()
    stack: List[str] = []
    for lineno, raw in enumerate((text or "").splitlines(), start=1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        low = s.lower()
        try:
            if low.startswith("config "):
                stack.append(s[7:].strip().strip('"'))
                sections.add(tuple(stack))
            elif low.startswith("edit "):
                stack.append(s[5:].strip().strip('"'))
                sections.add(tuple(stack))
            elif low in ("next", "end"):
                if stack:
                    stack.pop()
            elif low.startswith("set "):
                toks = _forti_tokens(s)
                if len(toks) >= 2:
                    records.append(ConfigRecord(
                        path=tuple(stack),
                        key=toks[1].lower(),
                        values=list(toks[2:]),
                        line=lineno,
                        raw=raw.rstrip("\r\n"),
                    ))
        except Exception:
            continue
    return ParsedConfig(records=records, sections=sections)


def _parts(section: str) -> Tuple[str, ...]:
    return (section,)


def section_present(cfg: ParsedConfig, section: str) -> bool:
    """True se il blocco ``config <section>`` compare, anche se vuoto."""
    return _parts(section) in cfg.sections


def section_entries(cfg: ParsedConfig,
                    section: str) -> Dict[str, List[ConfigRecord]]:
    """Record di ``config <section>`` raggruppati per chiave di ``edit``.

    Un blocco senza voci ``edit`` restituisce un dizionario vuoto: usare
    ``section_present`` per distinguerlo da una sezione assente.
    """
    base = _parts(section)
    out: Dict[str, List[ConfigRecord]] = {}
    for entry in cfg.sections:
        if len(entry) == len(base) + 1 and entry[:len(base)] == base:
            out.setdefault(entry[len(base)], [])
    for r in cfg.records:
        if len(r.path) >= len(base) + 1 and r.path[:len(base)] == base:
            out.setdefault(r.path[len(base)], []).append(r)
    return out


def setting(cfg: ParsedConfig, section: str,
            key: str) -> Optional[ConfigRecord]:
    """Primo record ``set <key>`` direttamente sotto ``config <section>``."""
    base = _parts(section)
    key = key.lower()
    for r in cfg.records:
        if r.path == base and r.key == key:
            return r
    return None
