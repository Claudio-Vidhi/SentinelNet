# -*- coding: utf-8 -*-
"""Stati, evidenze e calcolo del punteggio del motore di audit."""

from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
UNKNOWN = "UNKNOWN"


class Evidence(NamedTuple):
    """Riga di configurazione che motiva un esito diverso da PASS."""
    line: int      # 1-based; 0 quando l'evidenza e' un'ASSENZA
    text: str      # direttiva incriminata, o descrizione dell'assenza
    context: str   # path del blocco, es. "system interface / port1"


class RuleOutcome(NamedTuple):
    status: str
    detail: str
    evidence: Sequence[Evidence] = ()


def score_rules(rules: List[Dict[str, Any]]) -> Tuple[Optional[int],
                                                      Dict[str, int]]:
    """Punteggio e riepilogo.

    UNKNOWN e' ESCLUSO dal denominatore: una sezione assente non e' ne' una
    conformita' ne' una violazione, e contarla falserebbe il punteggio in un
    verso o nell'altro. Se ogni regola e' UNKNOWN il punteggio non e'
    determinabile e vale ``None`` (la UI mostra un trattino, non 0 o 100).
    """
    summary = {
        "total": len(rules),
        "passed": sum(1 for r in rules if r.get("status") == PASS),
        "failed": sum(1 for r in rules if r.get("status") == FAIL),
        "warned": sum(1 for r in rules if r.get("status") == WARN),
        "unknown": sum(1 for r in rules if r.get("status") == UNKNOWN),
    }
    assessed = summary["passed"] + summary["failed"] + summary["warned"]
    score = round(summary["passed"] / assessed * 100) if assessed else None
    return score, summary
