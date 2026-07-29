# -*- coding: utf-8 -*-
"""Stati, evidenze e calcolo del punteggio del motore di audit.

LINGUA — le regole non producono prose ma CHIAVI di catalogo. Un audit e' un
documento che si consegna: deve poter uscire in italiano o in inglese a
prescindere dalla lingua con cui l'operatore sta usando l'interfaccia. Se le
frasi nascessero gia' formattate dentro le regole, l'unico modo di tradurle
sarebbe riscriverle tutte e 200. Qui la regola dichiara *cosa* ha trovato
(chiave + parametri) e la resa in lingua avviene una volta sola, al confine
(``run_netsec_audit``), leggendo ``messages.py``.
"""

from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
UNKNOWN = "UNKNOWN"


class Evidence(NamedTuple):
    """Riga di configurazione che motiva un esito diverso da PASS.

    Due forme, distinte da ``message``:

    - **citazione**: ``line`` > 0 e ``text`` e' la riga cosi' com'e' scritta
      nella configurazione. Non si traduce: un comando CLI e' lo stesso in
      qualunque lingua, e alterarlo lo renderebbe non piu' confrontabile col
      file analizzato.
    - **assenza**: ``line`` == 0, ``message`` e' una chiave di catalogo e
      ``text`` resta vuoto finche' non viene reso. Qui la traduzione serve,
      perche' l'evidenza e' una frase ("nessun 'set X'"), non una riga.
    """
    line: int
    text: str
    context: str
    message: Optional[str] = None
    params: Optional[Dict[str, Any]] = None


class RuleOutcome(NamedTuple):
    """Esito di una regola.

    ``message`` e' una chiave di ``messages.MESSAGES``, non una frase gia'
    scritta; ``params`` sono i valori che la chiave interpola (conteggi,
    soglie, nomi di direttiva).
    """
    status: str
    message: str
    evidence: Sequence[Evidence] = ()
    params: Optional[Dict[str, Any]] = None


def absent(message: str, context: str = "", **params: Any) -> Evidence:
    """Evidenza di un'assenza: nessuna riga da citare, solo cosa manca."""
    return Evidence(line=0, text="", context=context,
                    message=message, params=params or None)


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
