# -*- coding: utf-8 -*-
"""Soppressioni: ciò che l'operatore si aspetta, con o senza scadenza.

Un'unica domanda — *l'operatore se lo aspettava?* — con due forme che il resto
del mondo tratta come funzionalità separate:

- "questa porta è giù per progetto"          → nessuna finestra, vale sempre;
- "questo apparato è in manutenzione stanotte" → finestra ``from_ts``/``to_ts``.

Sono lo stesso modello. Tenerli separati significherebbe avere due posti dove
cercare perché un allarme non è scattato.

NON sopprime il fatto. L'evento resta in ``events`` e nel feed: cambia solo se
diventi un'evidenza. La conoscenza dell'operatore entra
nell'INTERPRETAZIONE, che è l'unico punto in cui ha senso farla entrare — così
il giorno in cui la soppressione scade, lo storico è ancora completo.

Applicata in un posto solo (``correlator``), non regola per regola: una
manutenzione zittisce tutto quello che riguarda quell'apparato, non solo la
regola a cui qualcuno si è ricordato di aggiungere il controllo.
"""

import time
from typing import Optional

from core.app_settings import get_app_settings

ANY_INTERFACE = "*"


def key(tenant: str, entity_key: str, interface: Optional[str]) -> str:
    """Chiave deterministica: risalvare lo stesso bersaglio lo aggiorna invece
    di accumularne un secondo."""
    return f"{tenant}|{entity_key}|{interface or ANY_INTERFACE}"


def all_rules() -> dict:
    saved = get_app_settings().get("suppressions")
    return saved if isinstance(saved, dict) else {}


def _covers(rule: dict, interface: Optional[str]) -> bool:
    """Una soppressione di apparato copre ogni sua interfaccia; una di
    interfaccia copre solo quella."""
    target = rule.get("interface") or ANY_INTERFACE
    return target == ANY_INTERFACE or target == interface


def _in_window(rule: dict, at_ts: int) -> bool:
    """Estremi aperti: nessun ``from`` = da sempre, nessun ``to`` = per sempre.
    'Per sempre' non è un caso speciale, è il caso senza scadenza."""
    frm, to = rule.get("from_ts"), rule.get("to_ts")
    if frm is not None and at_ts < frm:
        return False
    if to is not None and at_ts > to:
        return False
    return True


def active(tenant: str, entity_key: Optional[str], interface: Optional[str],
           at_ts: int) -> Optional[dict]:
    """La soppressione che copre questo bersaglio a questo istante, se c'è.

    ``at_ts`` è il tempo dell'EVENTO, non quello corrente: una manutenzione di
    ieri notte deve continuare a coprire i fatti di ieri notte anche se la
    correlazione li rilegge stamattina.
    """
    if not entity_key:
        return None
    for rule in all_rules().values():
        if not isinstance(rule, dict):
            continue
        if rule.get("tenant") != tenant or rule.get("entity_key") != entity_key:
            continue
        if _covers(rule, interface) and _in_window(rule, at_ts):
            return rule
    return None


def expired(rule: dict, now: Optional[int] = None) -> bool:
    """Finestra già chiusa: la UI la mostra spenta invece di farla sparire, così
    resta leggibile perché un incidente di ieri non è mai nato."""
    to = rule.get("to_ts")
    return to is not None and to < (now or int(time.time()))
