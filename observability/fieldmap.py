# -*- coding: utf-8 -*-
"""Estrazione campi dai messaggi syslog grezzi — UNICO punto di verità.

Prima esisteva in due copie divergenti: ``correlator._extract_endpoints``
(srcip/dstip/dstport) e ``flow_siem._kv``/``_endpoints`` (che gestiva anche
srcport, proto, sentbyte, rcvdbyte). Due parser sugli stessi messaggi
significa due risultati diversi per lo stesso evento a seconda di chi lo
guarda: qui ce n'è uno solo, con il superset dei campi.

Vendor-agnostico per costruzione: prima si prova la forma key=value
(FortiGate e derivati), poi si ricade sulle prime due IP distinte del testo
(Palo Alto CSV e generici).
"""

import re
from typing import Optional

_KV_RE = re.compile(
    r'\b(srcip|dstip|srcport|dstport|proto|service|utmaction|action|'
    r'policyid|subtype|eventtype|sentbyte|rcvdbyte)=(?:"([^"]*)"|(\S+))')
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# ``utmaction`` è elencato a parte e non è coperto da ``action``: il ``\b``
# iniziale impedisce di agganciare la coda di 'utmaction=' (fra 'm' e 'a' non
# c'è confine di parola). Senza la voce esplicita un log UTM che porta SOLO
# utmaction restituiva action=None qui, mentre l'ingester syslog lo leggeva
# (syslog.py: ``kv.get("action") or kv.get("utmaction")``): due verità diverse
# sullo stesso messaggio, esattamente ciò che questo modulo esiste per evitare.

PROTO_NUM = {"6": "TCP", "17": "UDP", "1": "ICMP"}

# Verbi che significano "il traffico è stato fermato". Oltre ai verdetti di
# policy ci sono quelli UTM: IPS scrive 'dropped'/'reset'/'clear_session', il
# DNS filter 'redirect' (dirottato su sinkhole: il client NON raggiunge il
# sito). Senza di loro normalize.py li classificava 'log.event' invece di
# 'log.security', quindi non arrivavano a BLOCKED_TRAFFIC_001 — e un drop IPS
# è una delle cause più comuni di "il sito si carica a metà".
#
# DELIBERATAMENTE ASSENTI: 'passthrough' e 'bypass' (SSL: traffico lasciato
# passare SENZA ispezione, è un permesso), 'detected' (IPS in sola rilevazione)
# e 'pass' (application control). Sono verbi di consenso: classificarli come
# blocchi produrrebbe falsi positivi in Flow SIEM e incidenti inventati, che
# è peggio di un blocco non visto.
SECURITY_ACTIONS = ("deny", "denied", "blocked", "block", "drop", "dropped",
                    "reset", "reset-both", "reset-client", "reset-server",
                    "clear_session", "redirect", "sinkhole")


def kv(message: str) -> dict:
    """Coppie key=value riconosciute nel messaggio."""
    return {k: (v1 or v2) for k, v1, v2 in _KV_RE.findall(message or "")}


def int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def endpoints(message: str, pairs: Optional[dict] = None):
    """(src_ip, dst_ip) dal messaggio: kv se presente, altrimenti prime due IP."""
    pairs = kv(message) if pairs is None else pairs
    if pairs.get("srcip") and pairs.get("dstip"):
        return pairs["srcip"], pairs["dstip"]
    ips = list(dict.fromkeys(_IP_RE.findall(message or "")))
    if len(ips) >= 2:
        return ips[0], ips[1]
    return None, None


def extract(message: str) -> dict:
    """Campi normalizzati di un messaggio syslog. Ciò che il messaggio non
    contiene resta None: nessun valore inventato."""
    pairs = kv(message)
    src, dst = endpoints(message, pairs)
    sent = int_or_none(pairs.get("sentbyte")) or 0
    rcvd = int_or_none(pairs.get("rcvdbyte")) or 0
    proto = pairs.get("proto") or pairs.get("service")
    return {
        "src_ip": src,
        "dst_ip": dst,
        "src_port": int_or_none(pairs.get("srcport")),
        "dst_port": int_or_none(pairs.get("dstport")),
        "protocol": PROTO_NUM.get(str(proto), str(proto).upper()) if proto else None,
        # Stesso ordine di precedenza dell'ingester: su un log UTM il verdetto
        # sta in utmaction, su un log di traffico in action.
        "action": pairs.get("action") or pairs.get("utmaction"),
        "policy_id": pairs.get("policyid"),
        # Distingue "policy 12 ha negato" da "il web filter ha bloccato": senza
        # il sottotipo i due casi sono lo stesso DENY nella vista.
        "subtype": pairs.get("subtype") or pairs.get("eventtype"),
        "bytes": (sent + rcvd) or None,
    }


def is_security_action(action) -> bool:
    return (action or "").strip().lower() in SECURITY_ACTIONS
