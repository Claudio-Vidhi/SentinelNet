# -*- coding: utf-8 -*-
"""Utility IP di basso livello condivise dagli analizzatori firewall.

Modulo foglia (nessun import interno al progetto) per evitare import
circolari: ``config_analyzer`` e i moduli ``fw_analyzers.*`` importano da qui.
"""


def _mask_to_prefix(mask):
    """Converte una subnet mask dotted (255.255.255.0) in lunghezza /nn.
    Ritorna None se non e' una mask valida (es. gia' in forma /nn o wildcard)."""
    try:
        parts = mask.split('.')
        if len(parts) != 4:
            return None
        bits = 0
        for p in parts:
            v = int(p)
            if v < 0 or v > 255:
                return None
            bits += bin(v).count('1')
        return bits
    except Exception:
        return None


def _ip_addr_to_cidr(tokens):
    """Da una lista di token tipo ['10.1.10.1', '255.255.255.0'] ricava
    'a.b.c.d/nn'. Ritorna '' se non interpretabile."""
    try:
        if len(tokens) >= 2:
            ip = tokens[0]
            pfx = _mask_to_prefix(tokens[1])
            if pfx is not None:
                return f"{ip}/{pfx}"
            # eventuale forma gia' /nn
            if tokens[1].startswith('/'):
                return f"{ip}{tokens[1]}"
        if len(tokens) == 1 and '/' in tokens[0]:
            return tokens[0]
    except Exception:
        pass
    return ''
