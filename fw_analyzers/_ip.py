# -*- coding: utf-8 -*-
"""Low-level IP utilities shared by the firewall analyzers.

Leaf module (no internal project imports) to avoid circular imports:
``config_analyzer`` and the ``fw_analyzers.*`` modules import from here.
"""


def _mask_to_prefix(mask):
    """Converts a dotted subnet mask (255.255.255.0) to /nn length.
    Returns None if it is not a valid mask (e.g. already in /nn form or a wildcard)."""
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
    """From a list of tokens like ['10.1.10.1', '255.255.255.0'] derives
    'a.b.c.d/nn'. Returns '' if not interpretable."""
    try:
        if len(tokens) >= 2:
            ip = tokens[0]
            pfx = _mask_to_prefix(tokens[1])
            if pfx is not None:
                return f"{ip}/{pfx}"
            # possibly already in /nn form
            if tokens[1].startswith('/'):
                return f"{ip}{tokens[1]}"
        if len(tokens) == 1 and '/' in tokens[0]:
            return tokens[0]
    except Exception:
        pass
    return ''
