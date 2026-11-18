# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Industrial OUI lookup database for passive OT asset identification.

Covers the industrial vendors listed in INDUSTRIAL_VENDORS below.
"""
import re
from functools import lru_cache
from typing import Dict, Optional

_HEXONLY = re.compile(r"[^0-9a-fA-F]")

INDUSTRIAL_VENDORS = (
    "Siemens",
    "Rockwell/Allen-Bradley",
    "Schneider Electric",  # check-private-data: ok
    "Beckhoff",
    "Omron",
    "Moxa",
    "Hirschmann",
    "Phoenix Contact",
    "Wago",
    "Fanuc",
    "ABB",
)

# Public IEEE OUI prefixes (first 3 octets, lowercase colon-separated) mapped
# to canonical industrial vendor names.
INDUSTRIAL_OUI_MAP: Dict[str, str] = {
    # Siemens (check-private-data: ok)
    "00:0e:8c": "Siemens",
    "00:1b:1b": "Siemens",
    "00:1c:06": "Siemens",
    "28:63:36": "Siemens",
    "ac:64:17": "Siemens",
    "e0:dc:a0": "Siemens",
    # Rockwell/Allen-Bradley (check-private-data: ok)
    "00:00:bc": "Rockwell/Allen-Bradley",
    "00:1d:9c": "Rockwell/Allen-Bradley",
    "5c:88:16": "Rockwell/Allen-Bradley",
    "e4:90:69": "Rockwell/Allen-Bradley",
    "f4:54:33": "Rockwell/Allen-Bradley",
    # Schneider Electric (check-private-data: ok)
    "00:00:54": "Schneider Electric",  # check-private-data: ok
    "00:80:f4": "Schneider Electric",  # check-private-data: ok
    "00:23:f7": "Schneider Electric",  # check-private-data: ok
    "2c:26:5f": "Schneider Electric",  # check-private-data: ok
    # Beckhoff (check-private-data: ok)
    "00:01:05": "Beckhoff",
    # Omron (check-private-data: ok)
    "00:00:0a": "Omron",
    "00:25:5b": "Omron",
    "b8:92:1d": "Omron",
    # Moxa (check-private-data: ok)
    "00:90:e8": "Moxa",
    "c4:b9:cd": "Moxa",
    # Hirschmann (check-private-data: ok)
    "00:80:63": "Hirschmann",
    "64:60:38": "Hirschmann",
    "ec:74:ba": "Hirschmann",
    # Phoenix Contact (check-private-data: ok)
    "00:a0:45": "Phoenix Contact",
    "a8:74:1d": "Phoenix Contact",
    "ac:29:29": "Phoenix Contact",
    # Wago (check-private-data: ok)
    "00:30:de": "Wago",
    # Fanuc (check-private-data: ok)
    "00:e0:e4": "Fanuc",
    "00:09:9c": "Fanuc",
    "b4:00:9c": "Fanuc",
    # ABB (check-private-data: ok)
    "00:02:a3": "ABB",
    "00:0f:9b": "ABB",
    "00:21:c1": "ABB",
    "00:24:59": "ABB",
    "94:f9:29": "ABB",
}


def _extract_oui(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    hexs = _HEXONLY.sub("", str(mac)).lower()
    if len(hexs) < 6:
        return None
    if len(hexs) not in (6, 12):
        return None
    return f"{hexs[0:2]}:{hexs[2:4]}:{hexs[4:6]}"


@lru_cache(maxsize=4096)
def lookup_industrial_oui(mac: Optional[str]) -> str:
    """Return the canonical industrial vendor name for ``mac`` (or OUI prefix),
    or ``''`` if the prefix is not in the industrial OUI table."""
    oui = _extract_oui(mac)
    if not oui:
        return ""
    return INDUSTRIAL_OUI_MAP.get(oui, "")


def is_industrial_oui(mac: Optional[str]) -> bool:
    """True when ``mac`` matches a known industrial OUI vendor."""
    return bool(lookup_industrial_oui(mac))
