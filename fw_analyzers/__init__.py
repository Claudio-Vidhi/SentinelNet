# -*- coding: utf-8 -*-
"""Per-vendor firewall analyzers.

Each vendor module exposes ``analyze(text)`` which returns the generic envelope
``{"vendor": <str>, "sections": [{"id","label_key","columns","rows"}]}``
rendered generically by the frontend.

``analyze(vendor, text)`` acts as a dispatcher: returns ``None`` for unsupported
vendors.
"""
from . import fortios, panos

_VENDORS = {"fortios": fortios, "panos": panos}


def analyze(vendor, text):
    """Dispatches to the vendor's analyzer. Returns the envelope or None."""
    mod = _VENDORS.get((vendor or '').strip().lower())
    return mod.analyze(text) if mod else None
