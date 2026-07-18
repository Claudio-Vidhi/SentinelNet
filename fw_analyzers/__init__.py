# -*- coding: utf-8 -*-
"""Analizzatori firewall per-vendor.

Ogni modulo vendor espone ``analyze(text)`` che ritorna l'envelope generico
``{"vendor": <str>, "sections": [{"id","label_key","columns","rows"}]}``
renderizzato genericamente dal frontend.

``analyze(vendor, text)`` fa da dispatcher: ritorna ``None`` per vendor non
supportati.
"""
from . import fortios, panos

_VENDORS = {"fortios": fortios, "panos": panos}


def analyze(vendor, text):
    """Dispatch verso l'analizzatore del vendor. Ritorna l'envelope o None."""
    mod = _VENDORS.get((vendor or '').strip().lower())
    return mod.analyze(text) if mod else None
