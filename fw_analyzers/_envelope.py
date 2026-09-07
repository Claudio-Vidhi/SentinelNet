# -*- coding: utf-8 -*-
"""Shape of the analyzer result the UI consumes, shared by every vendor.

These were duplicated character for character in fortios.py and panos.py,
docstring included, so the table contract could be changed in one and not the
other. Nothing here is vendor-specific: it only builds the
{"id", "label_key", "columns", "rows"} envelope the frontend renders.
"""

MASK = '***REDACTED***'


def col(key):
    return {"key": key, "label_key": f"fw.col.{key}"}


def join(vals):
    return ', '.join(vals) if isinstance(vals, (list, tuple)) else (vals or '')


def multi(vals):
    """Multi-element value kept as a LIST up to the UI.

    A policy can reference dozens of address objects: flattening them here into a
    string forces the table into one huge cell, and the client no longer has a way
    to expand it on demand because the structure is gone. Reassembling it
    browser-side by splitting on ", " is not equivalent: an object name can
    contain a comma.
    """
    if isinstance(vals, (list, tuple)):
        return [str(v) for v in vals]
    return [str(vals)] if vals else []


def section(sid, columns, rows):
    return {
        "id": sid,
        "label_key": f"fw.sec.{sid}",
        "columns": [col(k) for k in columns],
        "rows": rows,
    }
