# -*- coding: utf-8 -*-
"""Shared CSV cell guard.

Two exports write CSV. A spreadsheet executes a cell that begins with one of
these characters, so the guard belongs in one place: a second copy is a second
thing to forget to fix.
"""

FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value):
    """Neutralise a cell a spreadsheet would execute.

    The leading apostrophe is the standard neutralisation: the sheet shows the
    text instead of evaluating it.
    """
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in FORMULA_LEADERS else s
