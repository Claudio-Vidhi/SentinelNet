# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Sidebar favorites: the tabs a user pinned at the top of the navigation.

Only the tab ids are stored. Whether the user may still open a tab is decided
at render time by the dashboard, so a permission removed and later restored
brings the favorite back instead of losing it.
"""

import json
import re

from core import db

MAX_FAVORITES = 20
_TAB_ID = re.compile(r"^tab-[a-z0-9-]{1,40}$")


def validate(tabs: list) -> list:
    """Unique valid tab ids, in order. Raises ValueError on anything else."""
    out: list = []
    for t in tabs:
        if not isinstance(t, str) or not _TAB_ID.match(t):
            raise ValueError(f"Id di tab non valido: {t!r}")
        if t not in out:
            out.append(t)
    if len(out) > MAX_FAVORITES:
        raise ValueError(f"Al massimo {MAX_FAVORITES} preferiti.")
    return out


def get(username: str) -> list:
    conn = db.get_observability_connection()
    try:
        row = conn.execute("SELECT tabs_json FROM ui_favorites WHERE username = ?",
                           (username,)).fetchone()
        return json.loads(row["tabs_json"]) if row else []
    finally:
        conn.close()


def save(username: str, tabs: list) -> list:
    tabs = validate(tabs)
    conn = db.get_observability_connection()
    try:
        conn.execute(
            "INSERT INTO ui_favorites (username, tabs_json) VALUES (?, ?) "
            "ON CONFLICT(username) DO UPDATE SET tabs_json = excluded.tabs_json",
            (username, json.dumps(tabs)))
        conn.commit()
    finally:
        conn.close()
    return tabs
