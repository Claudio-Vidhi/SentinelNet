# -*- coding: utf-8 -*-
"""What this host believes is already offsite.

Absence and corruption both read as "nothing known": a lost state file must
cost one full re-upload, never a crash.
"""

import datetime as dt
import json
import os
import threading

from core import data_config

STATE_FILE = "cloud_backup_state.json"
_lock = threading.Lock()


def _path() -> str:
    return data_config.get_path(STATE_FILE)


def read() -> dict:
    try:
        with open(_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write(data: dict) -> None:
    tmp = _path() + ".tmp"
    with _lock:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, _path())


def known_hashes() -> dict:
    files = read().get("files")
    return dict(files) if isinstance(files, dict) else {}


def record_run(result: dict) -> None:
    """Stores the outcome. last_success_at moves only on a successful run: that
    is what lets the UI say "last good copy 120 hours ago" instead of showing a
    stale ok=true as if it were fresh."""
    data = read()
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    data["schema"] = 1
    data["last_run"] = {k: v for k, v in result.items() if k != "files"}
    data["last_run"]["finished_at"] = now
    if result.get("ok"):
        data["last_success_at"] = now
        data["files"] = dict(result.get("files") or {})
    write(data)


def hours_since_success(now: float | None = None) -> float | None:
    stamp = read().get("last_success_at")
    if not stamp:
        return None
    try:
        then = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    current = now if now is not None else dt.datetime.now(dt.timezone.utc).timestamp()
    return (current - then.timestamp()) / 3600
