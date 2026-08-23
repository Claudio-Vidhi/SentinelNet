# -*- coding: utf-8 -*-
"""Per-device config history, stored beside the current backup.

The current backup file keeps its exact path and name: the policy test loader,
the netsec audit, the config analyzer and download_backup all read it. History
is therefore additive — a '.history' folder next to it, and nothing else moves.
"""
import hashlib
import json
import os
import time

from services.config_drift import normalize

_INDEX = "index.json"


def _now() -> str:
    """UTC stamp used both as the version id and in the archived filename.

    Microsecond precision, not second: two versions recorded inside the same
    second would otherwise share a stamp, and the archived filename with it —
    the second write would overwrite the first and read_version could not tell
    them apart.
    """
    ts = time.time()
    return (time.strftime("%Y%m%dT%H%M%S", time.gmtime(ts))
            + f".{int((ts % 1) * 1_000_000):06d}Z")


def _device_dir(device: dict) -> str:
    from core import core_engine
    return core_engine.group_backup_dir(device.get("Group") or "Generale",
                                        device.get("Vendor") or "")


def history_dir(device: dict) -> str:
    path = os.path.join(_device_dir(device), ".history")
    os.makedirs(path, exist_ok=True)
    return path


def _index_path(device: dict) -> str:
    return os.path.join(history_dir(device), f"{device['IP']}-{_INDEX}")


def _load_index(device: dict) -> dict:
    try:
        with open(_index_path(device), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        # No history yet, or a truncated write. Either way the device has no
        # known past: recording the current config re-creates it.
        return {"device": device.get("IP", ""), "versions": [], "last_seen_at": ""}


def _save_index(device: dict, index: dict) -> None:
    with open(_index_path(device), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1)


def _digest(device: dict, config_text: str) -> str:
    body = normalize.normalize(device.get("Vendor") or "", config_text)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def record_version(device: dict, config_text: str) -> bool:
    """Archive ``config_text`` if it differs from the newest known version.

    Returns True when a version was archived. An unchanged config only updates
    last_seen_at, so the UI can tell "unchanged for 14 days" from "not
    collected for 14 days".
    """
    from core import core_engine
    index = _load_index(device)
    stamp = _now()
    index["device"] = device.get("IP", "")
    index["last_seen_at"] = stamp

    digest = _digest(device, config_text)
    versions = index.setdefault("versions", [])
    if versions and versions[0].get("hash") == digest:
        _save_index(device, index)
        return False

    name = core_engine.sanitize_filename(device.get("Hostname") or device["IP"])
    filename = f"{name}-{device['IP']}.{stamp}.txt"
    with open(os.path.join(history_dir(device), filename), "w", encoding="utf-8") as fh:
        fh.write(config_text)
    versions.insert(0, {"hash": digest, "seen_at": stamp,
                        "size": len(config_text), "file": filename})
    _save_index(device, index)
    from services.config_drift import mirror
    mirror.commit_version(device, filename)
    prune(device)
    return True


def prune(device: dict) -> int:
    """Prunes history versions according to config_drift_keep_versions setting.

    0 (default) means keep everything. A positive integer keeps only the N newest
    versions and deletes older version files from disk. Pinned versions are protected.
    Returns the number of versions removed.
    """
    from core import app_settings
    settings = app_settings.get_app_settings()
    app_sec = settings.get("app") if isinstance(settings.get("app"), dict) else {}
    env_val = os.environ.get("SENTINELNET_DRIFT_KEEP_VERSIONS")
    raw = env_val if env_val is not None else (
        app_sec.get("config_drift_keep_versions")
        if app_sec.get("config_drift_keep_versions") is not None
        else settings.get("config_drift_keep_versions", 0)
    )
    try:
        keep = int(raw or 0)
    except (TypeError, ValueError):
        keep = 0

    if keep <= 0:
        return 0

    index = _load_index(device)
    versions = index.get("versions", [])
    if len(versions) <= keep:
        return 0

    to_keep = []
    to_prune = []
    for idx, v in enumerate(versions):
        if idx < keep or v.get("pinned"):
            to_keep.append(v)
        else:
            to_prune.append(v)

    if not to_prune:
        return 0

    h_dir = history_dir(device)
    for v in to_prune:
        fname = v.get("file")
        if fname:
            try:
                fpath = os.path.join(h_dir, fname)
                if os.path.exists(fpath):
                    os.remove(fpath)
            except OSError:
                pass

    index["versions"] = to_keep
    _save_index(device, index)
    return len(to_prune)


def list_versions(device: dict) -> list:
    """Every retained version, newest first."""
    return _load_index(device).get("versions", [])


def last_seen_at(device: dict) -> str:
    return _load_index(device).get("last_seen_at", "")


def read_version(device: dict, seen_at: str) -> str:
    """The archived config text for one version, or '' if it is not there."""
    entry = next((v for v in list_versions(device) if v.get("seen_at") == seen_at), None)
    if not entry:
        return ""
    try:
        with open(os.path.join(history_dir(device), entry["file"]), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""
