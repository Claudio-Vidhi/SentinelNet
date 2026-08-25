# -*- coding: utf-8 -*-
"""Walk backup-config/, send what changed, prove it arrived.

The mirror is write-only: nothing here ever reads the remote as a source of
truth. The verification pass exists because a remote that accepts writes and
discards them (full disk, quota, read-only export) otherwise looks exactly
like a successful run.
"""

import datetime as dt
import hashlib
import json
import os
import posixpath
import random
import threading

from core.core_engine import BACKUP_FOLDER
from services.cloud_backup import payload, settings, state
from services.cloud_backup.restore_template import RESTORE_SCRIPT
from services.cloud_backup.sftp import open_target as _open_target

MANIFEST_NAME = "_manifest.json"
RESTORE_NAME = "restore.py"
VERIFY_SAMPLE = 0.05

_run_lock = threading.Lock()


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def walk_local(root: str) -> dict:
    """Every file under root, hashed. .history/ is included: it is the part
    that makes the mirror worth having."""
    out = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            out[rel] = {"sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                        "size": len(data)}
    return out


def plan_uploads(local: dict, known: dict) -> list:
    return sorted(rel for rel, entry in local.items()
                  if known.get(rel) != entry["sha256"])


def run_mirror(open_target=_open_target) -> dict:
    """One mirror pass. Returns the result dict, also recorded in state."""
    result: dict = {"started_at": _now(), "ok": False, "uploaded": 0, "skipped": 0,
                    "failed": 0, "verified": 0, "error": None, "files": {}}
    if not _run_lock.acquire(blocking=False):
        result["error"] = "a mirror cycle is already running"
        return result
    try:
        cfg = settings.read()
        if not cfg.get("enabled"):
            result["error"] = "mirror not enabled"
            return result

        local = walk_local(BACKUP_FOLDER)
        known = state.known_hashes()
        todo = plan_uploads(local, known)
        result["skipped"] = len(local) - len(todo)
        encrypt = bool(cfg.get("encrypt_payload"))
        root = cfg["remote_root"].rstrip("/")

        target = open_target(cfg)
        try:
            uploaded = []
            for rel in todo:
                try:
                    with open(os.path.join(BACKUP_FOLDER, *rel.split("/")), "rb") as fh:
                        data = fh.read()
                    body = payload.encrypt_bytes(data) if encrypt else data
                    remote = posixpath.join(root, payload.remote_name(rel, encrypt))
                    target.put(body, remote)
                    uploaded.append((rel, remote, len(body)))
                    result["uploaded"] += 1
                except OSError as exc:
                    # One unreadable file must not abandon the rest of the run.
                    result["failed"] += 1
                    result["error"] = result["error"] or f"{rel}: {exc}"

            manifest = {
                "schema": 1, "updated_at": _now(), "source": "sentinelnet",
                "encrypted": encrypt,
                "files": {rel: {"sha256": entry["sha256"], "size": entry["size"],
                                "uploaded_at": _now()}
                          for rel, entry in local.items()},
            }
            target.put(json.dumps(manifest, indent=2).encode("utf-8"),
                       posixpath.join(root, MANIFEST_NAME))
            target.put(RESTORE_SCRIPT.encode("utf-8"), posixpath.join(root, RESTORE_NAME))

            # Verification: everything sent this run, plus a rotating sample of
            # the rest. A size that does not match means the remote took the
            # write and kept nothing.
            checks: list = list(uploaded)
            sent = {rel for rel, _, _ in uploaded}
            rest = [rel for rel in local if rel not in sent]
            if rest:
                sample_size = min(len(rest), int(len(rest) * VERIFY_SAMPLE) + 1)
                for rel in random.sample(rest, sample_size):
                    checks.append((rel, posixpath.join(root, payload.remote_name(rel, encrypt)), None))
            for rel, remote, expected in checks:
                actual = target.size(remote)
                if actual is None or (expected is not None and actual != expected):
                    result["failed"] += 1
                    result["error"] = result["error"] or \
                        f"{rel}: remote reports {actual} bytes instead of {expected}"
                else:
                    result["verified"] += 1
        finally:
            target.close()

        if not result["failed"]:
            result["ok"] = True
            result["files"] = {rel: entry["sha256"] for rel, entry in local.items()}
    except Exception as exc:  # boundary: network, auth, host key
        result["error"] = str(exc)
    finally:
        _run_lock.release()
    state.record_run(result)
    return result


def status() -> dict:
    data = state.read()
    cfg = settings.read()
    local = walk_local(BACKUP_FOLDER) if cfg.get("enabled") else {}
    return {
        "enabled": bool(cfg.get("enabled")),
        "encrypt_payload": bool(cfg.get("encrypt_payload")),
        "last_run": data.get("last_run") or {},
        "last_success_at": data.get("last_success_at"),
        "hours_since_success": state.hours_since_success(),
        "stale_after_hours": cfg.get("stale_after_hours", 48),
        "pending": len(plan_uploads(local, state.known_hashes())),
    }
