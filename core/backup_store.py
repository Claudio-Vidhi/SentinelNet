# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Config-backup storage: paths, save, stale-file handling, offsite mirror
(extracted from core_engine.py — plan Phase 3 item 12; core_engine keeps
re-exporting the public names so call sites are unchanged)."""

import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from core import data_config

BACKUP_FOLDER = data_config.get_path('backup-config')

if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)

OT_ARTIFACT_TYPES = (
    "tia_portal",
    "studio_5000",
    "iec_61850",
    "hmi_backup",
    "plc_project",
    "config_archive",
)

_TIA_EXT_RE = re.compile(r"^\.(?:z?ap\d*)$", re.I)
_OT_EXT_MAP = {
    ".acd": "studio_5000",
    ".l5x": "studio_5000",
    ".l5k": "studio_5000",
    ".rss": "studio_5000",
    ".rsp": "studio_5000",
    ".scd": "iec_61850",
    ".icd": "iec_61850",
    ".cid": "iec_61850",
    ".ssd": "iec_61850",
    ".iid": "iec_61850",
    ".sed": "iec_61850",
    ".hmi": "hmi_backup",
    ".mer": "hmi_backup",
    ".apa": "hmi_backup",
    ".eas": "hmi_backup",
    ".s7p": "plc_project",
    ".mwp": "plc_project",
    ".gxw": "plc_project",
    ".gx2": "plc_project",
    ".gx3": "plc_project",
    ".cxp": "plc_project",
    ".cxr": "plc_project",
    ".cxt": "plc_project",
    ".smc": "plc_project",
    ".pcw": "plc_project",
    ".pro": "plc_project",
    ".project": "plc_project",
    ".tpw": "plc_project",
    ".zip": "config_archive",
    ".tar": "config_archive",
    ".tgz": "config_archive",
    ".gz": "config_archive",
    ".7z": "config_archive",
    ".bak": "config_archive",
    ".bin": "config_archive",
    ".cfg": "config_archive",
    ".xml": "config_archive",
    ".json": "config_archive",
    ".txt": "config_archive",
    ".ini": "config_archive",
    ".conf": "config_archive",
}

_OT_VAULT_INDEX = "ot-vault-index.json"
_ot_vault_lock = threading.RLock()


def max_ot_artifact_bytes() -> int:
    try:
        return max(1024, int(os.environ.get("SENTINELNET_MAX_OT_ARTIFACT_BYTES", str(64 * 1024 * 1024))))
    except (TypeError, ValueError):
        return 64 * 1024 * 1024


def sanitize_filename(filename: str) -> str:
    sanitized = ''.join(
        '_' if char in r'\/:*?"<>| ' else char
        for char in filename
        if ord(char) > 31
    )
    return sanitized or "device_unknown"


def group_backup_dir(group: str, vendor: Optional[str] = None) -> str:
    """Backup folder dedicated to a group/tenant, with subfolder per
    vendor (backup-config/<group>/<vendor>/), created if absent."""
    path = os.path.join(BACKUP_FOLDER, sanitize_filename(group or "unknown"))
    if vendor:
        path = os.path.join(path, sanitize_filename(vendor.lower()))
    os.makedirs(path, exist_ok=True)
    return path


def save_backup(device, sys_name: str, config_out: str) -> str:
    """Saves the text backup in backup-config/<group>/<vendor>/<name>-<ip>.txt,
    moving first any residual copies of the same IP elsewhere within the tenant."""
    ip = device['IP']
    tenant = device.get('Group') or ""
    group_dir = group_backup_dir(tenant, device.get('Vendor', ''))
    target_name = f"{sanitize_filename(sys_name)}-{ip}.txt"
    remove_stale_backups(ip, new_dir=group_dir, keep=target_name, tenant=tenant)
    file_path = os.path.join(group_dir, target_name)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(config_out)
    return file_path


def backup_times() -> dict:
    """{(tenant_folder, ip): mtime} of every current backup, in one walk.

    Keyed by tenant folder too: two tenants may each own the same IP.
    Archived versions under '.history' and '.ot-vault' are not current CLI backups.
    """
    out = {}
    for root, dirs, files in os.walk(BACKUP_FOLDER):
        dirs[:] = [d for d in dirs if d not in (".history", ".ot-vault")]
        rel = os.path.relpath(root, BACKUP_FOLDER)
        if rel == ".":
            continue
        tenant = rel.split(os.sep)[0]
        for f in files:
            if not f.endswith(".txt"):
                continue
            stem = f[:-4]
            ip = stem[max(stem.rfind("-"), stem.rfind("_")) + 1:]
            try:
                mt = int(os.path.getmtime(os.path.join(root, f)))
            except OSError:
                continue
            key = (tenant, ip)
            if mt > out.get(key, 0):
                out[key] = mt
    return out


def remove_stale_backups(ip: str, new_dir: Optional[str] = None, keep: Optional[str] = None, tenant: Optional[str] = None):
    """Move a device's backup and its history when it changes vendor or hostname.

    Scoped strictly to the device's tenant: never walks or moves directories
    belonging to a different tenant.
    """
    if not os.path.exists(BACKUP_FOLDER):
        return
    if tenant is not None:
        walk_root = os.path.join(BACKUP_FOLDER, sanitize_filename(tenant or "unknown"))
        if not os.path.exists(walk_root):
            return
    else:
        walk_root = BACKUP_FOLDER

    for root, dirs, files in os.walk(walk_root):
        dirs[:] = [d for d in dirs if d != ".ot-vault"]
        in_dest = new_dir and os.path.abspath(root) == os.path.abspath(new_dir)
        for f in files:
            if not (f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt"):
                continue
            if in_dest and f == keep:
                continue
            src = os.path.join(root, f)
            try:
                if new_dir and not in_dest:
                    os.makedirs(new_dir, exist_ok=True)
                    os.replace(src, os.path.join(new_dir, f))
                else:
                    os.remove(src)
            except OSError as e:
                logging.warning(f"Backup obsoleto non spostato ({f}): {e}")
        if not in_dest:
            _move_history(root, ip, new_dir)


def _move_history(root: str, ip: str, new_dir: Optional[str]) -> None:
    """Carry the device's .history entries across with its current backup."""
    src_hist = os.path.join(root, ".history")
    if not new_dir or not os.path.isdir(src_hist):
        return
    dst_hist = os.path.join(new_dir, ".history")
    if os.path.abspath(src_hist) == os.path.abspath(dst_hist):
        return
    os.makedirs(dst_hist, exist_ok=True)
    for f in os.listdir(src_hist):
        if f"-{ip}." in f or f.startswith(f"{ip}-"):
            try:
                os.replace(os.path.join(src_hist, f), os.path.join(dst_hist, f))
            except OSError as e:
                logging.warning(f"Storico non spostato ({f}): {e}")


# --- OT Config / Project Vault (versioned, SHA-256 verified) -----------------

def _ot_vault_stamp() -> str:
    ts = time.time()
    return (
        time.strftime("%Y%m%dT%H%M%S", time.gmtime(ts))
        + f".{int((ts % 1) * 1_000_000):06d}Z"
    )


def _ot_vault_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_ot_filename(filename: str) -> str:
    base = os.path.basename(str(filename or "").replace("\\", "/")).strip()
    if not base or base in (".", ".."):
        raise ValueError("Nome file non valido.")
    cleaned = sanitize_filename(base)
    if cleaned in ("", ".", "..", "device_unknown"):
        raise ValueError("Nome file non valido.")
    return cleaned


def classify_ot_artifact(filename: str, artifact_type: str = "") -> str:
    """Validate and classify a non-CLI OT project/HMI/SCL artifact by extension."""
    cleaned = _safe_ot_filename(filename)
    _, ext = os.path.splitext(cleaned)
    ext_low = ext.lower()
    if _TIA_EXT_RE.match(ext_low):
        detected = "tia_portal"
    elif ext_low in _OT_EXT_MAP:
        detected = _OT_EXT_MAP[ext_low]
    else:
        raise ValueError(f"Estensione file OT non supportata: {ext_low or '(nessuna)'}")
    explicit = str(artifact_type or "").strip().lower()
    if explicit:
        if explicit not in OT_ARTIFACT_TYPES:
            raise ValueError(f"Tipo artefatto OT non valido: {artifact_type}")
        return explicit
    return detected


def _ot_vault_dir(device: dict, create: bool = False) -> str:
    ip = str(device.get("IP") or "").strip()
    if not ip:
        raise ValueError("IP apparato mancante.")
    tenant_folder = sanitize_filename(str(device.get("Group") or "") or "unknown")
    path = os.path.join(BACKUP_FOLDER, tenant_folder, ".ot-vault", sanitize_filename(ip))
    if create:
        os.makedirs(path, exist_ok=True)
    return path


def _ot_vault_index_path(device: dict, create: bool = False) -> str:
    return os.path.join(_ot_vault_dir(device, create=create), _OT_VAULT_INDEX)


def _load_ot_index(device: dict) -> dict:
    path = _ot_vault_index_path(device, create=False)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("versions"), list):
            return data
    except (OSError, ValueError):
        pass
    return {
        "ip": str(device.get("IP") or ""),
        "tenant": str(device.get("Group") or ""),
        "versions": [],
    }


def _atomic_write_vault(path: str, data: bytes) -> None:
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".vault-", dir=parent)
    try:
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def _save_ot_index(device: dict, index: dict) -> None:
    path = _ot_vault_index_path(device, create=True)
    payload = json.dumps(index, indent=1, ensure_ascii=False).encode("utf-8")
    _atomic_write_vault(path, payload)


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def save_ot_artifact(
    device: dict,
    filename: str,
    data: bytes,
    uploaded_by: str = "",
    notes: str = "",
    artifact_type: str = "",
    project_version: str = "",
) -> dict:
    """Store a versioned OT artifact in BACKUP_FOLDER/.ot-vault with SHA-256 integrity metadata."""
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
        raise ValueError("Contenuto artefatto vuoto.")
    raw = bytes(data)
    limit = max_ot_artifact_bytes()
    if len(raw) > limit:
        raise ValueError(f"Artefatto OT troppo grande ({len(raw)} byte > {limit}).")

    safe_name = _safe_ot_filename(filename)
    kind = classify_ot_artifact(safe_name, artifact_type=artifact_type)
    digest = _sha256_bytes(raw)
    rev = str(project_version or "").strip()[:64]
    note = str(notes or "").strip()[:500]
    actor = str(uploaded_by or "").strip()[:120]

    with _ot_vault_lock:
        index = _load_ot_index(device)
        versions = index.setdefault("versions", [])
        if versions and versions[0].get("sha256") == digest and versions[0].get("filename") == safe_name:
            return {
                "ok": True,
                "deduplicated": True,
                "version": dict(versions[0]),
                "count": len(versions),
            }

        version_id = _ot_vault_stamp()
        stored_name = f"{version_id}_{safe_name}"
        vault_dir = _ot_vault_dir(device, create=True)
        dest_path = os.path.join(vault_dir, stored_name)
        _atomic_write_vault(dest_path, raw)

        entry = {
            "version_id": version_id,
            "filename": safe_name,
            "stored_file": stored_name,
            "artifact_type": kind,
            "project_version": rev,
            "notes": note,
            "sha256": digest,
            "size": len(raw),
            "uploaded_at": _ot_vault_now_iso(),
            "uploaded_by": actor,
        }
        versions.insert(0, entry)
        index["ip"] = str(device.get("IP") or "")
        index["tenant"] = str(device.get("Group") or "")
        _save_ot_index(device, index)
        return {
            "ok": True,
            "deduplicated": False,
            "version": dict(entry),
            "count": len(versions),
        }


def list_ot_artifacts(device: dict) -> list:
    """Return archived OT project artifacts for a device, newest first."""
    with _ot_vault_lock:
        return [dict(v) for v in _load_ot_index(device).get("versions", [])]


def _resolve_vault_entry_path(vault_dir: str, entry: dict) -> Optional[str]:
    stored = str(entry.get("stored_file") or "")
    if not stored:
        return None
    root = os.path.realpath(vault_dir)
    cand = os.path.realpath(os.path.join(root, stored))
    if not cand.startswith(root + os.sep):
        return None
    return cand


def verify_ot_artifact(device: dict, version_id: Optional[str] = None) -> dict:
    """Recompute SHA-256 of archived OT artifacts and detect tampering or missing blobs."""
    with _ot_vault_lock:
        index = _load_ot_index(device)
        versions = index.get("versions", [])
        if version_id:
            targets = [v for v in versions if v.get("version_id") == version_id]
            if not targets:
                raise FileNotFoundError(f"Versione artefatto OT '{version_id}' non trovata.")
        else:
            targets = list(versions)

        vault_dir = _ot_vault_dir(device, create=False)
        results = []
        corrupted = []
        missing = []
        for entry in targets:
            vid = str(entry.get("version_id") or "")
            expected = str(entry.get("sha256") or "")
            fpath = _resolve_vault_entry_path(vault_dir, entry)
            if not fpath or not os.path.isfile(fpath):
                missing.append(vid)
                results.append({
                    "version_id": vid,
                    "filename": entry.get("filename", ""),
                    "artifact_type": entry.get("artifact_type", ""),
                    "expected_sha256": expected,
                    "actual_sha256": "",
                    "size": entry.get("size", 0),
                    "status": "missing",
                })
                continue
            actual = _sha256_file(fpath)
            ok = bool(expected and actual == expected)
            if not ok:
                corrupted.append(vid)
            results.append({
                "version_id": vid,
                "filename": entry.get("filename", ""),
                "artifact_type": entry.get("artifact_type", ""),
                "expected_sha256": expected,
                "actual_sha256": actual,
                "size": os.path.getsize(fpath),
                "status": "ok" if ok else "mismatch",
            })

        return {
            "ok": len(corrupted) == 0 and len(missing) == 0,
            "checked": len(results),
            "corrupted": corrupted,
            "missing": missing,
            "results": results,
        }


def read_ot_artifact(device: dict, version_id: str, verify: bool = True) -> tuple:
    """Read raw artifact bytes after optional SHA-256 verification."""
    with _ot_vault_lock:
        index = _load_ot_index(device)
        entry = next((v for v in index.get("versions", []) if v.get("version_id") == version_id), None)
        if not entry:
            raise FileNotFoundError(f"Versione artefatto OT '{version_id}' non trovata.")
        fpath = _resolve_vault_entry_path(_ot_vault_dir(device, create=False), entry)
        if not fpath or not os.path.isfile(fpath):
            raise FileNotFoundError(f"File artefatto OT '{version_id}' mancante su disco.")
        with open(fpath, "rb") as fh:
            data = fh.read()
        if verify:
            expected = str(entry.get("sha256") or "")
            actual = _sha256_bytes(data)
            if not expected or actual != expected:
                raise ValueError(
                    f"Verifica SHA-256 fallita per {entry.get('filename', version_id)}: atteso {expected}, calcolato {actual}"
                )
        return dict(entry), data


def delete_ot_artifact(device: dict, version_id: str) -> bool:
    """Delete a stored OT artifact version and remove it from the index."""
    with _ot_vault_lock:
        index = _load_ot_index(device)
        versions = index.get("versions", [])
        target = next((v for v in versions if v.get("version_id") == version_id), None)
        if not target:
            return False
        fpath = _resolve_vault_entry_path(_ot_vault_dir(device, create=False), target)
        if fpath and os.path.isfile(fpath):
            try:
                os.remove(fpath)
            except OSError:
                pass
        index["versions"] = [v for v in versions if v.get("version_id") != version_id]
        _save_ot_index(device, index)
        return True


def ot_vault_summary(devices: list, verify: bool = True) -> dict:
    """Aggregate OT Project Vault coverage and SHA-256 integrity across devices."""
    by_ip: dict = {}
    devices_with_artifacts = 0
    total_artifacts = 0
    integrity_failures = 0
    for d in devices or []:
        ip = str(d.get("IP") or "")
        versions = list_ot_artifacts(d)
        if not versions:
            continue
        devices_with_artifacts += 1
        total_artifacts += len(versions)
        status = "unverified"
        failures = 0
        if verify:
            check = verify_ot_artifact(d)
            failures = len(check["corrupted"]) + len(check["missing"])
            integrity_failures += failures
            status = "ok" if check["ok"] else "corrupted"
        latest = versions[0]
        by_ip[ip] = {
            "ip": ip,
            "count": len(versions),
            "latest_filename": latest.get("filename", ""),
            "latest_type": latest.get("artifact_type", ""),
            "latest_sha256": latest.get("sha256", ""),
            "latest_uploaded_at": latest.get("uploaded_at", ""),
            "integrity_status": status,
            "failures": failures,
        }
    return {
        "devices": len(devices or []),
        "devices_with_artifacts": devices_with_artifacts,
        "total_artifacts": total_artifacts,
        "integrity_failures": integrity_failures,
        "integrity_ok": integrity_failures == 0,
        "by_ip": by_ip,
    }


def maybe_mirror_offsite() -> None:
    """Runs the offsite mirror after a backup cycle, when configured.

    Imported lazily and never allowed to raise: the mirror is redundancy, and a
    broken remote must not turn a successful backup collection into a failed
    one. The failure is recorded in the mirror's own state and shown in its
    status panel.
    """
    try:
        from services import cloud_backup
        from services.cloud_backup import settings as cb_settings
        cfg = cb_settings.read()
        if not (cfg.get("enabled") and cfg.get("run_after_backup")):
            return
        result = cloud_backup.run_mirror()
        if not result.get("ok"):
            logging.warning("[cloud_backup] mirror non riuscito: %s", result.get("error"))
    except Exception as exc:
        logging.warning("[cloud_backup] mirror non eseguito: %s", exc)
