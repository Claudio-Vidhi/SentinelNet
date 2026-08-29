# -*- coding: utf-8 -*-
"""Config-backup storage: paths, save, stale-file handling, offsite mirror
(extracted from core_engine.py — plan Phase 3 item 12; core_engine keeps
re-exporting the public names so call sites are unchanged)."""

import logging
import os
from typing import Optional

from core import data_config

BACKUP_FOLDER = data_config.get_path('backup-config')

if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)


def sanitize_filename(filename: str) -> str:
    sanitized = ''.join(
        '_' if char in r'\/:*?"<>| ' else char
        for char in filename
        if ord(char) > 31
    )
    return sanitized or "device_unknown"


def group_backup_dir(group: str, vendor: Optional[str] = None) -> str:
    """Backup folder dedicated to a group/site, with subfolder per
    vendor (backup-config/<group>/<vendor>/), created if absent."""
    path = os.path.join(BACKUP_FOLDER, sanitize_filename(group or "Generale"))
    if vendor:
        path = os.path.join(path, sanitize_filename(vendor.lower()))
    os.makedirs(path, exist_ok=True)
    return path


def save_backup(device, sys_name: str, config_out: str) -> str:
    """Saves the text backup in backup-config/<group>/<vendor>/<name>-<ip>.txt,
    moving first any residual copies of the same IP elsewhere within the tenant."""
    ip = device['IP']
    tenant = device.get('Group', 'Generale')
    group_dir = group_backup_dir(tenant, device.get('Vendor', ''))
    target_name = f"{sanitize_filename(sys_name)}-{ip}.txt"
    remove_stale_backups(ip, new_dir=group_dir, keep=target_name, tenant=tenant)
    file_path = os.path.join(group_dir, target_name)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(config_out)
    return file_path


def remove_stale_backups(ip: str, new_dir: Optional[str] = None, keep: Optional[str] = None, tenant: Optional[str] = None):
    """Move a device's backup and its history when it changes vendor or hostname.

    Scoped strictly to the device's tenant: never walks or moves directories
    belonging to a different tenant.
    """
    if not os.path.exists(BACKUP_FOLDER):
        return
    if tenant is not None:
        walk_root = os.path.join(BACKUP_FOLDER, sanitize_filename(tenant or "Generale"))
        if not os.path.exists(walk_root):
            return
    else:
        walk_root = BACKUP_FOLDER

    for root, _dirs, files in os.walk(walk_root):
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
