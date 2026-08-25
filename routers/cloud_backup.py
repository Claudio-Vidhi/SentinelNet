# -*- coding: utf-8 -*-
"""Routes of the offsite backup mirror.

Admin-only, except status: a triage needs to see whether the copy is current
without holding admin. Every route is audited -- "who pointed our configs at
which host" is a security question.
"""

import asyncio
import json
import posixpath

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers.deps import get_current_user, require_admin, user_group_scope
from security.security_manager import log_audit
from services import cloud_backup
from services.cloud_backup import settings as cb_settings
from services.cloud_backup import sftp as cb_sftp

router = APIRouter(tags=["Cloud Backup"])


class CloudBackupSettingsSchema(BaseModel):
    enabled: bool = False
    kind: str = "sftp"
    host: str = ""
    port: int = 22
    username: str = ""
    auth: str = "key"
    key_path: str = ""
    key_passphrase: str = ""
    password: str = ""
    remote_root: str = ""
    host_key_fingerprint: str = ""
    encrypt_payload: bool = False
    run_after_backup: bool = True
    stale_after_hours: int = 48


@router.get("/api/cloud-backup/settings")
def get_cloud_backup_settings(current_user=Depends(require_admin)):
    return cb_settings.redacted()


@router.put("/api/cloud-backup/settings")
def put_cloud_backup_settings(payload: CloudBackupSettingsSchema,
                              current_user=Depends(require_admin)):
    # Merge onto the currently stored config: settings.save() replaces the
    # whole section with exactly the keys it receives, so a partial payload
    # would silently drop fields the client did not resend.
    cfg = dict(cb_settings.read())
    cfg.update(payload.model_dump())
    errors = cb_settings.validate(cfg)
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    cb_settings.save(cfg)
    log_audit(f"Mirror offsite riconfigurato da '{current_user.get('sub')}' verso "
              f"{cfg['username']}@{cfg['host']}:{cfg['port']}{cfg['remote_root']}.")
    return cb_settings.redacted()


@router.post("/api/cloud-backup/test")
async def test_cloud_backup(current_user=Depends(require_admin)):
    cfg = cb_settings.read()

    def _probe():
        target = cb_sftp.open_target(cfg)
        try:
            root = cfg["remote_root"].rstrip("/")
            target.ensure_dir(root)
            target.put(b"ok\n", posixpath.join(root, ".sentinelnet-write-test"))
            return {"ok": True, "fingerprint": target.fingerprint, "error": None}
        finally:
            target.close()

    try:
        result = await asyncio.to_thread(_probe)
    except Exception as exc:
        result = {"ok": False, "fingerprint": "", "error": str(exc)}
    log_audit(f"Test mirror offsite da '{current_user.get('sub')}': "
              f"{'ok' if result['ok'] else result['error']}.")
    return result


@router.post("/api/cloud-backup/run")
async def run_cloud_backup(current_user=Depends(require_admin)):
    result = await asyncio.to_thread(cloud_backup.run_mirror)
    log_audit(f"Mirror offsite avviato da '{current_user.get('sub')}': "
              f"{result.get('uploaded', 0)} caricati, {result.get('failed', 0)} falliti.")
    return result


@router.get("/api/cloud-backup/status")
def get_cloud_backup_status(current_user=Depends(get_current_user)):
    return cloud_backup.status()


@router.get("/api/cloud-backup/remote")
async def list_cloud_backup_remote(current_user=Depends(require_admin)):
    """What the remote manifest holds, filtered to the caller's tenant scope.
    The first path segment is the tenant, by construction of the layout."""
    cfg = cb_settings.read()
    scope = user_group_scope(current_user)

    def _fetch():
        target = cb_sftp.open_target(cfg)
        try:
            raw = target.get(posixpath.join(cfg["remote_root"].rstrip("/"),
                                            "_manifest.json"))
        finally:
            target.close()
        return json.loads(raw.decode("utf-8"))

    try:
        manifest = await asyncio.to_thread(_fetch)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Remoto non leggibile: {exc}")
    files = manifest.get("files") or {}
    if scope is not None:
        files = {rel: meta for rel, meta in files.items() if rel.split("/")[0] in scope}
    return {"updated_at": manifest.get("updated_at"),
            "encrypted": bool(manifest.get("encrypted")), "files": files}
