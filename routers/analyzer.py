# -*- coding: utf-8 -*-
"""Router Analyzer. Estratto da app_server.py (fase 6.6)."""

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel

from core import db
from ai import config_analyzer
from services import inventory_manager
from routers.deps import get_current_user, user_group_scope, assert_device_allowed, require_admin
from security.security_manager import log_audit

router = APIRouter(tags=["Analyzer"])


class ConvertSchema(BaseModel):
    """Corpo per il Config Converter: testo esplicito oppure IP di un
    dispositivo (in tal caso si usa il backup piu' recente)."""
    text: Optional[str] = None
    ip: Optional[str] = None
    source: str  # 'fortios' | 'panos'
    target: str  # 'fortios' | 'panos'


def _load_backup_text(ip: str, current_user) -> str:
    """Testo del backup piu' recente per l'IP, con scoping per sede.
    404 se il dispositivo non esiste o non ha backup."""
    device = assert_device_allowed(current_user, ip)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Dispositivo {ip} non trovato.")
    path, _tenant = config_analyzer._find_freshest_backup(ip)
    if not path:
        raise HTTPException(status_code=404, detail=f"Nessun backup trovato per {ip}.")
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        raise HTTPException(status_code=500, detail=f"Impossibile leggere il backup di {ip}.")
    return "\n".join(config_analyzer.running_config(content))


# --- ENDPOINTS ---

@router.get("/api/config-analyzer")
def config_analyzer_all(group: str = "all", current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    return config_analyzer.analyze_all(group_filter=group, allowed_groups=scope)

@router.get("/api/config-analyzer/{ip}")
def config_analyzer_device(ip: str, current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    device = next((d for d in inventory_manager.get_all_devices() if d.get('IP') == ip), None)
    # An IP absent from inventory is out of scope, not unscoped: analyze_device()
    # reads the freshest backup off disk regardless of inventory, and backups
    # outlive the device row. Same answer download_backup already gives.
    if scope is not None and (device is None
                              or device.get('Group', 'Generale') not in scope):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dispositivo non consentito per il tuo profilo.")
    result = config_analyzer.analyze_device(ip)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Nessun backup trovato per {ip}.")
    return result


@router.post("/api/config-analyzer/convert")
def config_analyzer_convert(payload: ConvertSchema, current_user = Depends(get_current_user)):
    """Conversione deterministica (preview) FortiOS <-> PAN-OS. Accetta testo
    esplicito oppure {ip} -> backup piu' recente del dispositivo (scoped)."""
    text = payload.text
    from_ip = False
    if not text and payload.ip:
        text = _load_backup_text(payload.ip, current_user)
        from_ip = True
    if not text:
        raise HTTPException(status_code=400, detail="Fornire 'text' oppure 'ip'.")
    try:
        result = config_analyzer.convert_config(text, payload.source, payload.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if from_ip:
        result["source_text"] = text
    return result


class ReportPdfSchema(BaseModel):
    """HTML gia' impaginato dall'anteprima, da stampare cosi' com'e'."""
    html: str
    filename: str = "compliance-report"


def _browser_executable() -> Optional[str]:
    """Chrome o Edge gia' installati sulla macchina.

    Il PDF va stampato dallo stesso motore che disegna l'anteprima: qualsiasi
    altro renderer ridisegna il documento con la sua interpretazione di grid e
    flex, e il report consegnato non e' piu' quello che l'operatore ha visto.
    """
    override = os.environ.get("SENTINELNET_BROWSER")
    if override and os.path.isfile(override):
        return override
    candidates = []
    for var in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        base = os.environ.get(var)
        if not base:
            continue
        candidates.append(os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"))
        candidates.append(os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"))
    candidates += ["/usr/bin/google-chrome", "/usr/bin/chromium",
                   "/usr/bin/chromium-browser", "/usr/bin/microsoft-edge"]
    return next((c for c in candidates if os.path.isfile(c)), None)


def _print_argv(exe: str, src: str, out: str, profile_dir: str) -> list:
    """Argv for the headless print. Extracted so the isolation flag below has a
    check that does not need a browser installed."""
    return [
        exe, "--headless=new", "--disable-gpu", "--disable-extensions",
        "--no-first-run", f"--user-data-dir={profile_dir}",
        # The report HTML arrives from the client. Without this, the browser
        # would resolve and fetch any subresource it names -- an authenticated
        # SSRF reading internal services from the appliance's network position
        # and painting the answer into the PDF we hand back. The report is a
        # self-contained local file, so refusing every name costs nothing.
        "--host-resolver-rules=MAP * ~NOTFOUND",
        # Le due varianti del flag: Chrome ignora quella che non conosce.
        "--no-pdf-header-footer", "--print-to-pdf-no-header-footer",
        # Senza budget la stampa parte prima che i font siano pronti e
        # l'impaginazione misurata dallo script slitta.
        "--virtual-time-budget=5000",
        f"--print-to-pdf={out}", Path(src).as_uri(),
    ]


@router.post("/api/netsec-audit/report/pdf")
def netsec_audit_report_pdf(payload: ReportPdfSchema,
                            current_user = Depends(get_current_user)):
    """Stampa in PDF l'HTML dell'anteprima, con il browser di sistema."""
    if len(payload.html) > 40_000_000:
        raise HTTPException(status_code=413, detail="Report troppo grande per la stampa.")
    exe = _browser_executable()
    if exe is None:
        raise HTTPException(
            status_code=503,
            detail="Nessun browser Chrome o Edge trovato per la stampa del report. "
                   "Impostare SENTINELNET_BROWSER con il percorso dell'eseguibile.")

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "report.html")
        out = os.path.join(tmp, "report.pdf")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(payload.html)
        cmd = _print_argv(exe, src, out, os.path.join(tmp, "profile"))
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=180)
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="Stampa del report scaduta.")
        if not os.path.isfile(out):
            err = (proc.stderr or b"").decode("utf-8", "ignore")[-500:]
            raise HTTPException(status_code=500,
                                detail=f"Stampa del report fallita. {err}")
        with open(out, "rb") as fh:
            data = fh.read()

    name = re.sub(r"[^\w.-]+", "_", payload.filename) or "compliance-report"
    log_audit(f"Report di audit '{name}' stampato in PDF "
              f"dall'utente '{current_user.get('sub')}'.")
    return Response(content=data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{name}.pdf"'})


class NetSecAuditSchema(BaseModel):
    config_text: Optional[str] = None
    device_ip: Optional[str] = None
    device_name: Optional[str] = None
    benchmark: str = "cis"  # 'cis' | 'nist' | 'pci'
    # Lingua del REPORT, indipendente da quella dell'interfaccia: un audit si
    # consegna, e il destinatario puo' non leggere la lingua di chi lo esegue.
    lang: str = "it"        # 'it' | 'en'
    # Keep this run in the history. The result stored is the one computed here;
    # nothing about the outcome is ever read from the request.
    save: bool = False
    run_name: Optional[str] = None


@router.get("/api/netsec-audit/benchmarks")
def netsec_audit_benchmarks(lang: str = "it",
                            current_user = Depends(get_current_user)):
    """Requisiti verificati da ciascun benchmark, senza eseguire alcuna scansione."""
    from services import netsec_audit
    from services.netsec_audit import guidance as _guidance
    from services.netsec_audit import messages as _messages

    code = _messages.normalize_lang(lang)

    def _text(value):
        if isinstance(value, dict):
            return value.get(code) or value.get(_messages.DEFAULT_LANG) or ""
        return value or ""

    return {
        key: [
            {
                "id": r["id"],
                "title": _text(r["title"]),
                "severity": r["severity"],
                "category": r["category"],
                "vendor": r["vendor"],
                "ref": r["ref"],
                "level": r["level"],
                "automated": r["automated"],
                "audit": r["audit"],
                # Docstring della regola: descrive cosa viene cercato nella
                # configurazione. Unica fonte, quindi non puo' divergere dal
                # controllo realmente eseguito.
                "checks": (r["check"].__doc__ or "").strip().split("\n")[0],
                "remediation": _text(r["remediation"]),
                "guidance": _guidance.guidance_for(r["check"].__name__, code),
            }
            for r in rules
        ]
        for key, rules in netsec_audit.BENCHMARKS.items()
    }


@router.post("/api/netsec-audit/scan")
def netsec_audit_scan(payload: NetSecAuditSchema, current_user = Depends(get_current_user)):
    """Valutazione di compliance di sicurezza (CIS, NIST, PCI-DSS) su testo o dispositivo."""
    from services import netsec_audit
    text = payload.config_text
    dev_name = payload.device_name
    if not text and payload.device_ip and payload.device_ip != "all":
        # Non ingoiare l'errore: se il dispositivo non esiste o non ha backup,
        # _load_backup_text solleva 404 con dettaglio in italiano. Prima questo
        # veniva catturato e ignorato, producendo un audit su config vuota
        # (risultato privo di significato) senza avvisare l'utente.
        text = _load_backup_text(payload.device_ip, current_user)
        dev_name = payload.device_ip
    elif text and not dev_name:
        dev_name = payload.device_ip or "Uploaded Config"
    if not text or not text.strip():
        # Senza configurazione non c'e' nulla da valutare. Il motore, ricevendo
        # una stringa vuota, non trova alcuna violazione e restituisce un
        # punteggio alto (80% / GRADE A su CIS): un esito inventato e
        # pericolosamente rassicurante. Meglio un errore esplicito.
        # Ricade qui anche device_ip == "all", che non seleziona alcun backup:
        # la scansione multi-dispositivo non e' ancora implementata.
        raise HTTPException(
            status_code=400,
            detail="Nessuna configurazione da analizzare: seleziona un dispositivo "
                   "specifico con un backup disponibile, oppure carica un file di "
                   "configurazione.")
    result = netsec_audit.run_netsec_audit(
        config_text=text,
        device_name=dev_name,
        benchmark=payload.benchmark,
        lang=payload.lang,
    )
    if payload.save:
        from services.netsec_audit import history
        from core.app_settings import get_app_settings
        from security.security_manager import log_audit

        tenant = None
        if payload.device_ip and payload.device_ip != "all":
            device = assert_device_allowed(current_user, payload.device_ip)
            tenant = (device or {}).get("Group") or None
        run_id = history.save(result, tenant=tenant, device_name=dev_name,
                              device_ip=payload.device_ip, actor=current_user.get("sub", ""),
                              run_name=payload.run_name)
        history.prune(int(get_app_settings().get("audit_history_days") or 365))
        log_audit(f"Audit '{payload.benchmark}' salvato nello storico (#{run_id}) "
                  f"da '{current_user.get('sub')}'.")
        result["saved_id"] = run_id
    return result


@router.post("/api/netsec-audit/export/docx")
def netsec_audit_export_docx(payload: Dict[str, Any], current_user = Depends(get_current_user)):
    """Esporta un report di compliance NetSec Audit in formato Microsoft Word (.docx)."""
    from services.netsec_audit.docx_export import generate_audit_docx
    try:
        docx_bytes = generate_audit_docx(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore durante la generazione del file Word: {e}")
    device = (payload.get("device_name") or payload.get("device_ip") or "device").replace(" ", "_")
    filename = f"audit-{device}.docx"
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/api/netsec-audit/history")
async def netsec_audit_history(tenant: Optional[str] = None,
                               device_ip: Optional[str] = None,
                               benchmark: Optional[str] = None,
                               limit: int = 100,
                               current_user = Depends(get_current_user)):
    """Saved runs, newest first. Summary columns only — the stored document is
    fetched one run at a time."""
    scope = user_group_scope(current_user)
    if tenant:
        if scope is not None and tenant not in scope:
            raise HTTPException(status_code=403, detail=f"Tenant '{tenant}' non consentito.")
        tenants = [tenant]
    else:
        tenants = scope

    sql = ("SELECT id, ts, tenant, device_name, device_ip, benchmark, "
           "benchmark_title, vendor, lang, score, summary_json, actor, run_name "
           "FROM netsec_audit_runs WHERE 1=1")
    params: list = []
    if tenants is not None:
        # A run on a pasted config has no tenant; only unrestricted users see it.
        sql += " AND tenant IN (%s)" % ",".join("?" for _ in tenants)
        params.extend(tenants)
    if device_ip:
        sql += " AND device_ip = ?"
        params.append(device_ip)
    if benchmark:
        sql += " AND benchmark = ?"
        params.append(benchmark)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))

    rows = await db.read(sql, tuple(params))
    out = []
    for r in rows:
        item = dict(r)
        if item.get("summary_json"):
            try:
                item["summary"] = json.loads(item["summary_json"])
            except Exception:
                item["summary"] = {}
            del item["summary_json"]
        out.append(item)
    return {"runs": out, "count": len(out)}


@router.get("/api/netsec-audit/history/{run_id}")
async def netsec_audit_history_detail(run_id: int,
                                      current_user = Depends(get_current_user)):
    """Single audit run detail. Returns full result document.
    Out-of-scope and non-existent both return 404."""
    scope = user_group_scope(current_user)
    rows = await db.read("SELECT * FROM netsec_audit_runs WHERE id = ?", (run_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Audit non trovato.")
    row = dict(rows[0])
    row_tenant = row.get("tenant")
    if scope is not None and (row_tenant is None or row_tenant not in scope):
        raise HTTPException(status_code=404, detail="Audit non trovato.")
    try:
        return json.loads(row["result_json"])
    except Exception:
        raise HTTPException(status_code=500, detail="Impossibile leggere il risultato memorizzato.")


@router.delete("/api/netsec-audit/history/{run_id}")
async def netsec_audit_history_delete(run_id: int,
                                      current_user = Depends(require_admin)):
    """Delete a saved audit run. Admin only.
    Out-of-scope and non-existent both return 404."""
    scope = user_group_scope(current_user)
    rows = await db.read("SELECT tenant FROM netsec_audit_runs WHERE id = ?", (run_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Audit non trovato.")
    row_tenant = dict(rows[0]).get("tenant")
    if scope is not None and (row_tenant is None or row_tenant not in scope):
        raise HTTPException(status_code=404, detail="Audit non trovato.")

    conn = db.get_observability_connection()
    try:
        conn.execute("DELETE FROM netsec_audit_runs WHERE id = ?", (run_id,))
        conn.commit()
    finally:
        conn.close()

    log_audit(f"Audit run #{run_id} eliminato dallo storico da '{current_user.get('sub')}'.")
    return {"status": "ok", "deleted": run_id}
