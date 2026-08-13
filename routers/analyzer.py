# -*- coding: utf-8 -*-
"""Router Analyzer. Estratto da app_server.py (fase 6.6)."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ai import config_analyzer
from services import inventory_manager
from routers.deps import get_current_user, user_group_scope, assert_device_allowed

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
                              device_ip=payload.device_ip, actor=current_user.get("sub", ""))
        history.prune(int(get_app_settings().get("audit_history_days") or 365))
        log_audit(f"Audit '{payload.benchmark}' salvato nello storico (#{run_id}) "
                  f"da '{current_user.get('sub')}'.")
        result["saved_id"] = run_id
    return result
