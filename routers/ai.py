# -*- coding: utf-8 -*-
"""Router AI. Estratto da app_server.py (fase 6.6)."""

import json
import uuid
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app_settings import get_app_settings, save_app_settings
import crypto_vault
from security_manager import log_audit
from routers.deps import get_current_user, require_admin, user_group_scope, assert_device_allowed, assert_group_allowed
from routers.fortigate import _fgt_device
import inventory_manager
import core_engine
import fortigate_service
import ai_assistant
import config_analyzer
import mac_history
import site_manager

_AI_PROVIDERS = {"anthropic", "openai", "gemini", "ollama"}

router = APIRouter(tags=["AI"])

class AiProfileSchema(BaseModel):
    """Corpo per la creazione di un profilo di connessione AI."""
    name: str
    provider: str  # anthropic | openai | gemini | ollama
    model: str = ""
    api_key: Optional[str] = None
    base_url: str = ""
    rate_limit_rpm: int = 0
    allow_unredacted: bool = False  # invio config NON redatte, solo LLM locali

class AiProfileUpdateSchema(BaseModel):
    """Corpo per l'aggiornamento parziale di un profilo AI esistente
    (tutti i campi opzionali; ``None`` = non modificare, salvo ``api_key``
    per cui stringa vuota = rimuove la chiave salvata)."""
    name: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    rate_limit_rpm: Optional[int] = None
    allow_unredacted: Optional[bool] = None

class AiChatMessage(BaseModel):
    role: str
    content: str

class FlowKeySchema(BaseModel):
    """Identificatori di un flusso selezionato (11.3). SOLO identificatori:
    byte/pacchetti NON sono accettati dal client — il server li ri-deriva dal DB."""
    src_ip: str
    dst_ip: str
    protocol: int
    dst_port: Optional[int] = None

class AiChatSchema(BaseModel):
    messages: List[AiChatMessage]
    attach_inventory: bool = False   # allega un riepilogo dell'inventario dispositivi
    attach_device_ip: Optional[str] = None  # allega la running-config di un dispositivo
    attach_tenant: Optional[str] = None  # allega il contesto completo di un tenant/sede (gruppo)
    attach_fortigate_ip: Optional[str] = None  # allega la config completa LIVE di un FortiGate (API/SSH)
    attach_top_flows: bool = False   # allega il riassunto dei top flussi (observability, scoped)
    attach_flow_keys: Optional[List[FlowKeySchema]] = None  # 11.3: analisi delle sole righe flusso selezionate (max 20)
    attach_device_ips: List[str] = []  # multi-selezione: running-config di più dispositivi del tenant

def _mask_ai_profile(p: dict) -> dict:
    """Rappresentazione di un profilo AI sicura da esporre via API (mai la
    chiave API in chiaro)."""
    return {
        "id": p.get("id"),
        "name": p.get("name", ""),
        # Nessun provider di default: un profilo senza provider esplicito
        # resta vuoto finché l'utente non ne sceglie uno.
        "provider": p.get("provider", ""),
        "model": p.get("model", ""),
        "base_url": p.get("base_url", ""),
        "api_key_set": bool(p.get("api_key_enc")),
        "rate_limit_rpm": p.get("rate_limit_rpm", 0),
        "allow_unredacted": bool(p.get("allow_unredacted", False)),
    }

def _get_ai_profiles_raw():
    """Ritorna (profiles: list[dict], active_id: str|None). Esegue, una
    tantum, la migrazione dal vecchio formato a profilo singolo ("ai") al
    nuovo formato a profili multipli se necessario."""
    settings = get_app_settings()
    profiles = settings.get("ai_profiles")
    active = settings.get("ai_active_profile")
    if profiles is None:
        legacy = settings.get("ai", {}) or {}
        profiles = []
        active = None
        if legacy.get("provider"):
            default_profile = {
                "id": uuid.uuid4().hex,
                "name": "Default",
                "provider": legacy.get("provider", "anthropic"),
                "model": legacy.get("model", ""),
                "base_url": legacy.get("base_url", ""),
                "api_key_enc": legacy.get("api_key_enc", ""),
                "rate_limit_rpm": legacy.get("rate_limit_rpm", 0),
            }
            profiles = [default_profile]
            active = default_profile["id"]
        save_app_settings({"ai_profiles": profiles, "ai_active_profile": active})
    return profiles, active

def _find_ai_profile(profiles, profile_id):
    if not profile_id:
        return None
    for p in profiles:
        if p.get("id") == profile_id:
            return p
    return None

def _get_active_ai_profile():
    profiles, active = _get_ai_profiles_raw()
    return _find_ai_profile(profiles, active)

def _device_inventory_summary(current_user) -> str:
    """Riepilogo testuale sintetico dell'inventario, scopato per sede utente."""
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()
    if scope is not None:
        devices = [d for d in devices if d.get('Group', 'Generale') in scope]
    lines = [f"Inventario dispositivi ({len(devices)} totali):"]
    for d in devices[:200]:  # limite di sicurezza per non gonfiare il contesto
        lines.append(
            f"- {d.get('IP', '?')} | {d.get('Hostname', '') or '(senza hostname)'} | "
            f"vendor={d.get('Vendor', '?')} | sede={d.get('Group', 'Generale')}"
        )
    if len(devices) > 200:
        lines.append(f"... e altri {len(devices) - 200} dispositivi (troncato).")
    return "\n".join(lines)

def _device_running_config_context(ip: str, current_user) -> str:
    """Testo della running-config più recente per un dispositivo (raw), con
    verifica di scoping per sede prima di restituirlo."""
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
    return f"Running-config di {ip}:\n\n{config_analyzer.running_config(content)}"

def _fortigate_live_context(ip: str, current_user) -> str:
    """Contesto AI: configurazione completa LIVE di un FortiGate (API o SSH)
    più stato di sistema, per domande su policy, NAT, VPN, interfacce.
    Best-effort: se il FortiGate non risponde si riporta l'errore nel blocco."""
    from routers.fortigate import _fgt_device
    device = _fgt_device(ip, current_user)
    lines = [f"## FortiGate {ip} — dati live"]
    try:
        st = fortigate_service.get_system_status(device)
        lines.append(f"Stato sistema (fonte {st['source']}):\n{json.dumps(st['data'], ensure_ascii=False)[:4000]}")
    except Exception as e:
        lines.append(f"Stato sistema non disponibile: {e}")
    try:
        cfg = fortigate_service.get_full_config(device)
        text = cfg["data"] if isinstance(cfg["data"], str) else json.dumps(cfg["data"], ensure_ascii=False)
        if len(text) > 120_000:
            text = text[:120_000] + "\n... [config troncata]"
        lines.append(f"Configurazione completa (fonte {cfg['source']}):\n{text}")
    except Exception as e:
        lines.append(f"Configurazione live non disponibile: {e}")
    return "\n\n".join(lines)

def _tenant_context_block(tenant: str, current_user) -> str:
    """Raccoglie TUTTE le informazioni rilevanti per un singolo tenant/sede
    (gruppo) — dispositivi, config del gruppo, MAC history, config sito VPN —
    e le formatta in un blocco di contesto compatto. Lo scope è verificato
    contro l'utente corrente e strettamente limitato al tenant richiesto:
    ogni sorgente dati viene filtrata per quel gruppo prima di essere passata
    al formatter di ai_assistant."""
    assert_group_allowed(current_user, tenant)
    groups = inventory_manager.get_all_groups()
    if tenant not in groups:
        raise HTTPException(status_code=404, detail=f"Sede/tenant '{tenant}' non trovata.")

    devices = [d for d in inventory_manager.get_all_devices() if d.get('Group', 'Generale') == tenant]

    mac_stats = mac_history.stats(tenants=[tenant])
    mac_recent = mac_history.search(tenants=[tenant], limit=15)

    # Le sedi VPN (site_manager) sono un concetto distinto dai gruppi/tenant ma
    # sono referenziate dai dispositivi tramite il campo 'Site': recuperiamo la
    # config di ognuna delle sedi VPN effettivamente usate da questo tenant.
    site_ids = sorted({d.get('Site', 'central') for d in devices})
    sites = [s for s in (site_manager.get_site(sid) for sid in site_ids) if s]

    return ai_assistant.build_tenant_context(
        tenant,
        devices=devices,
        group_info=groups.get(tenant),
        site=sites,
        mac_stats=mac_stats,
        mac_recent=mac_recent,
    )

def _assert_unredacted_allowed(allow_unredacted: bool, provider: str, base_url: str):
    """Rifiuta il flag 'allow_unredacted' su provider NON locali: le config
    non redatte possono raggiungere solo LLM locali fidati (fail-closed)."""
    if not allow_unredacted:
        return
    provider = (provider or "").strip().lower()
    if provider == "ollama" or (provider == "openai" and ai_assistant._is_local_base_url(base_url)):
        return
    raise HTTPException(
        status_code=400,
        detail="L'invio di configurazioni non redatte è consentito solo verso LLM locali "
               "(provider 'ollama' o endpoint OpenAI-compatible su host locale/privato)."
    )

@router.get("/api/ai/profiles")
def list_ai_profiles(current_user = Depends(require_admin)):
    """Elenca i profili di connessione AI salvati (chiavi API mascherate) e
    l'id del profilo attualmente attivo (usato da /api/ai/chat)."""
    profiles, active = _get_ai_profiles_raw()
    return {"profiles": [_mask_ai_profile(p) for p in profiles], "active_profile": active}

@router.post("/api/ai/profiles")
def create_ai_profile(payload: AiProfileSchema, current_user = Depends(require_admin)):
    provider = payload.provider.strip().lower()
    if provider not in _AI_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Provider non supportato: '{provider}'.")
    if not payload.name.strip():
        raise HTTPException(status_code=400, detail="Il nome del profilo è obbligatorio.")
    _assert_unredacted_allowed(payload.allow_unredacted, provider, payload.base_url)
    profiles, active = _get_ai_profiles_raw()
    new_profile = {
        "id": uuid.uuid4().hex,
        "name": payload.name.strip(),
        "provider": provider,
        "model": payload.model.strip(),
        "base_url": payload.base_url.strip(),
        "api_key_enc": crypto_vault.encrypt_password(payload.api_key) if payload.api_key else "",
        "rate_limit_rpm": max(0, int(payload.rate_limit_rpm or 0)),
        "allow_unredacted": bool(payload.allow_unredacted),
    }
    profiles = profiles + [new_profile]
    if active is None:
        active = new_profile["id"]
    save_app_settings({"ai_profiles": profiles, "ai_active_profile": active})
    log_audit(f"Profilo AI '{new_profile['name']}' creato (provider='{provider}') dall'utente '{current_user.get('sub')}'.")
    return _mask_ai_profile(new_profile)

@router.put("/api/ai/profiles/{profile_id}")
def update_ai_profile(profile_id: str, payload: AiProfileUpdateSchema, current_user = Depends(require_admin)):
    profiles, active = _get_ai_profiles_raw()
    profile = _find_ai_profile(profiles, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profilo AI non trovato.")
    if payload.name is not None:
        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Il nome del profilo è obbligatorio.")
        profile["name"] = name
    if payload.provider is not None:
        provider = payload.provider.strip().lower()
        if provider not in _AI_PROVIDERS:
            raise HTTPException(status_code=400, detail=f"Provider non supportato: '{provider}'.")
        profile["provider"] = provider
    if payload.model is not None:
        profile["model"] = payload.model.strip()
    if payload.base_url is not None:
        profile["base_url"] = payload.base_url.strip()
    if payload.rate_limit_rpm is not None:
        profile["rate_limit_rpm"] = max(0, int(payload.rate_limit_rpm or 0))
    # api_key=None -> mantiene quella già salvata; stringa vuota -> la rimuove.
    if payload.api_key is not None:
        profile["api_key_enc"] = crypto_vault.encrypt_password(payload.api_key) if payload.api_key else ""
    if payload.allow_unredacted is not None:
        profile["allow_unredacted"] = bool(payload.allow_unredacted)
    # Difesa in profondità: il flag non-redatto è valido solo su provider locali.
    _assert_unredacted_allowed(profile.get("allow_unredacted", False),
                               profile.get("provider", ""), profile.get("base_url", ""))
    save_app_settings({"ai_profiles": profiles, "ai_active_profile": active})
    log_audit(f"Profilo AI '{profile['name']}' aggiornato dall'utente '{current_user.get('sub')}'.")
    return _mask_ai_profile(profile)

@router.delete("/api/ai/profiles/{profile_id}")
def delete_ai_profile(profile_id: str, current_user = Depends(require_admin)):
    profiles, active = _get_ai_profiles_raw()
    profile = _find_ai_profile(profiles, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profilo AI non trovato.")
    remaining = [p for p in profiles if p.get("id") != profile_id]
    if active == profile_id:
        active = remaining[0]["id"] if remaining else None
    save_app_settings({"ai_profiles": remaining, "ai_active_profile": active})
    log_audit(f"Profilo AI '{profile['name']}' eliminato dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/ai/profiles/{profile_id}/activate")
def activate_ai_profile(profile_id: str, current_user = Depends(require_admin)):
    profiles, _active = _get_ai_profiles_raw()
    profile = _find_ai_profile(profiles, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profilo AI non trovato.")
    save_app_settings({"ai_profiles": profiles, "ai_active_profile": profile_id})
    log_audit(f"Profilo AI attivo impostato su '{profile['name']}' dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "active_profile": profile_id}

@router.get("/api/ai/models")
def list_ai_models(provider: Optional[str] = None, profile_id: Optional[str] = None,
                    current_user = Depends(require_admin)):
    """Elenca i modelli disponibili che supportano la chat per un provider,
    cosi' l'admin puo' sceglierne uno valido invece di indovinare il nome a
    mano. Usa la API key/base_url del profilo indicato (``profile_id``) o di
    quello attivo se omesso; se anche ``provider`` è indicato ed è diverso dal
    provider del profilo, si tenta comunque con la chiave/base_url del
    profilo (utile per verificare un provider prima di salvarlo)."""
    profiles, active = _get_ai_profiles_raw()
    profile = _find_ai_profile(profiles, profile_id) or _find_ai_profile(profiles, active)
    prov = (provider or (profile.get("provider") if profile else "")).strip().lower()
    if not prov:
        raise HTTPException(status_code=400, detail="Nessun provider AI configurato.")
    # I modelli elencati devono appartenere al provider richiesto: se il
    # profilo selezionato usa un ALTRO provider, la sua chiave non è valida
    # per questo elenco; si preferisce un profilo che usi il provider giusto.
    if profile and (profile.get("provider") or "").strip().lower() != prov:
        match = next((p for p in profiles
                      if (p.get("provider") or "").strip().lower() == prov
                      and (p.get("api_key_enc") or prov == "ollama")), None)
        if match:
            profile = match
    api_key = crypto_vault.decrypt_password(profile.get("api_key_enc", "")) if profile and profile.get("api_key_enc") else None
    base_url = (profile.get("base_url") if profile else None) or None
    try:
        models = ai_assistant.list_models(prov, api_key=api_key, base_url=base_url)
    except ai_assistant.AiAssistantError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return {"provider": prov, "models": models, "default_model": ai_assistant.get_default_model(prov)}

@router.post("/api/ai/chat")
def ai_chat(payload: AiChatSchema, current_user = Depends(get_current_user)):
    profile = _get_active_ai_profile()
    if profile is None:
        raise HTTPException(status_code=400, detail="Nessun profilo AI configurato/attivo. Un amministratore deve crearne uno prima.")
    provider = profile.get("provider", "")
    api_key = crypto_vault.decrypt_password(profile.get("api_key_enc", "")) if profile.get("api_key_enc") else None
    if provider != "ollama" and not api_key:
        raise HTTPException(status_code=400, detail="API key non configurata per il profilo AI attivo.")

    messages = [{"role": m.role, "content": m.content} for m in payload.messages]

    context_blocks = []
    if payload.attach_inventory:
        context_blocks.append(_device_inventory_summary(current_user))
    if payload.attach_device_ip:
        context_blocks.append(_device_running_config_context(payload.attach_device_ip, current_user))
    if payload.attach_device_ips:
        # Multi-selezione: running-config di più dispositivi (scoping per-IP).
        # Cap di sicurezza sul numero di device per non gonfiare il contesto.
        for ip in payload.attach_device_ips[:20]:
            if ip == payload.attach_device_ip:
                continue  # già allegato sopra
            context_blocks.append(_device_running_config_context(ip, current_user))
    if payload.attach_tenant:
        context_blocks.append(_tenant_context_block(payload.attach_tenant, current_user))
    if payload.attach_fortigate_ip:
        context_blocks.append(_fortigate_live_context(payload.attach_fortigate_ip, current_user))
    if payload.attach_top_flows or payload.attach_flow_keys:
        # Riassunto server-side (mai contesto raw assemblato dal browser),
        # scoped per tenant; la redazione avviene nel choke-point di chat().
        # 11.3: se sono state selezionate righe specifiche (attach_flow_keys),
        # il contesto è vincolato a quelle tuple — ma lo scope tenant NON viene
        # mai rilassato, e i totali byte/pacchetti sono ri-derivati dal DB
        # (i valori del client vengono ignorati).
        from observability.summary import top_flows_context
        keys = None
        if payload.attach_flow_keys:
            if len(payload.attach_flow_keys) > 20:
                raise HTTPException(status_code=400,
                    detail="Troppi flussi selezionati: massimo 20 righe per analisi.")
            keys = [k.model_dump() for k in payload.attach_flow_keys]
        context_blocks.append(top_flows_context(user_group_scope(current_user), keys=keys))
    if payload.attach_device_ips and current_user.get("role") in ("admin", "operator"):
        # Contratto di proposta config (§10.2): il modello PROPONE, non esegue.
        # Il browser mostra la proposta e, solo dopo conferma esplicita
        # dell'utente, chiama /api/bulk-command (blacklist/RBAC/audit invariati).
        context_blocks.append(
            "Se l'utente chiede una modifica di configurazione su uno dei "
            "dispositivi allegati, oltre alla spiegazione emetti UN blocco "
            "recintato cosi (JSON su una riga, device_ip tra quelli allegati):\n"
            "```sentinelnet-config\n"
            '{"device_ip": "<ip>", "commands": ["<riga config>", "..."], '
            '"config_mode": true, "save_after": false}\n'
            "```\n"
            "Non usare il blocco per comandi show/diagnostici. Non proporre "
            "comandi distruttivi (reload, erase, write erase, format)."
        )
    if context_blocks:
        messages = [{"role": "system", "content": "\n\n".join(context_blocks)}] + messages

    try:
        reply = ai_assistant.chat(
            messages,
            provider=provider,
            model=profile.get("model") or None,
            api_key=api_key,
            base_url=profile.get("base_url") or None,
            rate_limit_rpm=profile.get("rate_limit_rpm", 0),
            allow_unredacted=bool(profile.get("allow_unredacted", False)),
        )
    except ai_assistant.RateLimitExceededError as e:
        raise HTTPException(status_code=429, detail=str(e))
    except ai_assistant.AiAssistantError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return {"reply": reply, "provider": provider, "model": profile.get("model") or ai_assistant.get_default_model(provider),
            "profile_name": profile.get("name", "")}

