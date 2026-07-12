# -*- coding: utf-8 -*-
"""AI Assistant — interfaccia unica di chat verso provider LLM plug-in.

Espone una singola funzione ``chat(messages, provider, model, ...)`` che
inoltra la richiesta al provider selezionato usando semplici chiamate HTTP
(``requests``), senza dipendere dagli SDK ufficiali (non presenti in
requirements.txt e non necessari per una singola chiamata REST).

Provider supportati:
- "anthropic": Claude Messages API (api.anthropic.com)
- "openai":    Chat Completions API (api.openai.com), compatibile anche con
               endpoint OpenAI-compatible passando ``base_url``.
- "gemini":    Google Generative Language API (generativelanguage.googleapis.com)
- "ollama":    endpoint locale/self-hosted compatibile con l'API Ollama
               (``/api/chat``), URL configurabile via ``base_url``.

``messages`` e' sempre una lista di dict ``{"role": "user"|"assistant"|"system", "content": str}``,
indipendentemente dal provider: la funzione traduce nel formato nativo di
ciascuna API. Il modulo non gestisce streaming, tool/agent calling ne' RAG:
solo scambio sincrono di messaggi.
"""

import collections
import threading
import time

import requests

from redaction import redact

DEFAULT_TIMEOUT = 60

# Modello di default sensato per provider quando l'utente non ne specifica uno.
DEFAULT_MODELS = {
    "anthropic": "claude-3-5-sonnet-latest",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-3-flash",
    "ollama": "llama3",
}


def get_default_model(provider: str) -> str:
    """Ritorna il modello di default per il provider indicato (stringa vuota
    se il provider non e' riconosciuto)."""
    return DEFAULT_MODELS.get((provider or "").strip().lower(), "")


class AiAssistantError(Exception):
    """Errore di alto livello per problemi di configurazione o di rete verso il provider."""
    pass


class RateLimitExceededError(AiAssistantError):
    """Superato il limite configurato di richieste/minuto verso il provider AI."""
    pass


class RateLimiter:
    """Limiter a finestra scorrevole (sliding window) in-process, thread-safe.

    ``rpm`` (richieste/minuto) <= 0 disabilita il limite. Implementazione
    volutamente semplice: una deque di timestamp delle richieste accettate
    negli ultimi 60s: niente storage esterno, sufficiente per un singolo
    processo (non condiviso tra più worker/repliche).
    """

    def __init__(self, rpm: int = 0):
        self._lock = threading.Lock()
        self.rpm = rpm or 0
        self._timestamps = collections.deque()

    def configure(self, rpm) -> None:
        with self._lock:
            self.rpm = int(rpm) if rpm else 0

    def allow(self):
        """Ritorna (True, None) se la richiesta è ammessa ora, altrimenti
        (False, secondi_di_attesa_consigliati)."""
        with self._lock:
            if self.rpm <= 0:
                return True, None
            now = time.monotonic()
            window_start = now - 60.0
            while self._timestamps and self._timestamps[0] < window_start:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.rpm:
                retry_after = 60.0 - (now - self._timestamps[0])
                return False, max(0.0, retry_after)
            self._timestamps.append(now)
            return True, None


# Limiter globale condiviso da tutte le chiamate chat() del processo. Il
# valore rpm viene (ri)configurato ad ogni chiamata in base alle impostazioni
# correnti (vedi parametro ``rate_limit_rpm`` di ``chat``).
_rate_limiter = RateLimiter()


def configure_rate_limit(rpm) -> None:
    """Imposta il limite globale di richieste/minuto verso i provider AI
    (0/None/negativo = illimitato)."""
    _rate_limiter.configure(rpm)


def build_tenant_context(tenant: str, *, devices=None, group_info=None, site=None,
                          mac_stats=None, mac_recent=None, scan_summary=None,
                          max_devices=100, max_recent=15) -> str:
    """Costruisce un blocco di contesto compatto (markdown) con le
    informazioni rilevanti per UN SOLO tenant/sede, da usare come messaggio
    di sistema iniettato nella richiesta AI.

    Lo scope è rigorosamente limitato al tenant indicato: il chiamante deve
    aver già filtrato ``devices``/``mac_stats``/``mac_recent`` per quel
    tenant/gruppo prima di passarli qui (questa funzione non applica alcun
    filtro, si limita a formattare).

    - ``devices``: lista di dict inventario (IP/Hostname/Vendor/Group/Site).
    - ``group_info``: dict con 'description' del gruppo/sede (da groups.json).
    - ``site``: dict di sites.json (mode/subnets/last_seen) o lista di tali dict
      se il tenant copre più sedi VPN.
    - ``mac_stats``: dict {sightings, unique_macs, switches, retention_days}.
    - ``mac_recent``: lista di avvistamenti MAC recenti (già filtrati).
    - ``scan_summary``: stringa sintetica sull'ultima scansione di rete.
    """
    devices = devices or []
    mac_recent = mac_recent or []
    lines = [f"## Contesto sede/tenant: {tenant}"]

    if group_info:
        desc = group_info.get("description") if isinstance(group_info, dict) else str(group_info)
        if desc:
            lines.append(f"Descrizione: {desc}")

    sites = site if isinstance(site, list) else ([site] if site else [])
    for s in sites:
        lines.append(
            f"Config sito VPN '{s.get('name', s.get('id', '?'))}': mode={s.get('mode', '?')}, "
            f"subnets={', '.join(s.get('subnets') or []) or '(nessuna)'}, "
            f"last_seen={s.get('last_seen') or 'mai'}"
        )

    lines.append(f"\nDispositivi ({len(devices)} totali):")
    for d in devices[:max_devices]:
        lines.append(
            f"- {d.get('IP', '?')} | {d.get('Hostname', '') or '(senza hostname)'} | "
            f"vendor={d.get('Vendor', '?')} | site={d.get('Site', 'central')}"
        )
    if len(devices) > max_devices:
        lines.append(f"... e altri {len(devices) - max_devices} dispositivi (troncato).")

    if mac_stats:
        lines.append(
            f"\nMAC history: {mac_stats.get('sightings', 0)} avvistamenti, "
            f"{mac_stats.get('unique_macs', 0)} MAC unici, "
            f"{mac_stats.get('switches', 0)} switch coinvolti, "
            f"retention={mac_stats.get('retention_days', '?')}gg"
        )
    if mac_recent:
        lines.append(f"\nUltimi avvistamenti MAC (max {max_recent}):")
        for s in mac_recent[:max_recent]:
            lines.append(
                f"- {s.get('mac', '?')} su switch {s.get('switch_ip', '?')} "
                f"if={s.get('interface', '?')} vlan={s.get('vlan', '?')} "
                f"last_seen={s.get('last_seen', '?')}"
            )

    if scan_summary:
        lines.append(f"\nUltima scansione di rete: {scan_summary}")

    return "\n".join(lines)


def _split_system(messages):
    """Separa gli eventuali messaggi 'system' (concatenati) dal resto della conversazione."""
    system_parts = [m["content"] for m in messages if m.get("role") == "system"]
    convo = [m for m in messages if m.get("role") != "system"]
    return "\n\n".join(system_parts), convo


def _chat_anthropic(messages, model, api_key, timeout):
    if not api_key:
        raise AiAssistantError("API key Anthropic mancante.")
    system, convo = _split_system(messages)
    payload = {
        "model": model or DEFAULT_MODELS["anthropic"],
        "max_tokens": 2048,
        "messages": [{"role": m["role"], "content": m["content"]} for m in convo],
    }
    if system:
        payload["system"] = system
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json=payload,
        timeout=timeout,
    )
    if resp.status_code >= 400:
        raise AiAssistantError(f"Anthropic API error {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    parts = data.get("content") or []
    text = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
    return text


def _chat_openai(messages, model, api_key, timeout, base_url=None):
    if not api_key:
        raise AiAssistantError("API key OpenAI mancante.")
    url = (base_url or "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
    payload = {
        "model": model or DEFAULT_MODELS["openai"],
        "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
    }
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=timeout,
    )
    if resp.status_code >= 400:
        raise AiAssistantError(f"OpenAI API error {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        return ""
    return choices[0].get("message", {}).get("content", "")


def _normalize_gemini_model(model):
    """Normalizza il nome modello Gemini per l'uso nell'URL REST.

    Accetta sia forme brevi (``gemini-3-flash``) sia forme già prefissate
    (``models/gemini-3-flash``, come ritornate da ListModels) e ritorna
    sempre il nome senza prefisso ``models/`` per evitare percorsi doppi
    come ``models/models/...`` (causa dell'errore 400 "unexpected model
    name format").
    """
    name = (model or DEFAULT_MODELS["gemini"]).strip()
    while name.startswith("models/"):
        name = name[len("models/"):]
    return name


def _chat_gemini(messages, model, api_key, timeout):
    if not api_key:
        raise AiAssistantError("API key Gemini mancante.")
    system, convo = _split_system(messages)
    model_name = _normalize_gemini_model(model)
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model_name}:generateContent?key={api_key}"
    )
    role_map = {"assistant": "model", "user": "user"}
    contents = [
        {"role": role_map.get(m["role"], "user"), "parts": [{"text": m["content"]}]}
        for m in convo
    ]
    payload = {"contents": contents}
    if system:
        payload["systemInstruction"] = {"parts": [{"text": system}]}
    resp = requests.post(url, json=payload, timeout=timeout)
    if resp.status_code >= 400:
        raise AiAssistantError(f"Gemini API error {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    candidates = data.get("candidates") or []
    if not candidates:
        return ""
    parts = candidates[0].get("content", {}).get("parts", [])
    return "".join(p.get("text", "") for p in parts)


def _chat_ollama(messages, model, timeout, base_url=None):
    url = (base_url or "http://localhost:11434").rstrip("/") + "/api/chat"
    payload = {
        "model": model or DEFAULT_MODELS["ollama"],
        "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
        "stream": False,
    }
    resp = requests.post(url, json=payload, timeout=timeout)
    if resp.status_code >= 400:
        raise AiAssistantError(f"Ollama endpoint error {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    return data.get("message", {}).get("content", "")


def _list_models_gemini(api_key, timeout):
    if not api_key:
        raise AiAssistantError("API key Gemini mancante.")
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    resp = requests.get(url, timeout=timeout)
    if resp.status_code >= 400:
        raise AiAssistantError(f"Gemini API error {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    models = []
    for m in data.get("models") or []:
        methods = m.get("supportedGenerationMethods") or []
        if "generateContent" not in methods:
            continue
        name = _normalize_gemini_model(m.get("name", ""))
        if name:
            models.append(name)
    return models


# Prefissi/nomi di modelli OpenAI che NON sono chat-capable (embedding, audio,
# immagini, moderazione...): usati per filtrare la risposta di GET /v1/models,
# che elenca indistintamente tutti i modelli disponibili sull'account.
_OPENAI_NON_CHAT_HINTS = (
    "embedding", "whisper", "tts", "dall-e", "moderation", "davinci-002",
    "babbage-002", "text-", "audio", "realtime", "transcribe", "image",
)


def _list_models_openai(api_key, timeout, base_url=None):
    if not api_key:
        raise AiAssistantError("API key OpenAI mancante.")
    url = (base_url or "https://api.openai.com/v1").rstrip("/") + "/models"
    resp = requests.get(
        url, headers={"Authorization": f"Bearer {api_key}"}, timeout=timeout
    )
    if resp.status_code >= 400:
        raise AiAssistantError(f"OpenAI API error {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    models = []
    for m in data.get("data") or []:
        model_id = m.get("id", "")
        if not model_id:
            continue
        if any(hint in model_id.lower() for hint in _OPENAI_NON_CHAT_HINTS):
            continue
        models.append(model_id)
    return sorted(models)


def _list_models_anthropic(api_key, timeout):
    if not api_key:
        raise AiAssistantError("API key Anthropic mancante.")
    resp = requests.get(
        "https://api.anthropic.com/v1/models",
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
        timeout=timeout,
    )
    if resp.status_code >= 400:
        raise AiAssistantError(f"Anthropic API error {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    return [m.get("id") for m in data.get("data") or [] if m.get("id")]


def _list_models_ollama(timeout, base_url=None):
    url = (base_url or "http://localhost:11434").rstrip("/") + "/api/tags"
    resp = requests.get(url, timeout=timeout)
    if resp.status_code >= 400:
        raise AiAssistantError(f"Ollama endpoint error {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    return [m.get("name") for m in data.get("models") or [] if m.get("name")]


def list_models(provider, api_key=None, base_url=None, timeout=DEFAULT_TIMEOUT):
    """Ritorna la lista dei nomi modello disponibili per il provider che
    supportano la chat, quando l'API del provider espone un endpoint
    ListModels: Gemini (``ListModels``), OpenAI (``GET /v1/models``),
    Anthropic (``GET /v1/models``), Ollama (``GET /api/tags`` sul base_url
    configurato)."""
    provider = (provider or "").strip().lower()
    if provider not in _PROVIDERS:
        raise AiAssistantError(f"Provider non supportato: '{provider}'.")
    try:
        if provider == "gemini":
            return _list_models_gemini(api_key, timeout)
        if provider == "openai":
            return _list_models_openai(api_key, timeout, base_url=base_url)
        if provider == "anthropic":
            return _list_models_anthropic(api_key, timeout)
        if provider == "ollama":
            return _list_models_ollama(timeout, base_url=base_url)
        raise AiAssistantError(f"Elenco modelli non supportato per il provider '{provider}'.")
    except AiAssistantError:
        raise
    except requests.RequestException as e:
        raise AiAssistantError(f"Errore di rete verso il provider '{provider}': {e}")


_PROVIDERS = {"anthropic", "openai", "gemini", "ollama"}


def chat(messages, provider, model=None, api_key=None, base_url=None, timeout=DEFAULT_TIMEOUT,
         rate_limit_rpm=None):
    """Invia la conversazione al provider indicato e ritorna il testo della risposta.

    - ``messages``: lista di dict {"role", "content"} (ruoli: system/user/assistant).
    - ``provider``: uno tra "anthropic", "openai", "gemini", "ollama".
    - ``model``: nome modello specifico del provider (opzionale, si usa un default sensato).
    - ``api_key``: richiesta per anthropic/openai/gemini, ignorata per ollama.
    - ``base_url``: endpoint alternativo (usato da ollama per LLM locali, opzionale per openai
      per compatibilita' con endpoint OpenAI-compatible).
    - ``rate_limit_rpm``: se indicato, (ri)configura il limite globale di richieste/minuto
      prima di verificarlo (0/None = illimitato, non modifica il limite già impostato se
      omesso). Solleva ``RateLimitExceededError`` (sottoclasse di ``AiAssistantError``)
      se il limite è superato.
    """
    if not messages:
        raise AiAssistantError("Nessun messaggio da inviare.")
    # Redazione segreti (finding I-1): unico punto di passaggio prima che il
    # contesto lasci il processo verso qualunque provider LLM.
    messages = [dict(m, content=redact(m.get("content", ""))) for m in messages]
    provider = (provider or "").strip().lower()
    if provider not in _PROVIDERS:
        raise AiAssistantError(f"Provider non supportato: '{provider}'.")

    if rate_limit_rpm is not None:
        _rate_limiter.configure(rate_limit_rpm)
    allowed, retry_after = _rate_limiter.allow()
    if not allowed:
        wait_s = f"{retry_after:.0f}" if retry_after is not None else "?"
        raise RateLimitExceededError(
            f"Limite di {_rate_limiter.rpm} richieste/minuto verso il provider AI superato. "
            f"Riprova tra {wait_s}s."
        )

    try:
        if provider == "anthropic":
            return _chat_anthropic(messages, model, api_key, timeout)
        if provider == "openai":
            return _chat_openai(messages, model, api_key, timeout, base_url=base_url)
        if provider == "gemini":
            return _chat_gemini(messages, model, api_key, timeout)
        if provider == "ollama":
            return _chat_ollama(messages, model, timeout, base_url=base_url)
    except AiAssistantError:
        raise
    except requests.RequestException as e:
        raise AiAssistantError(f"Errore di rete verso il provider '{provider}': {e}")
