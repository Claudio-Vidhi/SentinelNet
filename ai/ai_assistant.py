# -*- coding: utf-8 -*-
"""AI Assistant — single chat interface towards pluggable LLM providers.

Exposes a single function ``chat(messages, provider, model, ...)`` that
forwards the request to the selected provider using plain HTTP calls
(``requests``), without depending on the official SDKs (not present in
requirements.txt and not needed for a single REST call).

Supported providers:
- "anthropic": Claude Messages API (api.anthropic.com)
- "openai":    Chat Completions API (api.openai.com), also compatible with
               OpenAI-compatible endpoints by passing ``base_url``.
- "gemini":    Google Generative Language API (generativelanguage.googleapis.com)
- "ollama":    local/self-hosted endpoint compatible with the Ollama API
               (``/api/chat``), URL configurable via ``base_url``.

``messages`` is always a list of dicts ``{"role": "user"|"assistant"|"system", "content": str}``,
regardless of the provider: the function translates it into the native format
of each API. The module does not handle streaming, tool/agent calling, nor RAG:
only synchronous message exchange.
"""

import collections
import threading
import time
from typing import Any, Dict, List, Optional

import requests

from security.redaction import redact

DEFAULT_TIMEOUT = 60

# Sensible per-provider default model when the user does not specify one.
DEFAULT_MODELS = {
    "anthropic": "claude-3-5-sonnet-latest",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-3-flash",
    "ollama": "llama3",
}


def get_default_model(provider: str) -> str:
    """Returns the default model for the given provider (empty string
    if the provider is not recognized)."""
    return DEFAULT_MODELS.get((provider or "").strip().lower(), "")


# --- Context budget (fix for 429 RESOURCE_EXHAUSTED) ------------------------
# Limit in CHARACTERS of the total context attached to an AI request
# (rough estimate: 4 characters ~ 1 token). Conservative per-model defaults:
# free-tier models (gemma: 16k tokens/min) require very small budgets,
# flash/pro models handle large contexts. Per-profile override via
# ``context_budget_chars`` (0 = automatic).
_TRUNC_MARKER = "\n... [contesto troncato] ...\n"


def context_char_budget(provider, model, override=0):
    """Context budget in characters for the given model.

    ``override`` > 0 (from the AI profile) always wins; otherwise a
    conservative default based on the model name is applied."""
    try:
        override = int(override or 0)
    except (TypeError, ValueError):
        override = 0
    if override > 0:
        return override
    name = (model or get_default_model(provider) or "").strip().lower()
    if "gemma" in name:
        return 24_000       # free tier: ~16k tokens/min -> ~6k tokens per request
    if any(t in name for t in ("-lite", "-mini", "haiku", "nano")):  # NB: not bare "mini" ("gemini")
        return 100_000
    if (provider or "").strip().lower() == "ollama":
        return 48_000       # local LLMs: typically small context windows
    return 200_000          # flash/pro/sonnet/gpt-4o: ~50k tokens of context


def _question_keywords(question):
    """Meaningful words (>3 characters, lowercase) of the user question."""
    import re
    return {w for w in re.findall(r"[\w.-]{3,}", (question or "").lower())}


def _truncate_head_tail(text, limit):
    """Truncates ``text`` to ~``limit`` characters keeping head and tail, with
    an explicit marker at the cut point."""
    if len(text) <= limit:
        return text
    keep = max(0, limit - len(_TRUNC_MARKER))
    head = int(keep * 0.7)
    tail = keep - head
    return text[:head] + _TRUNC_MARKER + (text[-tail:] if tail else "")


def _filter_relevant_sections(text, keywords, limit):
    """Reduces a configuration block to the budget by keeping the sections most
    relevant to the question (paragraphs separated by an empty line, or
    ``config``/``interface`` blocks...). If no section is relevant it falls
    back to head+tail truncation."""
    import re
    if not keywords or len(text) <= limit:
        return _truncate_head_tail(text, limit)
    # Split into sections: typical config block start lines (FortiOS/IOS)
    # or paragraphs separated by empty lines.
    parts = re.split(r"\n(?=config |interface |router |vlan |policy|!\n)", text)
    if len(parts) < 2:
        parts = re.split(r"\n\s*\n", text)
    scored = []
    for idx, p in enumerate(parts):
        low = p.lower()
        score = sum(1 for k in keywords if k in low)
        scored.append((score, idx, p))
    # Fair share among relevant sections: a single huge section must not
    # exhaust the budget and exclude other matching sections.
    positives = [t for t in scored if t[0] > 0]
    share = max(500, limit // max(1, len(positives))) if positives else limit
    kept = {}
    used = 0
    for score, idx, p in sorted(scored, key=lambda t: (-t[0], t[1])):
        if score <= 0 and kept:
            break
        cap = min(share, max(0, limit - used))
        take = p if len(p) <= cap else _truncate_head_tail(p, cap)
        if not take:
            continue
        kept[idx] = take
        used += len(take) + 1
        if used >= limit:
            break
    if not kept:
        return _truncate_head_tail(text, limit)
    out = "\n".join(kept[i] for i in sorted(kept))
    if len(out) < len(text):
        out += _TRUNC_MARKER
    return out[:limit + len(_TRUNC_MARKER)]


def fit_context(blocks, budget, question=""):
    """Fits the list of context blocks to the character budget.

    If the total exceeds the budget, each block is reduced in proportion to its
    size: large blocks are first filtered to the sections relevant to the
    question, then truncated head+tail with a marker."""
    blocks = [b for b in (blocks or []) if b]
    if budget is None or budget <= 0:
        return blocks
    total = sum(len(b) for b in blocks)
    if total <= budget:
        return blocks
    keywords = _question_keywords(question)
    fitted = []
    for b in blocks:
        # Proportional share, with a minimum so small blocks are not zeroed out.
        share = max(400, int(budget * (len(b) / total)))
        if len(b) <= share:
            fitted.append(b)
        else:
            fitted.append(_filter_relevant_sections(b, keywords, share))
    return fitted


class AiAssistantError(Exception):
    """High-level error for configuration or network problems towards the provider."""
    pass


class RateLimitExceededError(AiAssistantError):
    """Configured requests/minute limit towards the AI provider exceeded."""
    pass


class RateLimiter:
    """In-process, thread-safe sliding window rate limiter.

    ``rpm`` (requests/minute) <= 0 disables the limit. Deliberately simple
    implementation: a deque of timestamps of the requests accepted in the last
    60s; no external storage, sufficient for a single process (not shared
    across multiple workers/replicas).
    """

    def __init__(self, rpm: int = 0):
        self._lock = threading.Lock()
        self.rpm = rpm or 0
        self._timestamps = collections.deque()

    def configure(self, rpm) -> None:
        with self._lock:
            self.rpm = int(rpm) if rpm else 0

    def allow(self):
        """Returns (True, None) if the request is allowed now, otherwise
        (False, suggested_seconds_to_wait)."""
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


# Global limiter shared by all chat() calls in the process. The rpm value
# is (re)configured on each call based on the current settings (see the
# ``rate_limit_rpm`` parameter of ``chat``).
_rate_limiter = RateLimiter()


def configure_rate_limit(rpm) -> None:
    """Sets the global requests/minute limit towards the AI providers
    (0/None/negative = unlimited)."""
    _rate_limiter.configure(rpm)


def build_tenant_context(tenant: str, *, devices=None, group_info=None, site=None,
                          mac_stats=None, mac_recent=None, scan_summary=None,
                          max_devices=100, max_recent=15) -> str:
    """Builds a compact context block (markdown) with the relevant information
    for a SINGLE tenant/site, to be used as a system message injected into the
    AI request.

    The scope is strictly limited to the given tenant: the caller must have
    already filtered ``devices``/``mac_stats``/``mac_recent`` for that
    tenant/group before passing them here (this function applies no filtering,
    it only formats).

    - ``devices``: list of inventory dicts (IP/Hostname/Vendor/Group/Site).
    - ``group_info``: dict with the group/site 'description' (from groups.json).
    - ``site``: dict from sites.json (mode/subnets/last_seen), or a list of such
      dicts if the tenant covers multiple VPN sites.
    - ``mac_stats``: dict {sightings, unique_macs, switches, retention_days}.
    - ``mac_recent``: list of recent MAC sightings (already filtered).
    - ``scan_summary``: short string about the last network scan.
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


def _raise_provider_http_error(provider_label, resp):
    """Translates an HTTP error from the provider into a readable exception.

    A 429 (provider-side quota/rate limit, e.g. Gemini RESOURCE_EXHAUSTED on
    input tokens) becomes a ``RateLimitExceededError`` with a localized message
    instead of the raw provider JSON."""
    if resp.status_code == 429:
        raise RateLimitExceededError(
            f"Quota del provider {provider_label} superata (HTTP 429): limite di "
            "richieste o di token/minuto raggiunto. Riduci il contesto allegato "
            "(meno dispositivi/config, o abbassa il budget contesto nel profilo AI) "
            "oppure riprova tra qualche minuto."
        )
    raise AiAssistantError(f"{provider_label} API error {resp.status_code}: {resp.text[:500]}")


def _split_system(messages):
    """Separates any 'system' messages (concatenated) from the rest of the conversation."""
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
        _raise_provider_http_error("Anthropic", resp)
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
        _raise_provider_http_error("OpenAI", resp)
    data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        return ""
    return choices[0].get("message", {}).get("content", "")


def _normalize_gemini_model(model):
    """Normalizes the Gemini model name for use in the REST URL.

    Accepts both short forms (``gemini-3-flash``) and already-prefixed forms
    (``models/gemini-3-flash``, as returned by ListModels) and always returns
    the name without the ``models/`` prefix to avoid double paths like
    ``models/models/...`` (cause of the 400 error "unexpected model
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
    payload: Dict[str, Any] = {"contents": contents}
    if system:
        payload["systemInstruction"] = {"parts": [{"text": system}]}
    resp = requests.post(url, json=payload, timeout=timeout)
    if resp.status_code >= 400:
        _raise_provider_http_error("Gemini", resp)
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


# Prefixes/names of OpenAI models that are NOT chat-capable (embedding, audio,
# images, moderation...): used to filter the response of GET /v1/models,
# which indiscriminately lists all models available on the account.
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
    """Returns the list of available model names for the providers that
    support chat, when the provider API exposes a ListModels endpoint:
    Gemini (``ListModels``), OpenAI (``GET /v1/models``),
    Anthropic (``GET /v1/models``), Ollama (``GET /api/tags`` on the
    configured base_url)."""
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


def _is_local_base_url(base_url):
    """True if the base_url points to a local/private host (loopback or RFC1918)."""
    import ipaddress
    from urllib.parse import urlparse
    if not base_url:
        return False
    host = urlparse(base_url).hostname or ""
    if host.lower() in ("localhost",):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_loopback or addr.is_private
    except ValueError:
        return False


def chat(messages, provider, model=None, api_key=None, base_url=None, timeout=DEFAULT_TIMEOUT,
         rate_limit_rpm=None, allow_unredacted=False):
    """Sends the conversation to the given provider and returns the response text.

    - ``messages``: list of dicts {"role", "content"} (roles: system/user/assistant).
    - ``provider``: one of "anthropic", "openai", "gemini", "ollama".
    - ``model``: provider-specific model name (optional, a sensible default is used).
    - ``api_key``: required for anthropic/openai/gemini, ignored for ollama.
    - ``base_url``: alternative endpoint (used by ollama for local LLMs, optional for openai
      for compatibility with OpenAI-compatible endpoints).
    - ``rate_limit_rpm``: if given, (re)configures the global requests/minute limit
      before checking it (0/None = unlimited; when omitted, the already-set limit
      is not changed). Raises ``RateLimitExceededError`` (subclass of
      ``AiAssistantError``) if the limit is exceeded.
    """
    if not messages:
        raise AiAssistantError("Nessun messaggio da inviare.")
    provider_norm = (provider or "").strip().lower()
    # Secret redaction (finding I-1): single choke point before the context
    # leaves the process towards any LLM provider. Bypass allowed ONLY for
    # trusted local LLMs (ollama, or endpoints on loopback/private host)
    # and only if the profile explicitly authorizes it — fail-closed otherwise.
    is_local = provider_norm == "ollama" or (provider_norm == "openai" and _is_local_base_url(base_url))
    if not (allow_unredacted and is_local):
        messages = [dict(m, content=redact(m.get("content", ""))) for m in messages]
    provider = provider_norm
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
