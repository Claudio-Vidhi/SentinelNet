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

import requests

DEFAULT_TIMEOUT = 60


class AiAssistantError(Exception):
    """Errore di alto livello per problemi di configurazione o di rete verso il provider."""
    pass


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
        "model": model or "claude-3-5-sonnet-latest",
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
        "model": model or "gpt-4o-mini",
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


def _chat_gemini(messages, model, api_key, timeout):
    if not api_key:
        raise AiAssistantError("API key Gemini mancante.")
    system, convo = _split_system(messages)
    model_name = model or "gemini-1.5-flash"
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
        "model": model or "llama3",
        "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
        "stream": False,
    }
    resp = requests.post(url, json=payload, timeout=timeout)
    if resp.status_code >= 400:
        raise AiAssistantError(f"Ollama endpoint error {resp.status_code}: {resp.text[:500]}")
    data = resp.json()
    return data.get("message", {}).get("content", "")


_PROVIDERS = {"anthropic", "openai", "gemini", "ollama"}


def chat(messages, provider, model=None, api_key=None, base_url=None, timeout=DEFAULT_TIMEOUT):
    """Invia la conversazione al provider indicato e ritorna il testo della risposta.

    - ``messages``: lista di dict {"role", "content"} (ruoli: system/user/assistant).
    - ``provider``: uno tra "anthropic", "openai", "gemini", "ollama".
    - ``model``: nome modello specifico del provider (opzionale, si usa un default sensato).
    - ``api_key``: richiesta per anthropic/openai/gemini, ignorata per ollama.
    - ``base_url``: endpoint alternativo (usato da ollama per LLM locali, opzionale per openai
      per compatibilita' con endpoint OpenAI-compatible).
    """
    if not messages:
        raise AiAssistantError("Nessun messaggio da inviare.")
    provider = (provider or "").strip().lower()
    if provider not in _PROVIDERS:
        raise AiAssistantError(f"Provider non supportato: '{provider}'.")

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
