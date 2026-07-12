# -*- coding: utf-8 -*-
"""Parser syslog → evento normalizzato (fase 3.4).

Formati: RFC 3164 (BSD) e RFC 5424; normalizzazione vendor per FortiGate
(corpo key=value) e Palo Alto (CSV TRAFFIC/THREAT). Output:

    {ts (unix UTC), device_ip, severity (0-7), action (str|None),
     message (troncato a MAX_MESSAGE_LEN)}

Formati sconosciuti: action=None, messaggio raw preservato (troncato —
minimizzazione dei log, vedi piano §6.7). Input malformato non solleva mai.
"""

import re
import time
from datetime import datetime, timezone

from observability import metrics

MAX_MESSAGE_LEN = 2048

_PRI_RE = re.compile(rb"^<(\d{1,3})>")
_RFC5424_RE = re.compile(
    r"^(\d)\s+(\S+)\s+(\S+)\s+")  # version, timestamp, hostname
_BSD_TS_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+")
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

# FortiGate: corpo key=value, es. action="blocked" level="warning"
_FGT_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
_FGT_LEVELS = {"emergency": 0, "alert": 1, "critical": 2, "error": 3,
               "warning": 4, "notice": 5, "information": 6, "debug": 7}


def parse(data: bytes, exporter_ip: str):
    """Parsa un messaggio syslog. Ritorna una lista con al più UN evento
    normalizzato (interfaccia uniforme con gli altri parser)."""
    try:
        return [_parse(data, exporter_ip)]
    except Exception:
        metrics.inc("parse_errors", proto="syslog")
        return []


def _parse(data: bytes, exporter_ip: str) -> dict:
    severity = None
    m = _PRI_RE.match(data)
    if m:
        pri = int(m.group(1))
        severity = pri & 0x07
        data = data[m.end():]
    text = data.decode("utf-8", errors="replace").strip()

    ts = _extract_ts(text)
    action, vendor_severity = _vendor_normalize(text)
    if vendor_severity is not None:
        severity = vendor_severity

    return {
        "ts": ts if ts is not None else int(time.time()),
        "device_ip": exporter_ip,
        "severity": severity,
        "action": action,
        "message": text[:MAX_MESSAGE_LEN],
        "exporter_ip": exporter_ip,
    }


def _extract_ts(text: str):
    # RFC 5424: "1 2026-07-12T10:00:00.000Z host ..."
    m = _RFC5424_RE.match(text)
    if m and m.group(1) == "1":
        try:
            iso = m.group(2).replace("Z", "+00:00")
            return int(datetime.fromisoformat(iso).timestamp())
        except ValueError:
            pass
    # RFC 3164: "Jul 12 10:00:00 host ..." — senza anno né timezone: si assume
    # l'anno corrente e il fuso locale del server (limite noto del formato BSD).
    m = _BSD_TS_RE.match(text)
    if m:
        try:
            now = datetime.now()
            dt = datetime(now.year, _MONTHS[m.group(1)], int(m.group(2)),
                          int(m.group(3)), int(m.group(4)), int(m.group(5)))
            return int(dt.timestamp())
        except (KeyError, ValueError):
            pass
    return None


def _vendor_normalize(text: str):
    """Ritorna (action, severity) estratti dai formati vendor noti."""
    # FortiGate: corpo key=value con chiavi note (logid/devid/action/level)
    if "logid=" in text or ("devid=" in text and "type=" in text):
        kv = {k: (v1 or v2) for k, v1, v2 in _FGT_KV_RE.findall(text)}
        action = kv.get("action") or kv.get("utmaction")
        sev = _FGT_LEVELS.get((kv.get("level") or "").lower())
        return action, sev
    # Palo Alto: CSV, campo 4 = tipo (TRAFFIC/THREAT). Layout PAN-OS:
    # ... ,TRAFFIC,sottotipo,... action tipicamente al campo 31 ma varia per
    # versione: si cerca il primo valore fra i noti dopo il tipo.
    if ",TRAFFIC," in text or ",THREAT," in text:
        fields = text.split(",")
        known = {"allow", "deny", "drop", "reset-both", "reset-client",
                 "reset-server", "alert", "block", "sinkhole"}
        action = next((f.strip() for f in fields if f.strip().lower() in known), None)
        sev = None
        if ",THREAT," in text:
            pan_sev = {"critical": 2, "high": 3, "medium": 4, "low": 5,
                       "informational": 6}
            sev = next((pan_sev[f.strip().lower()] for f in fields
                        if f.strip().lower() in pan_sev), None)
        return action, sev
    return None, None
