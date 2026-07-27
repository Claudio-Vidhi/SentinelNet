# -*- coding: utf-8 -*-
"""Router Flow SIEM — registro degli eventi di sicurezza di rete.

La fonte e' ``syslog_events``: e' l'unica tabella che contiene VERDETTI reali
degli apparati (colonna ``action``, popolata dall'ingester syslog). Src/dst/
porte/byte vengono estratti dal corpo key=value del messaggio (FortiGate) con
fallback sulle prime due IP (Palo Alto e generici), come fa gia' il
correlatore.

Perche' non ``flow_aggregates``: quella tabella contiene volumi NetFlow/IPFIX e
NON ha alcuna nozione di ALLOW/DENY. La versione precedente di questo router la
usava e sintetizzava i campi mancanti — azione da ``idx % 5``, porta sorgente da
``1024 + idx*37``, timestamp da ``now - idx*45``, VLAN fissa a 10 — e assegnava
agli eventi un id posizionale (``siem-fl-<indice>``) derivato dal rango per
byte. Quell'id non identificava un evento ma una posizione in classifica: al
refresh successivo lo stesso id puntava a un'altra connessione, e il dettaglio
aperto in UI cambiava contenuto sotto gli occhi dell'utente. Qui l'id e' la
chiave primaria di ``syslog_events``, quindi stabile.
"""

import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core import db
from observability import fieldmap
from routers.deps import get_current_user, user_group_scope

router = APIRouter(prefix="/api/flow-siem", tags=["Flow SIEM"])

MAX_LIMIT = 500

# src_ip/dst_ip/proto/threat_flag non sono colonne: nascono da _to_event() sul
# corpo del messaggio, quindi il filtro non e' esprimibile in SQL e resta in
# Python. Per questo la lettura procede a lotti finche' non ha abbastanza
# corrispondenze, invece di filtrare un unico blocco di righe recenti: con un
# blocco solo un IP raro presente nelle faccette (che scandiscono 2000 righe)
# non compariva mai in tabella. Tetto di righe grezze esaminate per richiesta.
MAX_SCAN = 20000

# Campi filtrabili in modo esatto con la sintassi "campo:valore" nella query.
# Serve perche' la ricerca libera guarda TUTTI i campi: cliccare un IP fra le
# sorgenti restituiva anche le righe in cui quell'IP e' la destinazione, e con
# quelle piu' numerose le righe volute finivano fuori dalla prima pagina.
_FILTER_FIELDS = ("src_ip", "dst_ip", "action", "threat_flag", "proto",
                  "device_ip", "tenant")

_PROTO_NUM = fieldmap.PROTO_NUM
_SECURITY_ACTIONS = fieldmap.SECURITY_ACTIONS


def _window_to_seconds(window: str) -> int:
    w = (window or "24h").lower()
    try:
        if w.endswith("m"):
            return max(60, int(w[:-1]) * 60)
        if w.endswith("h"):
            return max(60, int(w[:-1]) * 3600)
        if w.endswith("d"):
            return max(60, int(w[:-1]) * 86400)
    except ValueError:
        pass
    return 86400


def _tenant_filter(current_user):
    """Clausola SQL per lo scope multi-gruppo dell'utente.

    Identica a quella di ``routers/observability.py``. Il router Flow SIEM non
    la applicava affatto: un utente limitato a una sede vedeva gli eventi di
    tutte le sedi.
    """
    scope = user_group_scope(current_user)
    if scope is None:
        return "", ()
    groups = sorted(scope)
    placeholders = ",".join("?" * len(groups))
    return f" AND tenant IN ({placeholders})", tuple(groups)


# L'estrazione vive in observability/fieldmap.py: era duplicata qui e nel
# correlatore, con set di campi diversi. Questi restano come nomi locali usati
# nel resto del modulo.
_kv = fieldmap.kv
_int_or_none = fieldmap.int_or_none


def _endpoints(message: str, kv: dict):
    """(src_ip, dst_ip) dal messaggio: kv FortiGate, altrimenti prime due IP."""
    return fieldmap.endpoints(message, kv)


def _is_deny(action: Optional[str]) -> bool:
    return fieldmap.is_security_action(action)


def _threat_flag(dst_ip: Optional[str], is_deny: bool,
                 severity: Optional[int], nbytes: Optional[int]) -> str:
    """Etichetta derivata SOLO da dati reali dell'evento."""
    if is_deny:
        return "BLOCKED_TRAFFIC"
    if severity is not None and severity <= 3:
        return "HIGH_SEVERITY"
    if nbytes and nbytes > 1_000_000:
        return "HIGH_VOLUME_TRANSFER"
    if dst_ip in ("8.8.8.8", "1.1.1.1"):
        return "EXTERNAL_DNS"
    return "NORMAL"


def _to_event(row: dict) -> dict:
    """Riga di syslog_events -> evento SIEM. Nessun campo inventato: cio' che
    il messaggio non contiene resta None e la UI mostra un trattino."""
    message = row.get("message") or ""
    kv = _kv(message)
    src, dst = _endpoints(message, kv)
    action_raw = row.get("action") or kv.get("action")
    deny = _is_deny(action_raw)
    sent = _int_or_none(kv.get("sentbyte")) or 0
    rcvd = _int_or_none(kv.get("rcvdbyte")) or 0
    nbytes = (sent + rcvd) or None
    proto = kv.get("proto") or kv.get("service")
    if proto:
        proto = _PROTO_NUM.get(str(proto), str(proto).upper())
    severity = _int_or_none(row.get("severity"))
    return {
        "id": row.get("id"),                     # chiave primaria: stabile
        "timestamp": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(row.get("ts") or 0)),
        "ts": row.get("ts"),
        "tenant": row.get("tenant"),
        "device_ip": row.get("device_ip"),
        "severity": severity,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": _int_or_none(kv.get("srcport")),
        "dst_port": _int_or_none(kv.get("dstport")),
        "proto": proto,
        "bytes": nbytes,
        "action": (action_raw or "").upper() or None,
        "is_deny": deny,
        "threat_flag": _threat_flag(dst, deny, severity, nbytes),
        "message": message,
    }


def _parse_field_query(q: Optional[str]):
    """"src_ip:10.0.1.2" -> ("src_ip", "10.0.1.2"). Altrimenti (None, None).

    Un prefisso non riconosciuto NON viene interpretato come campo: resta
    ricerca libera, cosi' scrivere "8.8.8.8:53" continua a funzionare.
    """
    if not q or ":" not in q:
        return None, None
    key, _, val = q.partition(":")
    key, val = key.strip().lower(), val.strip()
    if key in _FILTER_FIELDS and val:
        return key, val.lower()
    return None, None


def _field_value(event: dict, field: str):
    """Valore su cui confrontare, nella forma mostrata dalle faccette.

    Per ``action`` le faccette etichettano ogni verdetto di blocco come DENY
    (il device puo' scrivere 'blocked', 'drop', ...): senza questa
    normalizzazione cliccare la faccetta DENY non troverebbe quelle righe.
    """
    if field == "action":
        return "DENY" if event["is_deny"] else (event["action"] or "N/D")
    return event.get(field)


@router.get("/events")
async def get_flow_siem_events(
    q: Optional[str] = Query(None, description="Sottostringa su IP, azione, device, messaggio"),
    window: str = Query("24h", description="Finestra temporale (15m, 1h, 24h, 7d)"),
    action: Optional[str] = Query(None, description="Filtro: ALLOW / DENY"),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    current_user=Depends(get_current_user),
):
    """Registro eventi di sicurezza, ordinato dal piu' recente."""
    cutoff = int(time.time()) - _window_to_seconds(window)
    clause, params = _tenant_filter(current_user)

    want_deny = action.strip().upper() == "DENY" if action else None
    field, value = _parse_field_query(q)
    needle = None if field else (q.lower() if q else None)

    def keep(e: dict) -> bool:
        if want_deny is not None and e["is_deny"] != want_deny:
            return False
        if field:
            return str(_field_value(e, field) or "").lower() == value
        if needle is None:
            return True
        return needle in " ".join(
            str(v) for v in (e["src_ip"], e["dst_ip"], e["action"], e["proto"],
                             e["device_ip"], e["tenant"], e["threat_flag"],
                             e["message"]) if v).lower()

    wanted = offset + limit
    batch = min(max(limit * 4, 500), MAX_LIMIT * 4)
    events: list = []
    scanned = 0

    while len(events) < wanted and scanned < MAX_SCAN:
        rows = await db.read(
            f"""SELECT s.id, s.ts, s.tenant, s.device_ip, s.severity, s.action,
                       s.message
                FROM syslog_events AS s
                WHERE s.ts >= ?{clause}
                  AND NOT EXISTS (SELECT 1 FROM siem_suppressions x
                                  WHERE x.event_id = s.id)
                ORDER BY s.ts DESC, s.id DESC
                LIMIT ? OFFSET ?""",
            (cutoff, *params, batch, scanned)) or []
        if not rows:
            break
        scanned += len(rows)
        events.extend(e for e in (_to_event(dict(r)) for r in rows) if keep(e))
        if len(rows) < batch:
            break

    return {
        "total": len(events),
        "limit": limit,
        "offset": offset,
        "events": events[offset:offset + limit],
    }


@router.get("/histogram")
async def get_flow_siem_histogram(
    window: str = Query("24h"),
    buckets: int = Query(30, ge=10, le=100),
    current_user=Depends(get_current_user),
):
    """Istogramma reale degli eventi per bucket temporale.

    La versione precedente non interrogava affatto il database: i valori erano
    ``abs(sin(i * 0.4)) * 45`` e i deny il 15% di quelli. Le barre disegnate
    erano una sinusoide.
    """
    window_s = _window_to_seconds(window)
    bucket_sec = max(1, window_s // buckets)
    now = int(time.time())
    start = now - window_s
    clause, params = _tenant_filter(current_user)

    rows = await db.read(
        f"""SELECT ((ts - ?) / ?) AS bucket_index,
                   COUNT(*) AS n,
                   SUM(CASE WHEN lower(coalesce(action,'')) IN
                       ({",".join("?" * len(_SECURITY_ACTIONS))})
                       THEN 1 ELSE 0 END) AS denies
            FROM syslog_events
            WHERE ts >= ?{clause}
            GROUP BY bucket_index""",
        (start, bucket_sec, *_SECURITY_ACTIONS, start, *params)) or []

    counts = {}
    for r in rows:
        idx = _int_or_none(dict(r).get("bucket_index"))
        if idx is not None and 0 <= idx < buckets:
            d = dict(r)
            counts[idx] = (d.get("n") or 0, d.get("denies") or 0)

    result = []
    for i in range(buckets):
        n, denies = counts.get(i, (0, 0))
        result.append({
            "bucket_index": i,
            "timestamp": time.strftime(
                "%H:%M", time.localtime(start + i * bucket_sec)),
            "count": n,
            "deny_count": denies,
        })

    return {"window": window, "bucket_sec": bucket_sec, "buckets": result}


@router.get("/facets")
async def get_flow_siem_facets(
    window: str = Query("24h"),
    current_user=Depends(get_current_user),
):
    """Conteggi aggregati reali (top sorgenti/destinazioni, azioni, threat)."""
    cutoff = int(time.time()) - _window_to_seconds(window)
    clause, params = _tenant_filter(current_user)

    # Stessa esclusione delle soppressioni applicata da /events: senza, una
    # faccetta poteva contare eventi che la tabella non mostra piu'.
    rows = await db.read(
        f"""SELECT s.id, s.ts, s.tenant, s.device_ip, s.severity, s.action,
                   s.message
            FROM syslog_events AS s
            WHERE s.ts >= ?{clause}
              AND NOT EXISTS (SELECT 1 FROM siem_suppressions x
                              WHERE x.event_id = s.id)
            ORDER BY s.ts DESC
            LIMIT 2000""",
        (cutoff, *params)) or []

    src_counts, dst_counts, threat_counts, action_counts = {}, {}, {}, {}
    for r in rows:
        e = _to_event(dict(r))
        if e["src_ip"]:
            src_counts[e["src_ip"]] = src_counts.get(e["src_ip"], 0) + 1
        if e["dst_ip"]:
            dst_counts[e["dst_ip"]] = dst_counts.get(e["dst_ip"], 0) + 1
        threat_counts[e["threat_flag"]] = threat_counts.get(e["threat_flag"], 0) + 1
        label = "DENY" if e["is_deny"] else (e["action"] or "N/D")
        action_counts[label] = action_counts.get(label, 0) + 1

    def top_n(d, n=5):
        return [{"value": k, "count": v}
                for k, v in sorted(d.items(), key=lambda x: x[1],
                                   reverse=True)[:n]]

    return {
        "top_src_ips": top_n(src_counts),
        "top_dst_ips": top_n(dst_counts),
        "threat_flags": top_n(threat_counts),
        "actions": top_n(action_counts, 6),
        "events_considered": len(rows),
    }


class AlertSuppressSchema(BaseModel):
    event_id: int
    reason: Optional[str] = "Confermato falso positivo"


@router.post("/alerts/suppress")
async def suppress_flow_siem_alert(payload: AlertSuppressSchema,
                                   current_user=Depends(get_current_user)):
    """Sopprime un'allerta, PERSISTENDOLA.

    Prima rispondeva ``{"suppressed": true}`` senza scrivere nulla: l'allerta
    ricompariva al refresh successivo. L'evento va anche verificato nello scope
    dell'utente, altrimenti si potrebbe sopprimere un'allerta di un'altra sede.
    """
    clause, params = _tenant_filter(current_user)
    rows = await db.read(
        f"""SELECT id, tenant FROM syslog_events
            WHERE id = ?{clause} LIMIT 1""",
        (payload.event_id, *params)) or []
    if not rows:
        raise HTTPException(
            status_code=404,
            detail=f"Evento {payload.event_id} non trovato o non accessibile.")

    tenant = dict(rows[0]).get("tenant")
    db.enqueue_write(
        """INSERT OR REPLACE INTO siem_suppressions
               (event_id, ts, tenant, reason, suppressed_by)
           VALUES (?, ?, ?, ?, ?)""",
        (payload.event_id, int(time.time()), tenant, payload.reason,
         (current_user or {}).get("sub")))

    return {"status": "success", "event_id": payload.event_id,
            "suppressed": True}
