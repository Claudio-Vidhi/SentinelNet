# -*- coding: utf-8 -*-
"""Riassunti dei dati di flusso per contesti LLM (fase 5.4).

NOTA sul DB: queste funzioni usano una connessione sincrona breve e sono
pensate per essere chiamate SOLO da endpoint FastAPI ``def`` (sincroni,
eseguiti nel threadpool) — mai da codice ``async def`` (regola async-DB,
CONTRIBUTING.md §3). Il contesto prodotto è già aggregato/top-N (mai dump
raw) e passa comunque dal choke-point di redazione in ai_assistant.chat().
"""

import time

from core import db


def top_flows_context(scope, window_s: int = 900, limit: int = 20,
                      keys=None) -> str:
    """Blocco markdown con i top flussi della finestra, scoped per tenant.
    ``scope``: set di gruppi consentiti oppure None (nessuna restrizione).
    ``keys`` (11.3): lista opzionale di dict {src_ip, dst_ip, protocol, dst_port}
    per vincolare il contesto alle sole righe selezionate. Lo scope tenant NON
    viene MAI rilassato dai key forniti dal client; i totali byte/pacchetti sono
    ri-derivati qui dal DB (i volumi eventualmente inviati dal client sono
    ignorati). ``keys`` None/vuoto → comportamento invariato (intera finestra)."""
    cutoff = int(time.time()) - window_s
    clause, params = "", ()
    if scope is not None:
        groups = sorted(scope)
        clause = f" AND tenant IN ({','.join('?' * len(groups))})"
        params = tuple(groups)
    # Vincolo per-tupla (solo query flussi, mai le anomalie). Lo scope tenant
    # sopra resta applicato in AND, quindi i key fuori scope non possono
    # estrarre righe di altri tenant.
    flow_clause, flow_params = "", ()
    if keys:
        parts, kparams = [], []
        for k in keys:
            dport = k.get("dst_port")
            if dport is None:
                parts.append("(src_ip = ? AND dst_ip = ? AND protocol = ? "
                             "AND dst_port IS NULL)")
                kparams.extend([k["src_ip"], k["dst_ip"], k["protocol"]])
            else:
                parts.append("(src_ip = ? AND dst_ip = ? AND protocol = ? "
                             "AND dst_port = ?)")
                kparams.extend([k["src_ip"], k["dst_ip"], k["protocol"], dport])
        flow_clause = " AND (" + " OR ".join(parts) + ")"
        flow_params = tuple(kparams)
    conn = db.get_observability_connection()
    try:
        rows = conn.execute(
            f"""SELECT tenant, src_ip, dst_ip, protocol, dst_port,
                       SUM(total_bytes) AS b, SUM(total_packets) AS p
                FROM flow_aggregates WHERE window_start >= ?{clause}{flow_clause}
                GROUP BY tenant, src_ip, dst_ip, protocol, dst_port
                ORDER BY b DESC LIMIT ?""",
            (cutoff, *params, *flow_params, limit)).fetchall()
        anomalies = conn.execute(
            f"""SELECT created_ts, tenant, kind, src_ip, dst_ip, switch_port,
                       severity
                FROM correlated_events WHERE status != 'resolved'
                  AND created_ts >= ?{clause}
                ORDER BY created_ts DESC LIMIT 10""",
            (int(time.time()) - 86400, *params)).fetchall()
    finally:
        conn.close()

    lines = [f"## Top flussi di rete (ultimi {window_s // 60} minuti, "
             f"{len(rows)} aggregati)"]
    if not rows:
        lines.append("(nessun flusso registrato nella finestra)")
    for r in rows:
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(r["protocol"], r["protocol"])
        lines.append(f"- [{r['tenant']}] {r['src_ip']} → {r['dst_ip']} "
                     f"{proto}/{r['dst_port'] or '-'}: {r['b']} byte, {r['p']} pacchetti")
    if anomalies:
        lines.append("\n## Anomalie correlate aperte (ultime 24h)")
        for a in anomalies:
            port = f" — porta {a['switch_port']}" if a["switch_port"] else ""
            lines.append(f"- [{a['tenant']}] {a['kind']} sev={a['severity']}: "
                         f"{a['src_ip']} → {a['dst_ip']}{port}")
    return "\n".join(lines)
