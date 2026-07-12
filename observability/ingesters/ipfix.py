# -*- coding: utf-8 -*-
"""Decoder IPFIX (RFC 7011) + NetFlow v9 + NetFlow v5 → record di flusso
normalizzati (fase 3.3).

Record normalizzato (dict):
    src_ip, dst_ip, protocol, dst_port, bytes, packets, flow_end_ts (unix, o
    None se non presente), exporter_ip

Gestione template (v9/IPFIX):
- cache per (exporter_ip, observation_domain_id, template_id), bounded
  (MAX_TEMPLATES, eviction del più vecchio) con scadenza TEMPLATE_TTL_S;
- data set arrivati PRIMA del loro template: bufferizzati (bounded) e
  ridecodificati all'arrivo del template; overflow → scarto con metrica
  ``data_before_template_dropped``;
- ri-annuncio di un template: sostituzione pulita (il buffer pendente per
  quella chiave viene ritentato).

IE non riconosciuti vengono saltati (serve solo la lunghezza); campi
variable-length IPFIX e enterprise number gestiti da RFC. Input malformato
non solleva mai: ritorna i record decodificabili e conteggia
``parse_errors`` via il modulo metrics.
"""

import ipaddress
import struct
import time

from observability import metrics

MAX_TEMPLATES = 1024          # cache template complessiva
TEMPLATE_TTL_S = 1800
MAX_PENDING_SETS = 256        # data set bufferizzati in attesa di template

# IE IPFIX/v9 rilevanti (id → nome interno)
_IE_SRC4, _IE_DST4 = 8, 12
_IE_SRC6, _IE_DST6 = 27, 28
_IE_SRCPORT, _IE_DSTPORT = 7, 11
_IE_PROTO = 4
_IE_BYTES, _IE_PKTS = 1, 2
_IE_END_S, _IE_END_MS = 151, 153

# cache template: key -> (fields[(ie, length)], created_ts)
_templates: dict = {}
# data pendenti: key -> list[(payload, exporter_ip, export_ts)]
_pending: dict = {}


def reset_state():
    """Solo per i test."""
    _templates.clear()
    _pending.clear()


def template_cache_size() -> int:
    return len(_templates)


def parse(data: bytes, exporter_ip: str):
    """Entry point: decodifica un datagramma NetFlow v5/v9 o IPFIX.
    Ritorna una lista (eventualmente vuota) di record normalizzati."""
    try:
        if len(data) < 4:
            return []
        version = struct.unpack_from("!H", data, 0)[0]
        if version == 5:
            return _parse_v5(data, exporter_ip)
        if version == 9:
            return _parse_v9(data, exporter_ip)
        if version == 10:
            return _parse_ipfix(data, exporter_ip)
        metrics.inc("parse_errors", proto="netflow")
        return []
    except Exception:
        metrics.inc("parse_errors", proto="netflow")
        return []


def _record(src, dst, proto, dport, nbytes, npkts, end_ts, exporter_ip):
    return {
        "src_ip": src, "dst_ip": dst, "protocol": proto, "dst_port": dport,
        "bytes": nbytes, "packets": npkts, "flow_end_ts": end_ts,
        "exporter_ip": exporter_ip,
    }


# --- NetFlow v5 (formato fisso) ----------------------------------------------

_V5_HEADER = struct.Struct("!HHIIIIBBH")
_V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")  # 48 byte (pad finale incluso)


def _parse_v5(data: bytes, exporter_ip: str):
    hdr = _V5_HEADER.unpack_from(data, 0)
    count, unix_secs = hdr[1], hdr[3]
    out = []
    offset = 24
    for _ in range(min(count, 30)):
        if offset + 48 > len(data):
            break
        r = _V5_RECORD.unpack_from(data, offset)
        out.append(_record(
            str(ipaddress.IPv4Address(r[0])), str(ipaddress.IPv4Address(r[1])),
            r[13], r[10], r[6], r[5], unix_secs, exporter_ip))
        offset += 48
    return out


# --- NetFlow v9 / IPFIX (template-based) --------------------------------------

def _evict_if_needed():
    if len(_templates) <= MAX_TEMPLATES:
        return
    now = time.monotonic()
    # prima i template scaduti, poi il più vecchio
    expired = [k for k, (_f, ts) in _templates.items() if now - ts > TEMPLATE_TTL_S]
    for k in expired:
        _templates.pop(k, None)
    while len(_templates) > MAX_TEMPLATES:
        oldest = min(_templates, key=lambda k: _templates[k][1])
        _templates.pop(oldest)


def _store_template(key, fields):
    _templates[key] = (fields, time.monotonic())
    _evict_if_needed()
    # ritenta i data set pendenti per questo template
    for payload, exporter_ip, export_ts in _pending.pop(key, []):
        recs = _decode_data(payload, fields, exporter_ip, export_ts)
        _decoded_pending.extend(recs)


# I record rigenerati dal buffer pendente vengono accumulati qui e drenati
# dal chiamante nel parse corrente.
_decoded_pending: list = []


def _get_template(key):
    entry = _templates.get(key)
    if not entry:
        return None
    fields, ts = entry
    if time.monotonic() - ts > TEMPLATE_TTL_S:
        _templates.pop(key, None)
        return None
    return fields


def _buffer_pending(key, payload, exporter_ip, export_ts):
    total = sum(len(v) for v in _pending.values())
    if total >= MAX_PENDING_SETS:
        metrics.inc("data_before_template_dropped")
        return
    _pending.setdefault(key, []).append((payload, exporter_ip, export_ts))


def _decode_data(payload: bytes, fields, exporter_ip: str, export_ts: int):
    reclen = sum(l for _ie, l in fields if l != 65535)
    has_var = any(l == 65535 for _ie, l in fields)
    out = []
    offset = 0
    while True:
        if has_var:
            rec, offset = _decode_one_var(payload, offset, fields)
            if rec is None:
                break
        else:
            if offset + reclen > len(payload) or reclen == 0:
                break
            rec = {}
            pos = offset
            for ie, length in fields:
                rec[ie] = payload[pos:pos + length]
                pos += length
            offset += reclen
        out.append(_normalize(rec, exporter_ip, export_ts))
    return [r for r in out if r]


def _decode_one_var(payload, offset, fields):
    rec = {}
    pos = offset
    try:
        for ie, length in fields:
            if length == 65535:  # variable-length (RFC 7011 §7)
                if pos >= len(payload):
                    return None, offset
                l = payload[pos]
                pos += 1
                if l == 255:
                    l = struct.unpack_from("!H", payload, pos)[0]
                    pos += 2
                length = l
            if pos + length > len(payload):
                return None, offset
            rec[ie] = payload[pos:pos + length]
            pos += length
    except struct.error:
        return None, offset
    return rec, pos


def _uint(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0


def _normalize(rec: dict, exporter_ip: str, export_ts: int):
    src = dst = None
    if _IE_SRC4 in rec and len(rec[_IE_SRC4]) == 4:
        src = str(ipaddress.IPv4Address(rec[_IE_SRC4]))
    elif _IE_SRC6 in rec and len(rec[_IE_SRC6]) == 16:
        src = str(ipaddress.IPv6Address(rec[_IE_SRC6]))
    if _IE_DST4 in rec and len(rec[_IE_DST4]) == 4:
        dst = str(ipaddress.IPv4Address(rec[_IE_DST4]))
    elif _IE_DST6 in rec and len(rec[_IE_DST6]) == 16:
        dst = str(ipaddress.IPv6Address(rec[_IE_DST6]))
    if not src or not dst:
        return None
    end_ts = None
    if _IE_END_S in rec:
        end_ts = _uint(rec[_IE_END_S])
    elif _IE_END_MS in rec:
        end_ts = _uint(rec[_IE_END_MS]) // 1000
    else:
        end_ts = export_ts
    return _record(src, dst, _uint(rec.get(_IE_PROTO, b"")) or None,
                   _uint(rec.get(_IE_DSTPORT, b"")) or None,
                   _uint(rec.get(_IE_BYTES, b"")), _uint(rec.get(_IE_PKTS, b"")),
                   end_ts, exporter_ip)


def _parse_template_set(payload: bytes, exporter_ip: str, odid: int,
                        enterprise_capable: bool):
    """Decodifica un template set (v9 id=0 / IPFIX id=2) e registra i template."""
    offset = 0
    while offset + 4 <= len(payload):
        tid, field_count = struct.unpack_from("!HH", payload, offset)
        offset += 4
        fields = []
        ok = True
        for _ in range(field_count):
            if offset + 4 > len(payload):
                ok = False
                break
            ie, length = struct.unpack_from("!HH", payload, offset)
            offset += 4
            if enterprise_capable and ie & 0x8000:
                ie &= 0x7FFF
                offset += 4  # enterprise number: salta
                ie = -ie     # IE enterprise: mai matchato dai nostri IE noti
            fields.append((ie, length))
        if ok and fields:
            _store_template((exporter_ip, odid, tid), fields)


def _parse_v9(data: bytes, exporter_ip: str):
    _ver, _count, _uptime, unix_secs, _seq, source_id = struct.unpack_from("!HHIIII", data, 0)
    out = []
    offset = 20
    while offset + 4 <= len(data):
        set_id, set_len = struct.unpack_from("!HH", data, offset)
        if set_len < 4 or offset + set_len > len(data):
            break
        payload = data[offset + 4: offset + set_len]
        if set_id == 0:
            _parse_template_set(payload, exporter_ip, source_id, enterprise_capable=False)
        elif set_id == 1:
            pass  # options template: non usato
        elif set_id > 255:
            key = (exporter_ip, source_id, set_id)
            fields = _get_template(key)
            if fields:
                out.extend(_decode_data(payload, fields, exporter_ip, unix_secs))
            else:
                _buffer_pending(key, payload, exporter_ip, unix_secs)
        offset += set_len
    out.extend(_drain_pending_decoded())
    return out


def _parse_ipfix(data: bytes, exporter_ip: str):
    _ver, _length, export_time, _seq, odid = struct.unpack_from("!HHIII", data, 0)
    out = []
    offset = 16
    while offset + 4 <= len(data):
        set_id, set_len = struct.unpack_from("!HH", data, offset)
        if set_len < 4 or offset + set_len > len(data):
            break
        payload = data[offset + 4: offset + set_len]
        if set_id == 2:
            _parse_template_set(payload, exporter_ip, odid, enterprise_capable=True)
        elif set_id == 3:
            pass  # options template: non usato
        elif set_id > 255:
            key = (exporter_ip, odid, set_id)
            fields = _get_template(key)
            if fields:
                out.extend(_decode_data(payload, fields, exporter_ip, export_time))
            else:
                _buffer_pending(key, payload, exporter_ip, export_time)
        offset += set_len
    out.extend(_drain_pending_decoded())
    return out


def _drain_pending_decoded():
    global _decoded_pending
    out, _decoded_pending = _decoded_pending, []
    return out
