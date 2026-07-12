# -*- coding: utf-8 -*-
"""Decoder sFlow v5 → record di flusso normalizzati (fase 3.4).

SEMANTICA DI STIMA (vincolante): sFlow campiona 1 pacchetto ogni
``sampling_rate``; i valori emessi sono quindi STIME dell'intero traffico:
    bytes   = frame_length * sampling_rate
    packets = sampling_rate
per ogni flow sample. I counter sample non sono usati (Decisione #5):
header letto, corpo saltato, metrica ``counter_samples_skipped``.

Input malformato non solleva mai: si decodifica il decodificabile e si
incrementa ``parse_errors``.
"""

import ipaddress
import struct
import time

from observability import metrics

_FMT_FLOW_SAMPLE = 1
_FMT_COUNTER_SAMPLE = 2
_FMT_FLOW_SAMPLE_EXP = 3
_FMT_COUNTER_SAMPLE_EXP = 4
_REC_RAW_HEADER = 1


def parse(data: bytes, exporter_ip: str):
    """Decodifica un datagramma sFlow v5. Ritorna record normalizzati
    (stesso formato di ipfix.parse)."""
    try:
        return _parse(data, exporter_ip)
    except Exception:
        metrics.inc("parse_errors", proto="sflow")
        return []


def _parse(data: bytes, exporter_ip: str):
    if len(data) < 28 or struct.unpack_from("!I", data, 0)[0] != 5:
        metrics.inc("parse_errors", proto="sflow")
        return []
    addr_type = struct.unpack_from("!I", data, 4)[0]
    offset = 8 + (4 if addr_type == 1 else 16)
    offset += 12  # sub-agent id, sequence, uptime
    num_samples = struct.unpack_from("!I", data, offset)[0]
    offset += 4

    out = []
    now = int(time.time())
    for _ in range(min(num_samples, 64)):
        if offset + 8 > len(data):
            break
        sample_type, sample_len = struct.unpack_from("!II", data, offset)
        offset += 8
        payload = data[offset:offset + sample_len]
        offset += sample_len
        fmt = sample_type & 0xFFF
        if fmt == _FMT_FLOW_SAMPLE:
            out.extend(_flow_sample(payload, exporter_ip, now))
        elif fmt in (_FMT_COUNTER_SAMPLE, _FMT_COUNTER_SAMPLE_EXP):
            metrics.inc("counter_samples_skipped")
        # expanded flow sample (3): layout diverso, non supportato → skip
    return out


def _flow_sample(p: bytes, exporter_ip: str, now: int):
    if len(p) < 32:
        return []
    sampling_rate = struct.unpack_from("!I", p, 8)[0] or 1
    num_records = struct.unpack_from("!I", p, 28)[0]
    out = []
    offset = 32
    for _ in range(min(num_records, 16)):
        if offset + 8 > len(p):
            break
        rec_type, rec_len = struct.unpack_from("!II", p, offset)
        offset += 8
        body = p[offset:offset + rec_len]
        offset += rec_len
        if (rec_type & 0xFFF) == _REC_RAW_HEADER:
            rec = _raw_header(body, sampling_rate, exporter_ip, now)
            if rec:
                out.append(rec)
    return out


def _raw_header(body: bytes, sampling_rate: int, exporter_ip: str, now: int):
    if len(body) < 16:
        return None
    proto_hdr, frame_len, _stripped, hdr_len = struct.unpack_from("!IIII", body, 0)
    if proto_hdr != 1:  # solo Ethernet
        return None
    frame = body[16:16 + hdr_len]
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    off = 14
    if ethertype == 0x8100 and len(frame) >= 18:  # 802.1Q
        ethertype = struct.unpack_from("!H", frame, 16)[0]
        off = 18
    if ethertype != 0x0800 or len(frame) < off + 20:  # solo IPv4
        return None
    ihl = (frame[off] & 0x0F) * 4
    proto = frame[off + 9]
    src = str(ipaddress.IPv4Address(frame[off + 12: off + 16]))
    dst = str(ipaddress.IPv4Address(frame[off + 16: off + 20]))
    dst_port = None
    l4 = off + ihl
    if proto in (6, 17) and len(frame) >= l4 + 4:
        dst_port = struct.unpack_from("!H", frame, l4 + 2)[0]
    return {
        "src_ip": src, "dst_ip": dst, "protocol": proto, "dst_port": dst_port,
        # Stima: 1 campione rappresenta sampling_rate pacchetti reali.
        "bytes": frame_len * sampling_rate, "packets": sampling_rate,
        "flow_end_ts": now, "exporter_ip": exporter_ip,
    }
