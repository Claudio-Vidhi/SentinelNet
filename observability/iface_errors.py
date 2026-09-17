# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Interface error counters: one vocabulary, one way to turn samples into a
verdict, whatever brought the numbers in.

Two sources feed it:

- the SNMP poller, whose counters reach ``events.metrics_json`` of every
  ``interface.state`` event (the periodic view, over a window);
- an on-demand read (SNMP if the device has a community, otherwise SSH), two
  readings a few seconds apart, stored in ``iface_counter_reads``.

Counters are cumulative since boot or the last clear, so the absolute value
says nothing: a switch up for two years carries errors that stopped long ago.
Everything here is about INCREMENTS.
"""

import json
from typing import Dict, Iterable, List, Optional, Tuple

# Canonical counter -> class. The class is what the reader acts on: the fix
# for CRC errors (cable, optic) is not the fix for late collisions (duplex).
FIELDS: Dict[str, str] = {
    "in_errors": "errors",
    "out_errors": "errors",
    "crc": "physical",
    "alignment": "physical",
    "symbol": "physical",
    "runts": "physical",
    "giants": "physical",
    # Plain collisions are not here: no error total contains them, on half
    # duplex they are normal, and agents were seen returning garbage for them.
    # Late and excessive collisions are the duplex-mismatch signal.
    "late_collisions": "duplex",
    "excessive_collisions": "duplex",
    "carrier_sense": "duplex",
    "mac_rx_errors": "hardware",
    "mac_tx_errors": "hardware",
    "in_discards": "discards",
    "out_discards": "discards",
}

# Most actionable first. Discards last: on a busy uplink they are congestion,
# not a fault, and must not outrank a port that corrupts frames.
CLASS_ORDER = ("physical", "duplex", "hardware", "errors", "discards")

# How long an on-demand read waits between its two readings.
READ_INTERVAL_S = 10


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


# A detail counter is part of a total (RFC 3635: FCS, alignment, symbol,
# frame-too-long and internal MAC receive errors are counted in ifInErrors;
# late and excessive collisions, internal MAC transmit and carrier sense errors
# in ifOutErrors; IOS "input errors" includes runts and giants too). A detail
# larger than its total is not a measure: some agents return garbage for ports
# they do not really implement, e.g. billions of CRC errors on a management
# port whose ifInErrors is 0.
_PART_OF = {
    "crc": "in_errors", "alignment": "in_errors", "symbol": "in_errors",
    "runts": "in_errors", "giants": "in_errors", "mac_rx_errors": "in_errors",
    "late_collisions": "out_errors", "excessive_collisions": "out_errors",
    "mac_tx_errors": "out_errors", "carrier_sense": "out_errors",
}


def counters_of(metrics: dict) -> Dict[str, int]:
    """Only the known error counters, as ints. Absent stays absent: a port
    that does not expose a counter must not look clean on it. A detail that
    exceeds its total is dropped (see _PART_OF)."""
    out = {f: int(metrics[f]) for f in FIELDS if _is_num(metrics.get(f))}
    for field, total in _PART_OF.items():
        if field in out and total in out and out[field] > out[total]:
            del out[field]
    return out


def increments(samples: List[Tuple[int, Dict[str, int]]]) -> Tuple[Dict[str, int], bool]:
    """Sum of increments per counter over consecutive samples (oldest first).

    A counter that goes DOWN between two samples was reset (reboot, clear
    counters, wrap): that step counts nothing and the reset is flagged; the
    increments after it count normally. Taking the new value as the increment
    looked right for a clean reboot, but a counter that jumps between garbage
    values then added billions of errors that never happened. Undercounting
    one poll interval is the lesser error. Comparing only first and last would
    instead turn a reboot mid-window into a negative number.
    """
    delta: Dict[str, int] = {}
    reset = False
    for (_, prev), (_, cur) in zip(samples, samples[1:]):
        for field, value in cur.items():
            if field not in prev:
                continue
            if value >= prev[field]:
                inc = value - prev[field]
            else:
                inc, reset = 0, True
            delta[field] = delta.get(field, 0) + inc
    return delta, reset


def verdict(delta: Optional[Dict[str, int]]) -> Tuple[str, Optional[str], int]:
    """(status, worst class, errors excluding discards).

    ``erroring``: something other than discards grew. ``discards``: only
    discards grew. ``clean``: counters were readable and nothing grew.
    """
    if delta is None:
        return "single_sample", None, 0
    if not delta:
        return "no_counters", None, 0
    by_class: Dict[str, int] = {}
    for field, value in delta.items():
        if value:
            by_class[FIELDS[field]] = by_class.get(FIELDS[field], 0) + value
    worst = next((c for c in CLASS_ORDER if by_class.get(c)), None)
    errors = sum(v for c, v in by_class.items() if c != "discards")
    if errors:
        return "erroring", worst, errors
    if by_class.get("discards"):
        return "discards", worst, 0
    return "clean", None, 0


def _discards(delta: Optional[Dict[str, int]]) -> int:
    return sum(v for f, v in (delta or {}).items() if FIELDS[f] == "discards")


def summarize(samples: List[Tuple[int, dict]]) -> dict:
    """Verdict for one port from its samples (oldest first, raw metrics)."""
    parsed = [(ts, counters_of(m or {})) for ts, m in samples]
    parsed = [(ts, c) for ts, c in parsed if c]
    if not parsed:
        return {"status": "no_counters", "counters": {}, "delta": None,
                "errors": 0, "discards": 0, "worst_class": None, "samples": 0}
    ts_last, last = parsed[-1]
    out: dict = {"counters": last, "observed_ts": ts_last, "samples": len(parsed)}
    if len(parsed) < 2:
        out.update(status="single_sample", delta=None, errors=0, discards=0,
                   worst_class=None)
        return out
    delta, reset = increments(parsed)
    status, worst, errors = verdict(delta)
    out.update(status=status, delta=delta, errors=errors, worst_class=worst,
               discards=_discards(delta), reset=reset,
               span_s=ts_last - parsed[0][0])
    return out


def group_samples(rows: Iterable) -> Dict[Tuple[str, str, str], List[Tuple[int, dict]]]:
    """events rows (tenant, device_ip, interface, ts, metrics_json), in id
    order -> {(tenant, device_ip, interface): [(ts, metrics)]}."""
    out: Dict[Tuple[str, str, str], List[Tuple[int, dict]]] = {}
    for r in rows:
        try:
            metrics = json.loads(r["metrics_json"] or "{}")
        except ValueError:
            continue
        out.setdefault((r["tenant"], r["device_ip"], r["interface"]), []).append(
            (r["ts"], metrics))
    return out


def read_result(before: Dict[str, dict], after: Dict[str, dict]) -> Dict[str, dict]:
    """Two on-demand readings {iface: {counter: int}} -> per-port result."""
    out = {}
    for iface, raw in after.items():
        cur = counters_of(raw)
        if not cur:
            continue
        prev = counters_of(before.get(iface) or {})
        delta = increments([(0, prev), (1, cur)])[0] if prev else None
        status, worst, errors = verdict(delta)
        out[iface] = {"counters": cur, "delta": delta, "status": status,
                      "worst_class": worst, "errors": errors,
                      "discards": _discards(delta)}
    return out


def iface_key(name: str) -> str:
    """Comparable interface name: SNMP says 'Gi1/0/1', CLI and the MAC table
    'GigabitEthernet1/0/1'. Goes through the normalizer the codebase already
    uses to match config and CDP, instead of adding a third."""
    from core.core_engine import _normalize_iface
    return _normalize_iface(name or "")


def status_rank(item: dict) -> tuple:
    """Sort key: erroring ports first, worst class first, most errors first."""
    order = {"erroring": 0, "discards": 1, "clean": 2, "single_sample": 3, "no_counters": 4}
    cls = item.get("worst_class")
    return (order.get(item.get("status") or "", 5),
            CLASS_ORDER.index(cls) if cls in CLASS_ORDER else len(CLASS_ORDER),
            -(item.get("errors") or 0), -(item.get("discards") or 0))
