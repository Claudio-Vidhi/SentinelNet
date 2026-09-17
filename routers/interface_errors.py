# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Interface error counters: periodic (SNMP) over a window, and on demand.

Scope rule as everywhere: every query filters by the caller's tenants, and a
device outside them answers the same as one that does not exist.
"""

import asyncio
import json
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core import db
from observability import iface_errors as ie
from routers.deps import (assert_device_allowed, get_current_user,
                          require_operator, require_tab)
from routers.observability import _parse_window, _tenant_filter
from security.security_manager import log_audit

router = APIRouter(tags=["Interface errors"],
                   dependencies=[Depends(require_tab("tab-interfaces", "tab-endpoint"))])

# ponytail: rows scanned per request; past it the answer says "truncated".
# A 24h window over a large fleet gets there: narrow by device or window.
MAX_SAMPLE_ROWS = 300_000
MAX_PORTS = 500


def _hostnames() -> dict:
    from services import inventory_manager
    return {d.get("IP"): (d.get("Hostname") or "")
            for d in inventory_manager.get_all_devices()}


def _device(current_user, ip: str, tenant: Optional[str]) -> dict:
    device = assert_device_allowed(current_user, ip, tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo non trovato.")
    return device


async def _build(current_user, span_s: int, device: Optional[dict]) -> dict:
    """Per-port rows: the window verdict from the SNMP samples, merged with
    the latest on-demand read of the same port."""
    clause, params = _tenant_filter(current_user)
    extra, extra_params = "", ()
    if device:
        extra = " AND device_ip = ? AND tenant = ?"
        extra_params = (device["IP"], device.get("Group") or "Generale")
    now = int(time.time())
    rows = await db.read(
        f"""SELECT tenant, device_ip, interface, ts, metrics_json FROM events
            WHERE event_type = 'interface.state' AND ts >= ?{clause}{extra}
            ORDER BY id LIMIT ?""",
        (now - span_s, *params, *extra_params, MAX_SAMPLE_ROWS))
    reads = await db.read(
        f"""SELECT tenant, device_ip, ts, source, interval_s, result_json
            FROM iface_counter_reads
            WHERE id IN (SELECT MAX(id) FROM iface_counter_reads
                         GROUP BY tenant, device_ip){clause}{extra}""",
        (*params, *extra_params))

    ports: dict = {}
    for (tenant, ip, iface), samples in ie.group_samples(rows).items():
        window = ie.summarize(samples)
        if window["status"] == "no_counters":
            continue
        ports[(tenant, ip, ie.iface_key(iface))] = {
            "tenant": tenant, "device_ip": ip, "interface": iface,
            "window": window, "last_read": None}
    for r in reads:
        try:
            result = json.loads(r["result_json"] or "{}")
        except ValueError:
            continue
        for iface, item in result.items():
            # The verdict saved with the read used the rules of that day: it is
            # derived again, so a counter rejected since (agent garbage) does
            # not keep a port "erroring" until retention drops the row.
            valid = ie.counters_of(item.get("counters") or {})
            delta = item.get("delta")
            if delta is not None:
                delta = {f: v for f, v in delta.items() if f in valid}
            status, worst, errors = ie.verdict(delta)
            item = {**item, "counters": valid, "delta": delta, "status": status,
                    "worst_class": worst, "errors": errors,
                    "discards": sum(v for f, v in (delta or {}).items()
                                    if ie.FIELDS[f] == "discards")}
            key = (r["tenant"], r["device_ip"], ie.iface_key(iface))
            row = ports.setdefault(key, {"tenant": r["tenant"], "device_ip": r["device_ip"],
                                         "interface": iface, "window": None})
            row["last_read"] = {**item, "ts": r["ts"], "source": r["source"],
                                "interval_s": r["interval_s"]}

    names = await asyncio.to_thread(_hostnames)
    out = []
    for row in ports.values():
        window, last = row["window"], row.get("last_read")
        # The headline verdict is the most recent evidence able to judge: a
        # read newer than the last poll describes the port as it is now.
        judged = window if window and window["status"] != "single_sample" else None
        if last and last["status"] != "single_sample" and (
                not judged or last["ts"] >= judged.get("observed_ts", 0)):
            judged = last
        judged = judged or window or last or {}
        row.update(hostname=names.get(row["device_ip"], ""),
                   status=judged.get("status", "single_sample"),
                   worst_class=judged.get("worst_class"),
                   errors=judged.get("errors", 0),
                   discards=judged.get("discards", 0))
        out.append(row)
    out.sort(key=ie.status_rank)

    counts = {s: 0 for s in ("erroring", "discards", "clean", "single_sample")}
    for row in out:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {"ports": out[:MAX_PORTS], "counts": counts, "total": len(out),
            "window_s": span_s,
            "truncated": len(rows) >= MAX_SAMPLE_ROWS or len(out) > MAX_PORTS}


@router.get("/api/interface-errors")
async def list_interface_errors(window: str = "1h", device: Optional[str] = None,
                                tenant: Optional[str] = None,
                                current_user=Depends(get_current_user)):
    span = _parse_window(window)
    dev = await asyncio.to_thread(_device, current_user, device, tenant) if device else None
    return await _build(current_user, span, dev)


@router.get("/api/interface-errors/port")
async def port_interface_errors(device: str, port: str, window: str = "24h",
                                tenant: Optional[str] = None,
                                current_user=Depends(get_current_user)):
    span = _parse_window(window)
    dev = await asyncio.to_thread(_device, current_user, device, tenant)
    want = ie.iface_key(port)
    data = await _build(current_user, span, dev)
    row = next((p for p in data["ports"] if ie.iface_key(p["interface"]) == want), None)
    return {"known": row is not None, "port": row, "window_s": span}


class InterfaceErrorsReadSchema(BaseModel):
    device: str
    tenant: Optional[str] = None


@router.post("/api/interface-errors/read")
async def read_interface_errors(payload: InterfaceErrorsReadSchema, current_user=Depends(require_operator)):
    """Two readings READ_INTERVAL_S apart: SNMP when the device has a
    community and answers, SSH otherwise."""
    from collectors import iface_counters_cli
    from core.ssh_pool import run_ssh
    from observability.ingesters import snmp_poller
    from security.snmp_defaults import resolve_snmp_community

    device = await asyncio.to_thread(_device, current_user, payload.device, payload.tenant)
    ip, tenant = device["IP"], device.get("Group") or "Generale"
    interval = ie.READ_INTERVAL_S
    source, before, after, elapsed = None, {}, {}, interval

    community = resolve_snmp_community(device)
    if community:
        start = time.monotonic()
        before = await snmp_poller.read_error_counters(ip, community)
        if before:
            await asyncio.sleep(interval)
            after = await snmp_poller.read_error_counters(ip, community)
            source, elapsed = "snmp", round(time.monotonic() - start)
    if not source:
        res = await run_ssh(iface_counters_cli.read_twice, device, interval)
        if res.get("error"):
            detail = res["error"]
            if community:
                detail = f"SNMP non ha risposto; {detail}"
            raise HTTPException(status_code=502, detail=detail)
        source, before, after, elapsed = "cli", res["before"], res["after"], res["elapsed_s"]

    result = ie.read_result(before, after)
    ts = int(time.time())
    db.enqueue_write(
        "INSERT INTO iface_counter_reads(ts, tenant, device_ip, source, interval_s, "
        "requested_by, result_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, tenant, ip, source, elapsed, current_user.get("sub"),
         json.dumps(result, ensure_ascii=False)))
    log_audit(f"Lettura contatori errori interfacce su {ip} ({tenant}) via {source} "
              f"da '{current_user.get('sub')}'.")
    ports = [{"interface": name, **item} for name, item in result.items()]
    ports.sort(key=ie.status_rank)
    return {"device_ip": ip, "tenant": tenant, "source": source,
            "interval_s": elapsed, "ts": ts, "ports": ports}
