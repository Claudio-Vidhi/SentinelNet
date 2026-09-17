# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Interface error counters over SSH, for devices without SNMP.

One command per driver prints the counters of every port at once, and one
parser per output format turns it into ``{interface: {counter: int}}`` with the
vocabulary of ``observability/iface_errors.FIELDS``. A counter the output does
not show stays ABSENT: absent is "unknown", zero is "clean", and mixing the two
would make an unsupported counter look healthy.

The formats come from the vendors' documented output. Releases move labels
around, so every parser reads label/value pairs instead of fixed columns, and
an output it does not recognise yields {} ("not readable"), never zeros.

Supported drivers (drivers/registry.py names):
  cisco_ios, cisco_9800  IOS / IOS-XE / NX-OS     ``show interfaces``
  juniper_junos          Junos                    ``show interfaces extensive``
  hp_procurve            ProCurve/ArubaOS-Switch  ``show interfaces``
  aruba_os               AOS-CX or ArubaOS-Switch ``show interface``
  fortinet               FortiOS                  ``diagnose netlink interface list``
  paloalto_panos         PAN-OS                   ``show counter interface all``
Cisco CBS (cisco_s300) prints error counters only one port at a time: it is
left to SNMP, which it supports.
"""

import logging
import re
import time
from typing import Dict

log = logging.getLogger("sentinelnet.iface_counters_cli")

Counters = Dict[str, Dict[str, int]]


def _num(text: str) -> int:
    return int(text.replace(",", ""))


def _add(port: dict, field: str, value: int) -> None:
    port[field] = port.get(field, 0) + value


# --- Cisco IOS / IOS-XE / NX-OS ---------------------------------------------
#
# IOS:   "     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored"
# NX-OS: "    0 runts  0 giants  0 CRC/FCS  0 no buffer"
# Both are "<number> <label>" pairs, separated by commas (IOS) or runs of
# spaces (NX-OS). Labels not listed here (overrun, ignored, ...) are skipped.

_CISCO_LABELS = {
    "input errors": "in_errors", "input error": "in_errors",
    "output errors": "out_errors", "output error": "out_errors",
    "crc": "crc", "crc/fcs": "crc",
    "frame": "alignment",
    "runts": "runts", "giants": "giants",
    "late collision": "late_collisions",
    "lost carrier": "carrier_sense",
    "input discard": "in_discards", "output discard": "out_discards",
}
_CISCO_HEADER = re.compile(r"^(\S+) is (?:administratively )?(?:up|down|deleted)", re.I)
_PAIR = re.compile(r"(\d[\d,]*)\s+([A-Za-z][A-Za-z/ ]*?)(?=\s*,|\s{2,}|\s*$)")
_CISCO_OUT_DROPS = re.compile(r"Total output drops:\s*(\d+)", re.I)
_CISCO_IN_QUEUE = re.compile(r"Input queue:\s*\d+/\d+/(\d+)/\d+", re.I)


def parse_cisco(output: str) -> Counters:
    out: Counters = {}
    port = None
    for line in output.splitlines():
        m = _CISCO_HEADER.match(line)
        if m:
            port = out.setdefault(m.group(1), {})
            continue
        if port is None:
            continue
        m = _CISCO_OUT_DROPS.search(line)
        if m:
            _add(port, "out_discards", _num(m.group(1)))
        m = _CISCO_IN_QUEUE.search(line)
        if m:
            _add(port, "in_discards", _num(m.group(1)))
        for value, label in _PAIR.findall(line):
            field = _CISCO_LABELS.get(label.strip().lower())
            if field:
                _add(port, field, _num(value))
    return {k: v for k, v in out.items() if v}


# --- Juniper Junos (show interfaces extensive) --------------------------------
#
#   Physical interface: ge-0/0/0, Enabled, Physical link is Up
#     Input errors:
#       Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, Policed discards: 0, ...
#     Output errors:
#       Carrier transitions: 1, Errors: 0, Drops: 0, Collisions: 0, ...
#     MAC statistics:                      Receive         Transmit
#       CRC/Align errors                         0                0
#       Oversized frames                         0

_JUNOS_HEADER = re.compile(r"^\s*Physical interface:\s*([^,\s]+)", re.I)
_JUNOS_PAIR = re.compile(r"([A-Za-z][A-Za-z /]*?):\s*(\d[\d,]*)")
_JUNOS_IN = {"errors": "in_errors", "drops": "in_discards",
             "framing errors": "alignment", "runts": "runts"}
_JUNOS_OUT = {"errors": "out_errors", "drops": "out_discards"}
_JUNOS_MAC = {"crc/align errors": "crc", "oversized frames": "giants"}
_JUNOS_MAC_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z /]*?)\s{2,}(\d[\d,]*)(?:\s+\d[\d,]*)?\s*$")


def parse_junos(output: str) -> Counters:
    out: Counters = {}
    port = None
    section = None
    for line in output.splitlines():
        m = _JUNOS_HEADER.match(line)
        if m:
            port, section = out.setdefault(m.group(1), {}), None
            continue
        if port is None:
            continue
        low = line.strip().lower()
        # A logical unit belongs to the physical port above: its counters
        # would be counted twice.
        if low.startswith("logical interface"):
            port = None
            continue
        if low.startswith("input errors:"):
            section = _JUNOS_IN
        elif low.startswith("output errors:"):
            section = _JUNOS_OUT
        elif low.startswith("mac statistics"):
            section = _JUNOS_MAC
        elif section is _JUNOS_MAC:
            m = _JUNOS_MAC_LINE.match(line)
            if m and m.group(1).strip().lower() in _JUNOS_MAC:
                port[_JUNOS_MAC[m.group(1).strip().lower()]] = _num(m.group(2))
        elif section is not None:
            labels = section
            pairs = _JUNOS_PAIR.findall(line)
            if not pairs:
                section = None
            for label, value in pairs:
                field = labels.get(label.strip().lower())
                if field:
                    port[field] = _num(value)
    return {k: v for k, v in out.items() if v}


# --- HP ProCurve / ArubaOS-Switch ---------------------------------------------
#
# Summary table of `show interfaces` (every port, one line each):
#   Port  | Total Bytes  Total Frames Errors Rx  Errors Tx  Drops Tx  Flow Ctrl
#   ----- + ------------ ------------ ---------- ---------- --------- ---------
#   1     | 1,234,567    12,345       0          0          0         off
# Per-port detail (`show interfaces <port>`), when that is what came back:
#   Status and Counters - Port Counters for port 1
#    FCS Rx          : 0                Drops Tx        : 0
#    Alignment Rx    : 0                Collisions Tx   : 0

_PROCURVE_ROW = re.compile(
    r"^\s*([A-Za-z]?\d[\w/\-]*)\s*\|\s*[\d,]+\s+[\d,]+\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)\b")
_PROCURVE_DETAIL = re.compile(r"Port Counters for port\s+(\S+)", re.I)
_PROCURVE_PAIR = re.compile(r"([A-Za-z][A-Za-z /]*?)\s*:\s*(\d[\d,]*)")
_PROCURVE_LABELS = {
    "fcs rx": "crc", "alignment rx": "alignment", "runts rx": "runts",
    "giants rx": "giants", "total rx errors": "in_errors",
    "drops tx": "out_discards",
    "late colln tx": "late_collisions", "excessive colln": "excessive_collisions",
    "discards rx": "in_discards",
}


def parse_procurve(output: str) -> Counters:
    out: Counters = {}
    port = None
    for line in output.splitlines():
        m = _PROCURVE_ROW.match(line)
        if m:
            out[m.group(1)] = {"in_errors": _num(m.group(2)),
                               "out_errors": _num(m.group(3)),
                               "out_discards": _num(m.group(4))}
            continue
        m = _PROCURVE_DETAIL.search(line)
        if m:
            port = out.setdefault(m.group(1), {})
            continue
        if port is not None:
            for label, value in _PROCURVE_PAIR.findall(line):
                field = _PROCURVE_LABELS.get(label.strip().lower())
                if field:
                    port[field] = _num(value)
    return {k: v for k, v in out.items() if v}


# --- Aruba AOS-CX -------------------------------------------------------------
#
# 10.x table format:
#   Interface 1/1/1 is up
#    Statistics            RX                   TX                   Total
#    Dropped                                 0                    0                    0
#    Errors                                  0                    0                    0
#      CRC/FCS                               0                  n/a                    0
#      Collision                           n/a                    0                    0
# Older releases print "<n> <label>" pairs under RX / TX headings.

_CX_HEADER = re.compile(r"^\s*Interface\s+(\S+)\s+is\s+", re.I)
_CX_ROW = re.compile(r"^\s*([A-Za-z][A-Za-z/ ]*?)\s{2,}(\S+)\s+(\S+)(?:\s+\S+)?\s*$")
_CX_ROWS = {"dropped": ("in_discards", "out_discards"),
            "errors": ("in_errors", "out_errors"),
            "crc/fcs": ("crc", None),
            "runts": ("runts", None), "giants": ("giants", None)}
# Older pair format: (field when under RX, field when under TX)
_CX_PAIRS = {"input error": ("in_errors", "out_errors"),
             "input errors": ("in_errors", "out_errors"),
             "output error": ("in_errors", "out_errors"),
             "output errors": ("in_errors", "out_errors"),
             "dropped": ("in_discards", "out_discards"),
             "crc/fcs": ("crc", "crc"),
             "runts": ("runts", "runts"), "giants": ("giants", "giants")}


def parse_aoscx(output: str) -> Counters:
    out: Counters = {}
    port = None
    direction = None
    for line in output.splitlines():
        m = _CX_HEADER.match(line)
        if m:
            port, direction = out.setdefault(m.group(1), {}), None
            continue
        if port is None:
            continue
        head = line.strip().upper()
        if head in ("RX", "TX"):
            direction = head
            continue
        m = _CX_ROW.match(line)
        if m and m.group(1).strip().lower() in _CX_ROWS:
            rx_field, tx_field = _CX_ROWS[m.group(1).strip().lower()]
            for field, raw in ((rx_field, m.group(2)), (tx_field, m.group(3))):
                if field and re.fullmatch(r"[\d,]+", raw):
                    port[field] = _num(raw)
            continue
        if direction:
            for value, label in _PAIR.findall(line):
                fields = _CX_PAIRS.get(label.strip().lower())
                if fields:
                    port[fields[0] if direction == "RX" else fields[1]] = _num(value)
    return {k: v for k, v in out.items() if v}


def parse_aruba(output: str) -> Counters:
    """aruba_os covers both families: whichever format came back."""
    return parse_aoscx(output) or parse_procurve(output)


# --- FortiOS (diagnose netlink interface list) -------------------------------
#
#   if=port1 family=00 type=1 index=3 mtu=1500 link=0 master=0
#   stat: rxp=101 txp=202 rxb=303 txb=404 rxe=0 txe=0 rxd=0 txd=0 mc=0 collision=0 @ time=...
#   re: rxl=0 rxo=0 rxc=0 rxf=0 rxfi=0 rxm=0
#   te: txa=0 txc=0 txfi=0 txh=0 txw=0
# rxc = CRC, rxf = frame alignment, txc = carrier.

_FORTI_HEADER = re.compile(r"^\s*if=(\S+)")
_FORTI_KV = re.compile(r"\b([a-z]+)=(\d+)\b")
_FORTI_KEYS = {"rxe": "in_errors", "txe": "out_errors", "rxd": "in_discards",
               "txd": "out_discards",
               "rxc": "crc", "rxf": "alignment", "txc": "carrier_sense"}


def parse_fortios(output: str) -> Counters:
    out: Counters = {}
    port = None
    for line in output.splitlines():
        m = _FORTI_HEADER.match(line)
        if m:
            port = out.setdefault(m.group(1), {})
            continue
        if port is None or not re.match(r"^\s*(stat|re|te):", line):
            continue
        for key, value in _FORTI_KV.findall(line):
            if key in _FORTI_KEYS:
                port[_FORTI_KEYS[key]] = int(value)
    return {k: v for k, v in out.items() if v}


# --- PAN-OS (show counter interface all) --------------------------------------
#
#   Interface: ethernet1/1
#   Hardware interface counters read from MAC:
#   receive errors                0
#   transmit errors               0
#   receive discarded             0
#   Software interface counters:
#   receive errors                0      <- dataplane, not the wire: skipped

_PAN_HEADER = re.compile(r"^\s*Interface:\s*(\S+)", re.I)
_PAN_LINE = re.compile(r"^\s*([a-z][a-z \-]*?)\s{2,}(\d[\d,]*)\s*$", re.I)
_PAN_LABELS = {"receive errors": "in_errors", "transmit errors": "out_errors",
               "receive discarded": "in_discards", "receive drops": "in_discards",
               "transmit discarded": "out_discards", "transmit drops": "out_discards",
               "rx-fcs-errors": "crc", "fcs errors": "crc",
               "late collisions": "late_collisions"}


def parse_panos(output: str) -> Counters:
    out: Counters = {}
    port = None
    hardware = False
    for line in output.splitlines():
        m = _PAN_HEADER.match(line)
        if m:
            port, hardware = out.setdefault(m.group(1), {}), False
            continue
        low = line.strip().lower()
        if low.startswith("hardware interface counters"):
            hardware = True
            continue
        if low.startswith("software interface counters"):
            hardware = False
            continue
        if port is None or not hardware:
            continue
        m = _PAN_LINE.match(line)
        if m and m.group(1).strip().lower() in _PAN_LABELS:
            port[_PAN_LABELS[m.group(1).strip().lower()]] = _num(m.group(2))
    return {k: v for k, v in out.items() if v}


# driver -> (command, parser)
COMMANDS = {
    "cisco_ios": ("show interfaces", parse_cisco),
    "cisco_9800": ("show interfaces", parse_cisco),
    "juniper_junos": ("show interfaces extensive | no-more", parse_junos),
    "hp_procurve": ("show interfaces", parse_procurve),
    "aruba_os": ("show interface", parse_aruba),
    "fortinet": ("diagnose netlink interface list", parse_fortios),
    "paloalto_panos": ("show counter interface all", parse_panos),
}


def read_twice(device: dict, interval_s: int) -> dict:
    """Two readings `interval_s` apart over ONE SSH session.

    Returns {"before", "after", "elapsed_s"} or {"error": text}. One session
    keeps the two readings comparable and halves the logins.
    """
    from core import core_engine
    from core.net_ssh import ConnectHandler
    from drivers.registry import driver_name_for

    vendor = device.get("Vendor") or ""
    driver = driver_name_for(vendor)
    if driver not in COMMANDS:
        return {"error": f"Lettura CLI dei contatori non supportata per il vendor '{vendor or '?'}'."}
    command, parser = COMMANDS[driver]
    try:
        _, netmiko_type = core_engine.resolve_driver(vendor)
    except ValueError as e:
        return {"error": str(e)}
    username, password, secret = core_engine.get_device_credentials(device)
    params = {"device_type": netmiko_type, "host": device["IP"], "username": username,
              "password": password, "secret": secret or "", "timeout": 20,
              "auth_timeout": 10, "banner_timeout": 10}
    try:
        with ConnectHandler(**params) as conn:
            try:
                conn.enable()
            except Exception:
                pass
            start = time.monotonic()
            before = parser(str(conn.send_command(command, read_timeout=90) or ""))
            if not before:
                return {"error": "Output del comando non riconosciuto: nessun contatore letto."}
            time.sleep(interval_s)
            after = parser(str(conn.send_command(command, read_timeout=90) or ""))
            return {"before": before, "after": after,
                    "elapsed_s": round(time.monotonic() - start)}
    except Exception as e:
        log.info("CLI interface counters failed on %s: %s", device.get("IP"), e)
        return {"error": f"Connessione SSH fallita: {e}"}
