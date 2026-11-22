# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Traffico per policy firewall, letto dai contatori che gli apparati tengono.

Unlike the syslog Search view, these numbers have no time window. I byte e le sessioni per policy
vivono SUL firewall, in contatori che il FortiGate azzera solo al reboot o a
richiesta.

Da qui la differenza che la vista deve dichiarare invece di lasciar credere il
contrario: **la finestra del tab non filtra questi numeri**. 850 MB su una
policy sono 850 MB dall'ultimo azzeramento, non nell'ultima ora. Presentarli
sotto un selettore "Ultime 6 ore" senza dirlo e' il modo piu' rapido di far
leggere a un operatore una cifra sbagliata di un ordine di grandezza.

La raccolta e' quella che la tab FortiGate fa gia' per un apparato alla volta
(get_policies_with_stats): qui gira su tutti quelli in scope.
"""
import ipaddress
import logging
import re
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set, Tuple

from core import db
from services import fortigate_service

logger = logging.getLogger("sentinelnet.firewall_traffic")

_HYGIENE_VENDORS = {
    "fortinet", "fortigate",
    "paloalto", "panos",
    "juniper", "junos",
    "cisco", "cisco_ios", "cisco_nxos", "nxos",
    "cisco_ie", "siemens_scalance", "moxa", "hirschmann", "westermo", "phoenix_contact",
}

_BUILTIN_ADDR_NAMES = {
    "all", "any", "none", "all-internet", "localhost",
    "junos-global", "any-ipv4", "any-ipv6",
}
_BUILTIN_SVC_NAMES = {
    "all", "any", "all_icmp", "all_tcp", "all_udp",
    "application-default", "none",
}


def policy_devices(devices) -> list:
    """Gli apparati che tengono contatori per policy: i FortiGate.

    Uno switch non ha policy, e un router con ACL non espone byte per regola:
    allargare questa lista senza un servizio che li legga darebbe righe vuote
    presentate come "nessun traffico"."""
    return [d for d in devices
            if (d.get("Vendor") or "").lower() == "fortinet" and d.get("IP")]


def hygiene_devices(devices) -> list:
    """Devices eligible for offline/snapshot firewall hygiene analysis."""
    return [
        d for d in devices
        if (d.get("Vendor") or "").lower() in _HYGIENE_VENDORS and d.get("IP")
    ]


def _joined(value) -> str:
    """srcaddr/dstaddr/service sono liste di oggetti {name: ...}: la vista
    vuole i nomi, non il JSON."""
    if isinstance(value, list):
        return ", ".join(
            str((v.get("name") if isinstance(v, dict) else v) or "")
            for v in value).strip(", ")
    return str(value or "")


def _row(device, entry: dict) -> dict:
    """Una policy con i suoi contatori, nella forma che la vista disegna."""
    return {
        "device": device.get("Hostname") or device.get("IP"),
        "device_ip": device.get("IP"),
        "group": device.get("Group") or "",
        "policyid": entry.get("policyid"),
        "name": entry.get("name") or "",
        "srcaddr": _joined(entry.get("srcaddr")),
        "dstaddr": _joined(entry.get("dstaddr")),
        "srcaddr_ips": _joined(entry.get("srcaddr_ips")),
        "dstaddr_ips": _joined(entry.get("dstaddr_ips")),
        "service": _joined(entry.get("service")),
        "action": (entry.get("action") or "").lower(),
        "status": (entry.get("status") or "").lower(),
        "bytes": entry.get("bytes") or 0,
        "hit_count": entry.get("hit_count") or 0,
        "active_sessions": entry.get("active_sessions") or 0,
        "last_used": entry.get("last_used"),
        # never_hit distingue "contatore a zero" da "nessun contatore": senza,
        # una policy di cui non sappiamo nulla sembrerebbe una regola morta.
        "never_hit": bool(entry.get("never_hit")),
    }


def collect_for(device) -> dict:
    """Policy di UN apparato: ``{"rows": [...]}`` oppure ``{"error": ...}``.

    Non solleva: un firewall irraggiungibile e' una riga di errore accanto agli
    altri, non una tabella vuota per tutti."""
    ip = device.get("IP")
    try:
        answer = fortigate_service.get_policies_with_stats(device)
    except fortigate_service.FortiGateError as e:
        return {"device_ip": ip, "error": str(e)}
    data = answer.get("data")
    if not isinstance(data, list):
        return {"device_ip": ip, "error": "risposta non interpretabile"}
    out = {"device_ip": ip, "source": answer.get("source"),
           "rows": [_row(device, e) for e in data if isinstance(e, dict)]}
    if answer.get("stats_error"):
        # Configurazione arrivata, contatori no: meta' risposta e' meglio di un
        # errore, ma la meta' mancante va nominata o le colonne a zero si
        # leggono come "questa policy non passa traffico".
        out["stats_error"] = answer["stats_error"]
    return out


# ---------------------------------------------------------------------------
# Policy Hit Snapshots & 7d / 30d Deltas
# ---------------------------------------------------------------------------

# A 30d delta needs a baseline up to ~45 days old; the retention job keeps
# exactly this window (observability/rollup.py).
SNAPSHOT_HISTORY_DAYS = 45


def record_policy_snapshots(
    device: Dict[str, Any],
    rows: List[Dict[str, Any]],
    ts: Optional[int] = None,
) -> int:
    """Persist policy counter rows into ``policy_hit_snapshots`` (blocking SQLite)."""
    ip = str(device.get("IP") or "").strip()
    if not ip or not rows:
        return 0
    snap_ts = int(ts if ts is not None else time.time())
    tenant = str(device.get("Group") or "")
    payload = []
    for r in rows:
        pid = r.get("policyid")
        if pid is None:
            pid = r.get("rule_id")
        if pid is None or str(pid).strip() == "":
            continue
        payload.append((
            snap_ts,
            tenant,
            ip,
            str(pid),
            str(r.get("name") or ""),
            int(r.get("hit_count") or 0),
            int(r.get("bytes") or 0),
            int(r["last_used"]) if r.get("last_used") is not None else None,
        ))
    if not payload:
        return 0

    conn = db.get_observability_connection()
    try:
        conn.executemany(
            "INSERT INTO policy_hit_snapshots "
            "(ts, tenant, device_ip, policy_id, policy_name, hit_count, bytes, last_used) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            payload,
        )
        conn.commit()
    finally:
        conn.close()
    return len(payload)


def get_policy_snapshot_history(
    device_ip: str,
    tenant: str,
    since_ts: int = 0,
) -> List[Dict[str, Any]]:
    """Return stored snapshots for ``device_ip`` in ``tenant``, oldest first.

    The tenant is part of the key: two customers can run their firewall on
    the same private IP, and mixing their counters fakes the deltas."""
    if not device_ip:
        return []
    conn = db.get_observability_connection()
    try:
        cur = conn.execute(
            "SELECT id, ts, tenant, device_ip, policy_id, policy_name, hit_count, bytes, last_used "
            "FROM policy_hit_snapshots WHERE device_ip = ? AND tenant = ? AND ts >= ? "
            "ORDER BY ts ASC, id ASC",
            (device_ip, tenant or "", int(since_ts)),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def _pick_baseline(
    snaps: List[Dict[str, Any]],
    now: int,
    window_days: int,
) -> Optional[Dict[str, Any]]:
    """Pick baseline snapshot for ``window_days``.

    Prefers the most recent snapshot at or before ``now - window_days*86400``.
    If none exists that old, falls back to the earliest snapshot strictly older
    than ``now - 30`` seconds so shorter histories still show delta growth.
    """
    prior = [s for s in snaps if int(s["ts"]) < now - 30]
    if not prior:
        return None
    cutoff = now - window_days * 86400
    at_or_before = [s for s in prior if int(s["ts"]) <= cutoff]
    if at_or_before:
        return max(at_or_before, key=lambda s: (int(s["ts"]), int(s["id"])))
    if window_days <= 7:
        return min(prior, key=lambda s: (int(s["ts"]), int(s["id"])))
    # For 30d window, accept earliest baseline if at least 21d old; otherwise
    # keep 30d delta honest (only partial <7d history does not equal 30d idle).
    oldest = min(prior, key=lambda s: (int(s["ts"]), int(s["id"])))
    if (now - int(oldest["ts"])) >= 21 * 86400:
        return oldest
    return None


def _delta_pair(
    cur_hits: int,
    cur_bytes: int,
    base: Optional[Dict[str, Any]],
) -> Tuple[Optional[int], Optional[int], bool]:
    if base is None:
        return None, None, False
    b_hits = int(base.get("hit_count") or 0)
    b_bytes = int(base.get("bytes") or 0)
    if cur_hits < b_hits or cur_bytes < b_bytes:
        # Device rebooted or counters cleared: reset detected
        return cur_hits, cur_bytes, True
    return cur_hits - b_hits, cur_bytes - b_bytes, False


def compute_policy_deltas(
    device_ip: str,
    tenant: str,
    rows: List[Dict[str, Any]],
    now_ts: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Attach 7d and 30d delta counters to each row using stored snapshots."""
    now = int(now_ts if now_ts is not None else time.time())
    history = get_policy_snapshot_history(device_ip, tenant, since_ts=now - SNAPSHOT_HISTORY_DAYS * 86400)
    by_pid: Dict[str, List[Dict[str, Any]]] = {}
    for s in history:
        by_pid.setdefault(str(s["policy_id"]), []).append(s)

    enriched: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        pid = str(item.get("policyid") if item.get("policyid") is not None else item.get("rule_id") or "")
        snaps = by_pid.get(pid, [])
        cur_hits = int(item.get("hit_count") or 0)
        cur_bytes = int(item.get("bytes") or 0)

        b7 = _pick_baseline(snaps, now, 7)
        b30 = _pick_baseline(snaps, now, 30)
        dh7, db7, rst7 = _delta_pair(cur_hits, cur_bytes, b7)
        dh30, db30, rst30 = _delta_pair(cur_hits, cur_bytes, b30)

        item["delta_hits_7d"] = dh7
        item["delta_bytes_7d"] = db7
        item["delta_hits_30d"] = dh30
        item["delta_bytes_30d"] = db30
        item["counter_reset_7d"] = rst7
        item["counter_reset_30d"] = rst30
        enriched.append(item)
    return enriched


# ---------------------------------------------------------------------------
# Unused Objects Extraction (Multi-Vendor)
# ---------------------------------------------------------------------------

def _fortios_unused_objects(config_text: str) -> List[Dict[str, Any]]:
    from fw_analyzers.fortios import _forti_tree, _forti_get, _forti_tokens

    tree = _forti_tree(config_text or "")
    declared: List[Tuple[str, str, Dict[str, Any]]] = []

    section_kinds = [
        ("firewall address", "address"),
        ("firewall addrgrp", "addrgrp"),
        ("firewall service custom", "service"),
        ("firewall service group", "service-group"),
        ("firewall vip", "vip"),
        ("firewall ippool", "ippool"),
    ]
    for path, kind in section_kinds:
        sec_node = _forti_get(tree, path) or {}
        edits = sec_node.get("children") if isinstance(sec_node, dict) and "children" in sec_node else sec_node
        if not isinstance(edits, dict):
            continue
        for name, node in edits.items():
            low = str(name).strip().lower()
            if not low or low in _BUILTIN_ADDR_NAMES or low in _BUILTIN_SVC_NAMES:
                continue
            body = node.get("sets", {}) if isinstance(node, dict) and "sets" in node else (node if isinstance(node, dict) else {})
            declared.append((str(name), kind, body))

    if not declared:
        return []

    referenced: Set[str] = set()

    def _collect_refs(section: Any, keys: Tuple[str, ...]) -> None:
        if not isinstance(section, dict):
            return
        items = section.get("children") if "children" in section else section
        if not isinstance(items, dict):
            return
        for _eid, node in items.items():
            if not isinstance(node, dict):
                continue
            body = node.get("sets", {}) if "sets" in node else node
            for key in keys:
                raw = body.get(key)
                if raw is None:
                    continue
                vals = raw if isinstance(raw, list) else [raw]
                for item in vals:
                    for tok in _forti_tokens(str(item)):
                        referenced.add(tok)

    _collect_refs(_forti_get(tree, "firewall policy"),
                  ("srcaddr", "dstaddr", "service", "poolname", "srcaddr6", "dstaddr6"))
    _collect_refs(_forti_get(tree, "firewall addrgrp"), ("member",))
    _collect_refs(_forti_get(tree, "firewall service group"), ("member",))
    _collect_refs(_forti_get(tree, "firewall central-snat-map"),
                  ("orig-addr", "dst-addr", "nat-ippool"))
    _collect_refs(_forti_get(tree, "router policy"), ("srcaddr", "dstaddr"))

    cfg_cmd_map = {
        "address": "config firewall address",
        "addrgrp": "config firewall addrgrp",
        "service": "config firewall service custom",
        "service-group": "config firewall service group",
        "vip": "config firewall vip",
        "ippool": "config firewall ippool",
    }
    api_path_map = {
        "address": "firewall/address",
        "addrgrp": "firewall/addrgrp",
        "service": "firewall.service/custom",
        "service-group": "firewall.service/group",
        "vip": "firewall/vip",
        "ippool": "firewall/ippool",
    }

    def _vals(raw: Any) -> List[str]:
        if raw is None:
            return []
        return [str(x) for x in raw] if isinstance(raw, list) else _forti_tokens(str(raw))

    unused: List[Dict[str, Any]] = []
    for name, kind, body in declared:
        if name in referenced:
            continue
        detail = ""
        if "subnet" in body:
            detail = " ".join(_vals(body["subnet"]))
        elif "member" in body:
            detail = ", ".join(_vals(body["member"]))
        elif "tcp-portrange" in body:
            detail = f"tcp/{' '.join(_vals(body['tcp-portrange']))}"
        elif "extip" in body and "mappedip" in body:
            detail = f"{' '.join(_vals(body['extip']))} -> {' '.join(_vals(body['mappedip']))}"
        sec_cmd = cfg_cmd_map[kind]
        api_path = api_path_map[kind]
        rollback_lines = [sec_cmd, f'    edit "{name}"']
        for rk, rv in body.items():
            toks = _vals(rv)
            if toks:
                rendered = " ".join(f'"{t}"' if " " in t else t for t in toks)
                rollback_lines.append(f"        set {rk} {rendered}")
        rollback_lines.extend(["    next", "end"])
        unused.append({
            "name": name,
            "kind": kind,
            "vendor": "fortios",
            "detail": detail,
            "cli_dry_run": f'{sec_cmd}\n    delete "{name}"\nend',
            "cli_rollback": "\n".join(rollback_lines),
            "api_dry_run": f"DELETE /api/v2/cmdb/{api_path}/{name}",
        })
    return unused


def _panos_unused_objects(config_text: str) -> List[Dict[str, Any]]:
    declared: List[Tuple[str, str, str]] = []
    ref_text_lines: List[str] = []
    text = (config_text or "").strip()

    if text.startswith("<"):
        try:
            root = ET.fromstring(text)
            for tag, kind in (("address", "address"), ("address-group", "addrgrp"),
                              ("service", "service"), ("service-group", "service-group")):
                for parent in root.findall(f".//{tag}"):
                    for entry in parent.findall("./entry"):
                        name = entry.attrib.get("name", "").strip()
                        if name and name.lower() not in _BUILTIN_ADDR_NAMES | _BUILTIN_SVC_NAMES:
                            detail = ""
                            ipn = entry.findtext("ip-netmask") or entry.findtext("fqdn")
                            if ipn:
                                detail = ipn.strip()
                            declared.append((name, kind, detail))
            for container in root.findall(".//rulebase") + root.findall(".//address-group") + root.findall(".//service-group"):
                for elem in container.findall(".//member"):
                    if elem.text:
                        ref_text_lines.append(elem.text.strip())
        except ET.ParseError:
            pass
    else:
        for line in text.splitlines():
            s = line.strip()
            if not s.startswith("set "):
                continue
            m = re.match(r'^set\s+(?:shared\s+|vsys\s+\S+\s+)?(address|address-group|service|service-group)\s+"?([^"\s]+)"?\s*(.*)$', s)
            if m and any(k in s for k in (" ip-netmask ", " ip-range ", " fqdn ", " protocol ")):
                declared.append((m.group(2), "addrgrp" if m.group(1) == "address-group" else m.group(1), m.group(3)))
                continue
            if " rulebase " in s or " static " in s or " members " in s:
                ref_text_lines.append(s)

    seen_names: Set[str] = set()
    ref_blob = "\n".join(ref_text_lines)
    unused: List[Dict[str, Any]] = []
    for name, kind, detail in declared:
        if name in seen_names:
            continue
        seen_names.add(name)
        if re.search(rf'(?<![A-Za-z0-9_.-]){re.escape(name)}(?![A-Za-z0-9_.-])', ref_blob):
            continue
        pan_kind = "address-group" if kind == "addrgrp" else kind
        unused.append({
            "name": name,
            "kind": kind,
            "vendor": "panos",
            "detail": detail,
            "cli_dry_run": f"delete {pan_kind} {name}",
            "cli_rollback": f"set {pan_kind} {name} {detail}".strip(),
            "api_dry_run": (
                f"GET /api/?type=config&action=delete"
                f"&xpath=/config/devices/entry/vsys/entry[@name='vsys1']/{pan_kind}/entry[@name='{name}']"
            ),
        })
    return unused


def _junos_unused_objects(config_text: str) -> List[Dict[str, Any]]:
    declared: List[Tuple[str, str, str, str]] = []
    ref_lines: List[str] = []
    for line in (config_text or "").splitlines():
        s = line.strip()
        if not s.startswith("set "):
            continue
        m_addr = re.match(
            r'^set\s+security\s+(?:zones\s+security-zone\s+(\S+)\s+)?address-book\s+(?:\S+\s+)?address\s+(\S+)\s+(.+)$',
            s,
        )
        if m_addr:
            zone = m_addr.group(1) or "global"
            declared.append((m_addr.group(2), "address", m_addr.group(3), zone))
            continue
        m_app = re.match(r'^set\s+applications\s+application\s+(\S+)\s+(.+)$', s)
        if m_app:
            declared.append((m_app.group(1), "application", m_app.group(2), "applications"))
            continue
        if " policies " in s or " address-set " in s or " application-set " in s or " nat " in s:
            ref_lines.append(s)

    seen: Set[str] = set()
    ref_blob = "\n".join(ref_lines)
    unused: List[Dict[str, Any]] = []
    for name, kind, detail, scope in declared:
        if name in seen or name.lower() in _BUILTIN_ADDR_NAMES | _BUILTIN_SVC_NAMES:
            continue
        seen.add(name)
        if re.search(rf'(?<![A-Za-z0-9_.-]){re.escape(name)}(?![A-Za-z0-9_.-])', ref_blob):
            continue
        if kind == "application":
            del_cmd = f"delete applications application {name}"
            rb_cmd = f"set applications application {name} {detail}"
        elif scope == "global":
            del_cmd = f"delete security address-book global address {name}"
            rb_cmd = f"set security address-book global address {name} {detail}"
        else:
            del_cmd = f"delete security zones security-zone {scope} address-book address {name}"
            rb_cmd = f"set security zones security-zone {scope} address-book address {name} {detail}"
        unused.append({
            "name": name,
            "kind": kind,
            "vendor": "junos",
            "detail": detail,
            "cli_dry_run": del_cmd,
            "cli_rollback": rb_cmd,
            "api_dry_run": f"NETCONF <edit-config>: delete {name} (candidate commit-check)",
        })
    return unused


def _ios_unused_objects(config_text: str, vendor: str = "ios") -> List[Dict[str, Any]]:
    declared: List[Tuple[str, str, str]] = []
    ref_lines: List[str] = []
    cur_acl: Optional[str] = None
    for line in (config_text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("!"):
            cur_acl = None
            continue
        m_og = re.match(r'^object-group\s+(ip\s+)?(network|service)\s+(\S+)', s, re.I)
        if m_og:
            kind = f"object-group-{m_og.group(2).lower()}"
            declared.append((m_og.group(3), kind, s))
            continue
        m_acl = re.match(r'^ip\s+access-list\s+(extended|standard)\s+(\S+)', s, re.I)
        if m_acl:
            cur_acl = m_acl.group(2)
            declared.append((cur_acl, f"acl-{m_acl.group(1).lower()}", s))
            continue
        if not line.startswith(" ") and not line.startswith("\t"):
            cur_acl = None
        if cur_acl is None or "access-group" in s or "object-group " in s or "match ip address" in s:
            if not re.match(r'^(object-group|ip access-list)\b', s, re.I):
                ref_lines.append(s)

    ref_blob = "\n".join(ref_lines)
    unused: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for name, kind, decl in declared:
        if name in seen:
            continue
        seen.add(name)
        if re.search(rf'(?<![A-Za-z0-9_.-]){re.escape(name)}(?![A-Za-z0-9_.-])', ref_blob):
            continue
        unused.append({
            "name": name,
            "kind": kind,
            "vendor": vendor,
            "detail": decl,
            "cli_dry_run": f"no {decl}",
            "cli_rollback": decl,
            "api_dry_run": f"RESTCONF PATCH dry-run remove {name}",
        })
    return unused


def extract_unused_objects(config_text: str, vendor: str = "fortios") -> List[Dict[str, Any]]:
    """Detect unreferenced firewall address/service objects and ACLs in a config."""
    v = (vendor or "fortios").lower()
    if v in ("fortios", "fortinet", "fortigate"):
        return _fortios_unused_objects(config_text)
    if v in ("panos", "paloalto"):
        return _panos_unused_objects(config_text)
    if v in ("junos", "juniper"):
        return _junos_unused_objects(config_text)
    return _ios_unused_objects(config_text, vendor=v)


# ---------------------------------------------------------------------------
# Hygiene Engine: Dead Policies + Flow-based Tightening + CLI/API Snippets
# ---------------------------------------------------------------------------

def _summarize_ips(ips: List[str]) -> List[str]:
    """Summarize observed IPv4 addresses into minimal /24 or /32 CIDRs."""
    valid: List[ipaddress.IPv4Address] = []
    seen: Set[str] = set()
    for raw in ips:
        s = str(raw or "").strip()
        if not s or s in seen:
            continue
        try:
            addr = ipaddress.IPv4Address(s)
        except ValueError:
            continue
        seen.add(s)
        valid.append(addr)
    if not valid:
        return []
    by_24: Dict[str, List[ipaddress.IPv4Address]] = {}
    for addr in valid:
        net24 = str(ipaddress.ip_network(f"{addr}/24", strict=False))
        by_24.setdefault(net24, []).append(addr)
    out: List[str] = []
    for net24, members in sorted(by_24.items()):
        if len(members) >= 3:
            out.append(net24)
        else:
            for m in sorted(members):
                out.append(f"{m}/32")
    return out


def _rule_hygiene_snippets(
    vendor: str,
    rule: Dict[str, Any],
    op: str,
    suggested_src: Optional[List[str]] = None,
    suggested_dst: Optional[List[str]] = None,
    suggested_svc: Optional[List[str]] = None,
) -> Tuple[str, str, str]:
    """Build (cli_dry_run, cli_rollback, api_dry_run) for dead-rule or tightening."""
    v = (vendor or "fortios").lower()
    rid = str(rule.get("policyid") or rule.get("rule_id") or "")
    rname = str(rule.get("name") or rid)
    src_old = str(rule.get("srcaddr") or "all")
    dst_old = str(rule.get("dstaddr") or "all")
    svc_old = str(rule.get("service") or "ALL")

    if op == "disable":
        if v == "fortios":
            cli = (
                "config firewall policy\n"
                f"    edit {rid}\n"
                "        set status disable\n"
                "    next\n"
                "end"
            )
            rb = (
                "config firewall policy\n"
                f"    edit {rid}\n"
                "        set status enable\n"
                "    next\n"
                "end"
            )
            api = f'PATCH /api/v2/cmdb/firewall/policy/{rid}  {{"status": "disable"}}'
            return cli, rb, api
        if v == "panos":
            cli = f'set rulebase security rules "{rname}" disabled yes'
            rb = f'set rulebase security rules "{rname}" disabled no'
            api = f'POST /api/?type=config&action=set&xpath=/config/.../security/rules/entry[@name="{rname}"] <disabled>yes</disabled>'
            return cli, rb, api
        if v == "junos":
            cli = f"deactivate security policies policy {rname}"
            rb = f"activate security policies policy {rname}"
            api = f"NETCONF <edit-config>: inactive='inactive' on policy {rname}"
            return cli, rb, api
        acl = str(rule.get("acl") or "ACL")
        raw = str(rule.get("raw_text") or "").strip()
        cli = f"ip access-list extended {acl}\n no {raw or rid}"
        rb = f"ip access-list extended {acl}\n {raw or rid}"
        api = f"RESTCONF DELETE ACL {acl} seq {rid}"
        return cli, rb, api

    # op == "tighten"
    srcs = suggested_src or ["<observed-src>"]
    dsts = suggested_dst or ["<observed-dst>"]
    svcs = suggested_svc or ["<observed-svc>"]
    if v == "fortios":
        cli_lines = ["config firewall address"]
        src_objs = []
        for idx, c in enumerate(srcs, 1):
            nm = f"HYG_SRC_{rid}_{idx}"
            net = ipaddress.ip_network(c, strict=False)
            cli_lines.append(f'    edit "{nm}"\n        set subnet {net.network_address} {net.netmask}\n    next')
            src_objs.append(f'"{nm}"')
        dst_objs = []
        for idx, c in enumerate(dsts, 1):
            nm = f"HYG_DST_{rid}_{idx}"
            net = ipaddress.ip_network(c, strict=False)
            cli_lines.append(f'    edit "{nm}"\n        set subnet {net.network_address} {net.netmask}\n    next')
            dst_objs.append(f'"{nm}"')
        cli_lines.append("end\nconfig firewall policy")
        cli_lines.append(
            f"    edit {rid}\n"
            f"        set srcaddr {' '.join(src_objs)}\n"
            f"        set dstaddr {' '.join(dst_objs)}\n"
            f"        set service {' '.join(svcs)}\n"
            "    next\nend"
        )
        rb = (
            "config firewall policy\n"
            f"    edit {rid}\n"
            f"        set srcaddr {src_old}\n"
            f"        set dstaddr {dst_old}\n"
            f"        set service {svc_old}\n"
            "    next\nend"
        )
        api = (
            f'PATCH /api/v2/cmdb/firewall/policy/{rid}  '
            f'{{"srcaddr": {srcs}, "dstaddr": {dsts}, "service": {svcs}}}'
        )
        return "\n".join(cli_lines), rb, api
    if v == "panos":
        cli = (
            f'set rulebase security rules "{rname}" source [ {" ".join(srcs)} ]\n'
            f'set rulebase security rules "{rname}" destination [ {" ".join(dsts)} ]\n'
            f'set rulebase security rules "{rname}" service [ {" ".join(svcs)} ]'
        )
        rb = (
            f'set rulebase security rules "{rname}" source {src_old}\n'
            f'set rulebase security rules "{rname}" destination {dst_old}\n'
            f'set rulebase security rules "{rname}" service {svc_old}'
        )
        api = f'POST /api/?type=config&action=set security rule "{rname}" source={srcs} dst={dsts}'
        return cli, rb, api
    if v == "junos":
        cli = (
            f"set security policies ... policy {rname} match source-address [ {' '.join(srcs)} ]\n"
            f"set security policies ... policy {rname} match destination-address [ {' '.join(dsts)} ]"
        )
        rb = f"rollback 1  # restore policy {rname} any-any"
        api = f"NETCONF <edit-config> candidate + commit check on {rname}"
        return cli, rb, api
    acl = str(rule.get("acl") or "ACL")
    cli = "\n".join(
        [f"ip access-list extended {acl}"]
        + [f" {rid} permit {s} {srcs[0]} {dsts[0]}" for s in svcs[:3]]
    )
    rb = f"ip access-list extended {acl}\n no {rid}\n {rule.get('raw_text') or ''}".strip()
    api = f"RESTCONF PATCH ACL {acl} seq {rid}"
    return cli, rb, api


HIGH_VOLUME_BYTES = 100_000_000
REORDER_MIN_POSITION = 6
_BULK_SERVICE_HINTS = (
    "veeam", "backup", "rsync", "iscsi", "smb", "cifs", "nfs",
    "sql", "mysql", "postgres", "oracle", "mssql", "replication",
)
_HYG_UTM_KEYS = (
    "av-profile", "ips-sensor", "webfilter-profile",
    "application-list", "dnsfilter-profile", "ssl-ssh-profile",
)


def _optimization_snippets(
    vendor: str,
    rule: Dict[str, Any],
    kind: str,
    first_pid: str = "",
    prev_pid: str = "",
    suggested_src: Optional[List[str]] = None,
    suggested_dst: Optional[List[str]] = None,
    suggested_svc: Optional[List[str]] = None,
) -> Tuple[str, str, str]:
    """Build (cli_dry_run, cli_rollback, api_dry_run) for reorder_top or spu_bypass."""
    v = (vendor or "fortios").lower()
    rid = str(rule.get("policyid") or rule.get("rule_id") or "")
    rname = str(rule.get("name") or rid)

    if kind == "reorder_top":
        if v == "fortios":
            cli = f"config firewall policy\n    move {rid} before {first_pid}\nend"
            rb = (
                f"config firewall policy\n    move {rid} after {prev_pid}\nend"
                if prev_pid else f"# Restore original order for policy {rid}"
            )
            api = f"PUT /api/v2/cmdb/firewall/policy/{rid}?action=move&before={first_pid}"
            return cli, rb, api
        return (
            f"# Move policy {rname} ({rid}) near top before {first_pid}",
            f"# Move policy {rname} ({rid}) back after {prev_pid or 'original position'}",
            f"PUT/PATCH reorder rule {rid} before {first_pid}",
        )

    # kind == "spu_bypass"
    insp = str(rule.get("inspection_mode") or "flow").lower()
    offload = str(rule.get("auto_asic_offload") or "enable").lower()
    if v == "fortios" and (insp == "proxy" or offload == "disable"):
        cli = (
            "config firewall policy\n"
            f"    edit {rid}\n"
            "        set inspection-mode flow\n"
            "        set auto-asic-offload enable\n"
            "    next\n"
            "end"
        )
        rb = (
            "config firewall policy\n"
            f"    edit {rid}\n"
            f"        set inspection-mode {insp}\n"
            f"        set auto-asic-offload {offload}\n"
            "    next\n"
            "end"
        )
        api = f'PATCH /api/v2/cmdb/firewall/policy/{rid}  {{"inspection-mode": "flow", "auto-asic-offload": "enable"}}'
        return cli, rb, api

    svc = (suggested_svc[0] if suggested_svc else (str(rule.get("service") or "ALL").split()[0] or "ALL"))
    safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", rname)[:32] or rid
    src_intf = str(rule.get("srcintf") or "lan").split()[0]
    dst_intf = str(rule.get("dstintf") or "wan1").split()[0]
    move_line = f"\n    move <new_id> before {first_pid}" if first_pid else ""
    cli = (
        "config firewall policy\n"
        "    edit 0\n"
        f'        set name "BYPASS_{safe_name}"\n'
        f'        set srcintf "{src_intf}"\n'
        f'        set dstintf "{dst_intf}"\n'
        "        set srcaddr <host_32>\n"
        "        set dstaddr <host_32>\n"
        "        set action accept\n"
        '        set schedule "always"\n'
        f"        set service {svc}\n"
        "        set auto-asic-offload enable\n"
        f"    next{move_line}\n"
        "end"
    )
    rb = "config firewall policy\n    delete <new_id>\nend"
    api = 'POST /api/v2/cmdb/firewall/policy  {"auto-asic-offload": "enable", "utm-status": "disable"}'
    return cli, rb, api


def _format_svc(proto: str, dport: Optional[int]) -> str:
    p = (proto or "ip").upper()
    if dport is None:
        return p
    well_known = {
        (6, 22): "SSH", (6, 80): "HTTP", (6, 443): "HTTPS",
        (6, 502): "MODBUS-TCP", (6, 102): "S7COMM", (6, 4840): "OPC-UA",
        (17, 53): "DNS", (17, 123): "NTP", (17, 161): "SNMP",
    }
    pnum = 6 if p == "TCP" else (17 if p == "UDP" else 0)
    if (pnum, int(dport)) in well_known:
        return well_known[(pnum, int(dport))]
    return f"{p}/{int(dport)}"


def _extract_backup_rules(content: str, config_type: str, device: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Any]:
    """Parse backup into canonical policy/rule dict rows + policy_test environment."""
    from services.policy_test.fortios import parse_fortios_config
    from services.policy_test.ios import parse_ios_config
    from services.policy_test.junos import parse_junos_config
    from services.policy_test.panos import parse_panos_config

    rows: List[Dict[str, Any]] = []
    env: Any = None
    hostname = device.get("Hostname") or device.get("IP") or ""
    ip = device.get("IP") or ""
    group = device.get("Group") or ""

    if config_type == "fortios":
        from fw_analyzers.fortios import _forti_get, _forti_tree, _forti_tokens

        env = parse_fortios_config(content)
        tree = _forti_tree(content)
        sec_node = _forti_get(tree, "firewall policy") or {}
        raw_pols = sec_node.get("children") if isinstance(sec_node, dict) and "children" in sec_node else sec_node
        rule_by_id = {str(r.id): r for r in env.policies}

        def _fval(b: Dict[str, Any], key: str, default: str) -> str:
            raw = b.get(key)
            if raw is None:
                return default
            toks = [str(x) for x in raw] if isinstance(raw, list) else _forti_tokens(str(raw))
            return " ".join(toks) or default

        if isinstance(raw_pols, dict):
            for pos, (pid, node) in enumerate(raw_pols.items(), start=1):
                if not isinstance(node, dict):
                    continue
                body = node.get("sets", {}) if "sets" in node else node
                rule = rule_by_id.get(str(pid))
                src = _fval(body, "srcaddr", "all")
                dst = _fval(body, "dstaddr", "all")
                svc = _fval(body, "service", "ALL")
                status = _fval(body, "status", "enable").lower()
                action = _fval(body, "action", "accept").lower()
                name = _fval(body, "name", "").strip('"')
                insp_mode = _fval(body, "inspection-mode", "flow").lower()
                asic_offload = _fval(body, "auto-asic-offload", "enable").lower()
                utm_status = _fval(body, "utm-status", "disable").lower()
                has_utm = (utm_status != "disable") and any(
                    k in body and _fval(body, k, "") != "" for k in _HYG_UTM_KEYS
                )
                rows.append({
                    "device": hostname, "device_ip": ip, "group": group,
                    "vendor": "fortios", "policyid": str(pid), "name": name,
                    "position": pos,
                    "srcintf": _fval(body, "srcintf", "any"),
                    "dstintf": _fval(body, "dstintf", "any"),
                    "srcaddr": src, "dstaddr": dst, "service": svc,
                    "action": action, "status": status,
                    "inspection_mode": insp_mode,
                    "auto_asic_offload": asic_offload,
                    "has_utm": has_utm,
                    "bytes": 0, "hit_count": 0, "active_sessions": 0,
                    "last_used": None, "never_hit": False,
                    "is_broad": (
                        ("all" in src.lower().split() or "any" in src.lower().split())
                        and ("all" in dst.lower().split() or "any" in dst.lower().split())
                    ) or (rule is not None and rule.fields.is_any_any()),
                    "_rule": rule,
                })
    elif config_type == "panos":
        env = parse_panos_config(content)
        for pos, rule in enumerate(env.policies, start=1):
            src_any = all(c.is_any() for c in rule.fields.src_ips)
            dst_any = all(c.is_any() for c in rule.fields.dst_ips)
            svc_any = rule.fields.dst_ports is None and rule.fields.protos is None
            rows.append({
                "device": hostname, "device_ip": ip, "group": group,
                "vendor": "panos", "policyid": str(rule.id), "name": rule.name or str(rule.id),
                "position": pos,
                "inspection_mode": "", "auto_asic_offload": "", "has_utm": False,
                "srcaddr": "any" if src_any else "scoped",
                "dstaddr": "any" if dst_any else "scoped",
                "service": "any" if svc_any else "scoped",
                "action": "accept" if rule.action == "permit" else "deny",
                "status": "disable" if rule.disabled else "enable",
                "bytes": 0, "hit_count": 0, "active_sessions": 0,
                "last_used": None, "never_hit": False,
                "is_broad": src_any and dst_any,
                "raw_text": rule.raw_text,
                "_rule": rule,
            })
    elif config_type == "junos":
        env = parse_junos_config(content)
        for pos, rule in enumerate(env.policies, start=1):
            src_any = all(c.is_any() for c in rule.fields.src_ips)
            dst_any = all(c.is_any() for c in rule.fields.dst_ips)
            svc_any = rule.fields.dst_ports is None and rule.fields.protos is None
            rows.append({
                "device": hostname, "device_ip": ip, "group": group,
                "vendor": "junos", "policyid": str(rule.id), "name": rule.name or str(rule.id),
                "position": pos,
                "inspection_mode": "", "auto_asic_offload": "", "has_utm": False,
                "srcaddr": "any" if src_any else "scoped",
                "dstaddr": "any" if dst_any else "scoped",
                "service": "any" if svc_any else "scoped",
                "action": "accept" if rule.action == "permit" else "deny",
                "status": "disable" if rule.disabled else "enable",
                "bytes": 0, "hit_count": 0, "active_sessions": 0,
                "last_used": None, "never_hit": False,
                "is_broad": src_any and dst_any,
                "raw_text": rule.raw_text,
                "_rule": rule,
            })
    elif config_type in ("ios", "nxos", "ot_switch"):
        env = parse_ios_config(content)
        pos = 0
        for acl_name, rs in env.acls.items():
            for rule in rs.rules:
                pos += 1
                src_any = all(c.is_any() for c in rule.fields.src_ips)
                dst_any = all(c.is_any() for c in rule.fields.dst_ips)
                svc_any = rule.fields.dst_ports is None and rule.fields.protos is None
                rows.append({
                    "device": hostname, "device_ip": ip, "group": group,
                    "vendor": config_type, "policyid": f"{acl_name}:{rule.id}",
                    "acl": acl_name, "name": f"{acl_name} seq {rule.id}",
                    "position": pos,
                    "inspection_mode": "", "auto_asic_offload": "", "has_utm": False,
                    "srcaddr": "any" if src_any else "scoped",
                    "dstaddr": "any" if dst_any else "scoped",
                    "service": "any" if svc_any else "scoped",
                    "action": "accept" if rule.action == "permit" else "deny",
                    "status": "disable" if rule.disabled else "enable",
                    "bytes": 0, "hit_count": 0, "active_sessions": 0,
                    "last_used": None, "never_hit": False,
                    "is_broad": src_any and dst_any and svc_any,
                    "raw_text": rule.raw_text,
                    "_rule": rule,
                })
    return rows, env


def _load_observed_flows(device_ips: List[str], tenants: List[str], since_ts: int) -> List[Dict[str, Any]]:
    """Query observed ``events`` rows carrying 4-tuple/5-tuple network flows."""
    import sqlite3

    dev_set = {ip for ip in device_ips if ip}
    ten_set = {t for t in tenants if t}
    if not dev_set and not ten_set:
        return []

    conn = db.get_observability_connection()
    try:
        try:
            rows = conn.execute(
                "SELECT ts, tenant, device_ip, src_ip, dst_ip, dst_port, protocol, attrs_json "
                "FROM events WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != '' "
                "AND dst_ip IS NOT NULL AND dst_ip != '' "
                "ORDER BY ts DESC LIMIT 2000",
                (int(since_ts),),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        out = []
        for r in rows:
            d = dict(r)
            if ten_set and d.get("tenant") not in ten_set:
                continue
            if not dev_set or d.get("device_ip") in dev_set or not d.get("device_ip"):
                out.append(d)
        return out
    finally:
        conn.close()


def _flow_matches_rule(rule_obj: Any, ev: Dict[str, Any]) -> bool:
    if rule_obj is None:
        return True
    from services.policy_test.model import Flow
    try:
        flow = Flow(
            src_ip=str(ev.get("src_ip") or ""),
            dst_ip=str(ev.get("dst_ip") or ""),
            proto=str(ev.get("protocol") or "tcp").lower(),
            dport=int(ev["dst_port"]) if ev.get("dst_port") else None,
        )
        return rule_obj.fields.matches(flow)
    except Exception:
        return True


def analyze_hygiene(
    devices: List[Dict[str, Any]],
    window_days: int = 30,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Run firewall hygiene & rule delta analysis across selected devices.

    Must run synchronously or inside ``asyncio.to_thread`` (uses blocking SQLite).
    """
    from ai import config_analyzer

    now = int(now_ts if now_ts is not None else time.time())
    since_ts = now - int(window_days) * 86400
    targets = hygiene_devices(devices)
    if not targets:
        return {
            "window_days": int(window_days),
            "devices_analyzed": 0,
            "summary": {
                "dead_policies": 0,
                "unused_objects": 0,
                "tightenable_rules": 0,
                "optimization_candidates": 0,
                "policies_tracked": 0,
                "snapshots_available": 0,
            },
            "dead_policies": [],
            "unused_objects": [],
            "tightenable_rules": [],
            "optimization_candidates": [],
            "policy_deltas": [],
        }

    dead_policies: List[Dict[str, Any]] = []
    unused_objects: List[Dict[str, Any]] = []
    tightenable_rules: List[Dict[str, Any]] = []
    optimization_candidates: List[Dict[str, Any]] = []
    policy_deltas: List[Dict[str, Any]] = []
    snapshots_available = 0

    observed = _load_observed_flows(
        [d["IP"] for d in targets if d.get("IP")],
        [str(d.get("Group") or "") for d in targets],
        since_ts,
    )

    for dev in targets:
        ip = str(dev.get("IP") or "")
        hostname = dev.get("Hostname") or ip
        group = str(dev.get("Group") or "")
        vendor_raw = str(dev.get("Vendor") or "").lower()

        path, _ = config_analyzer._find_freshest_backup(ip, group)
        content = ""
        cfg_type = vendor_raw
        if path:
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    raw = fh.read()
                content = "\n".join(config_analyzer.running_config(raw))
                cfg_type = config_analyzer.detect_config_type(content, dev)
            except OSError:
                content = ""

        # Unused objects from backup
        if content:
            for obj in extract_unused_objects(content, cfg_type):
                unused_objects.append({
                    "device": hostname,
                    "device_ip": ip,
                    "group": group,
                    **obj,
                })

        # Policy rows: combine backup structure + live counters + latest snapshot
        backup_rows, _env = _extract_backup_rules(content, cfg_type, dev) if content else ([], None)
        history = get_policy_snapshot_history(ip, group, since_ts=now - SNAPSHOT_HISTORY_DAYS * 86400)
        snapshots_available += len(history)
        latest_snap_by_pid: Dict[str, Dict[str, Any]] = {}
        for s in history:
            latest_snap_by_pid[str(s["policy_id"])] = s

        base_rows = backup_rows
        for r in base_rows:
            snap = latest_snap_by_pid.get(str(r.get("policyid")))
            if snap:
                r["hit_count"] = snap["hit_count"]
                r["bytes"] = snap["bytes"]
                r["last_used"] = snap["last_used"]
                r["never_hit"] = (snap["hit_count"] == 0 and snap["bytes"] == 0)

        enriched = compute_policy_deltas(ip, group, base_rows, now_ts=now)

        # Scope observed events relevant to this device/tenant
        dev_flows = [
            ev for ev in observed
            if (not group or ev.get("tenant") == group)
            and (ev.get("device_ip") == ip or not ev.get("device_ip"))
        ]
        # Fallback to tenant flows if device_ip had no direct tag
        if not dev_flows and group:
            dev_flows = [ev for ev in observed if ev.get("tenant") == group]

        ordered = sorted(enriched, key=lambda row: int(row.get("position") or 0))
        first_pid = ""
        prev_by_pid: Dict[str, str] = {}
        last_pid = ""
        for row in ordered:
            pid_s = str(row.get("policyid") or "")
            prev_by_pid[pid_s] = last_pid
            last_pid = pid_s
            if (
                not first_pid
                and (row.get("status") or "enable") == "enable"
                and (row.get("action") or "").lower() in ("accept", "permit")
            ):
                first_pid = pid_s
        if not first_pid and ordered:
            first_pid = str(ordered[0].get("policyid") or "")

        for r in enriched:
            rule_obj = r.pop("_rule", None)
            is_broad = bool(r.pop("is_broad", False))
            vendor = r.get("vendor") or cfg_type or vendor_raw
            policy_deltas.append(r)

            enabled = (r.get("status") or "enable") == "enable"
            action = (r.get("action") or "").lower()
            matching_flows = [ev for ev in dev_flows if _flow_matches_rule(rule_obj, ev)]

            # 1. Dead policy detection: enabled rule with 0 hits over 30d delta OR never_hit=True with 0 flows
            dh30 = r.get("delta_hits_30d")
            dh7 = r.get("delta_hits_7d")
            is_dead = False
            reason = ""
            if enabled and action in ("accept", "permit"):
                if dh30 is not None and dh30 == 0 and not matching_flows:
                    is_dead = True
                    reason = "0 hits over 30d snapshot window"
                elif dh30 is None and dh7 is not None and dh7 == 0 and int(r.get("hit_count") or 0) == 0 and not matching_flows:
                    is_dead = True
                    reason = "0 hits in recorded snapshots"
                elif r.get("never_hit") and int(r.get("hit_count") or 0) == 0 and not matching_flows:
                    is_dead = True
                    reason = "Counter never hit (0 hits / 0 B)"

            if is_dead:
                cli, rb, api = _rule_hygiene_snippets(vendor, r, "disable")
                dead_policies.append({
                    "device": hostname,
                    "device_ip": ip,
                    "group": group,
                    "vendor": vendor,
                    "policyid": r.get("policyid"),
                    "name": r.get("name") or f"Rule {r.get('policyid')}",
                    "srcaddr": r.get("srcaddr"),
                    "dstaddr": r.get("dstaddr"),
                    "service": r.get("service"),
                    "hit_count": r.get("hit_count") or 0,
                    "delta_hits_7d": dh7,
                    "delta_hits_30d": dh30,
                    "reason": reason,
                    "cli_dry_run": cli,
                    "cli_rollback": rb,
                    "api_dry_run": api,
                })

            # 2. Broad / any-any tightening from observed flows
            if enabled and action in ("accept", "permit") and is_broad and matching_flows:
                sug_src = _summarize_ips([str(ev["src_ip"]) for ev in matching_flows])
                sug_dst = _summarize_ips([str(ev["dst_ip"]) for ev in matching_flows])
                svcs = sorted({
                    _format_svc(str(ev.get("protocol") or "tcp"), ev.get("dst_port"))
                    for ev in matching_flows
                })
                if sug_src and sug_dst:
                    cli, rb, api = _rule_hygiene_snippets(
                        vendor, r, "tighten",
                        suggested_src=sug_src, suggested_dst=sug_dst, suggested_svc=svcs,
                    )
                    tightenable_rules.append({
                        "device": hostname,
                        "device_ip": ip,
                        "group": group,
                        "vendor": vendor,
                        "policyid": r.get("policyid"),
                        "name": r.get("name") or f"Rule {r.get('policyid')}",
                        "current": f"{r.get('srcaddr')} -> {r.get('dstaddr')} ({r.get('service')})",
                        "observed_flows": len(matching_flows),
                        "suggested_src": sug_src,
                        "suggested_dst": sug_dst,
                        "suggested_services": svcs,
                        "cli_dry_run": cli,
                        "cli_rollback": rb,
                        "api_dry_run": api,
                    })

            # 3. High-volume policy reorder and SPU bypass optimization candidates
            pos = int(r.get("position") or 0)
            vol = max(int(r.get("bytes") or 0), int(r.get("delta_bytes_30d") or 0))
            pid_s = str(r.get("policyid") or "")
            if enabled and action in ("accept", "permit") and vol >= HIGH_VOLUME_BYTES:
                if pos >= REORDER_MIN_POSITION and first_pid and pid_s != first_pid:
                    cli, rb, api = _optimization_snippets(
                        vendor, r, "reorder_top",
                        first_pid=first_pid, prev_pid=prev_by_pid.get(pid_s, ""),
                    )
                    optimization_candidates.append({
                        "device": hostname,
                        "device_ip": ip,
                        "group": group,
                        "vendor": vendor,
                        "policyid": r.get("policyid"),
                        "name": r.get("name") or f"Rule {r.get('policyid')}",
                        "position": pos,
                        "bytes": vol,
                        "hit_count": r.get("hit_count") or 0,
                        "kind": "reorder_top",
                        "reason": f"High-volume policy ({vol} B) at position #{pos}; move before #{first_pid}",
                        "cli_dry_run": cli,
                        "cli_rollback": rb,
                        "api_dry_run": api,
                    })

                if vendor == "fortios":
                    insp = str(r.get("inspection_mode") or "flow").lower()
                    offload = str(r.get("auto_asic_offload") or "enable").lower()
                    has_utm = bool(r.get("has_utm"))
                    txt = f"{r.get('name') or ''} {r.get('service') or ''}".lower()
                    is_bulk = has_utm and any(h in txt for h in _BULK_SERVICE_HINTS)
                    if insp == "proxy" or offload == "disable" or is_bulk:
                        if insp == "proxy":
                            opt_reason = "High-volume FortiOS policy using proxy inspection instead of flow/CP9"
                        elif offload == "disable":
                            opt_reason = "High-volume FortiOS policy with auto-asic-offload disabled"
                        else:
                            opt_reason = "Bulk backup/replication service with UTM active; candidate for /32 NPU bypass"
                        cli, rb, api = _optimization_snippets(
                            vendor, r, "spu_bypass",
                            first_pid=first_pid, prev_pid=prev_by_pid.get(pid_s, ""),
                        )
                        optimization_candidates.append({
                            "device": hostname,
                            "device_ip": ip,
                            "group": group,
                            "vendor": vendor,
                            "policyid": r.get("policyid"),
                            "name": r.get("name") or f"Rule {r.get('policyid')}",
                            "position": pos,
                            "bytes": vol,
                            "hit_count": r.get("hit_count") or 0,
                            "kind": "spu_bypass",
                            "reason": opt_reason,
                            "cli_dry_run": cli,
                            "cli_rollback": rb,
                            "api_dry_run": api,
                        })

    return {
        "window_days": int(window_days),
        "devices_analyzed": len(targets),
        "summary": {
            "dead_policies": len(dead_policies),
            "unused_objects": len(unused_objects),
            "tightenable_rules": len(tightenable_rules),
            "optimization_candidates": len(optimization_candidates),
            "policies_tracked": len(policy_deltas),
            "snapshots_available": snapshots_available,
        },
        "dead_policies": dead_policies,
        "unused_objects": unused_objects,
        "tightenable_rules": tightenable_rules,
        "optimization_candidates": optimization_candidates,
        "policy_deltas": policy_deltas,
    }

