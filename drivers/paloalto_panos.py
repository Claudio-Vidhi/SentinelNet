# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Palo Alto PAN-OS CLI driver and XML API helpers (policies, NAT, routes, zones)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl
from xml.etree import ElementTree as ET

from drivers.base_driver import BaseDriver


class PanOSError(RuntimeError):
    """Raised when a PAN-OS XML API call fails or returns an error status."""


def _safe_xml_root(xml_text: str) -> ET.Element:
    text = (xml_text or "").strip()
    if not text:
        raise ValueError("Empty PAN-OS XML payload.")
    if "<!ENTITY" in text.upper() or "<!DOCTYPE" in text.upper():
        raise ValueError("Unsafe XML DTD declarations are not allowed.")
    return ET.fromstring(text)


def api_request(
    host: str,
    api_key: str,
    req_type: str = "op",
    cmd: str = "",
    xpath: str = "",
    timeout: int = 12,
    verify_tls: bool = False,
) -> str:
    """Execute a synchronous PAN-OS XML API request over HTTPS (/api/)."""
    params: Dict[str, str] = {"type": req_type, "key": api_key}
    if cmd:
        params["cmd"] = cmd
    if xpath:
        params["xpath"] = xpath
    url = f"https://{host}/api/?{urlencode(params)}"
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    req = Request(url, headers={"Accept": "application/xml"})
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, OSError) as e:
        raise PanOSError(f"PAN-OS XML API request failed for {host}: {e}") from e
    try:
        root = _safe_xml_root(body)
    except (ET.ParseError, ValueError) as e:
        raise PanOSError(f"Invalid PAN-OS XML response from {host}: {e}") from e
    if (root.attrib.get("status") or "").lower() == "error":
        msg = "".join(root.itertext()).strip() or "PAN-OS API returned error"
        raise PanOSError(msg)
    return body


def parse_panos_xml_routes(xml_text: str) -> List[Dict[str, Any]]:
    """Parse PAN-OS `<show><routing><route>` XML response into normalized route dicts."""
    root = _safe_xml_root(xml_text)
    rows: List[Dict[str, Any]] = []
    for entry in root.findall(".//result/entry"):
        dst = (entry.findtext("destination") or "").strip()
        if not dst or "/" not in dst:
            continue
        nexthop = (entry.findtext("nexthop") or "").strip()
        if nexthop.lower() in ("discard", "none", "0.0.0.0"):
            nexthop = ""
        iface = (entry.findtext("interface") or "").strip()
        vr = (entry.findtext("virtual-router") or "").strip()
        flags = (entry.findtext("flags") or "").upper()
        metric_s = (entry.findtext("metric") or "").strip()
        metric = int(metric_s) if metric_s.isdigit() else 0
        if "C" in flags:
            rtype = "connected"
        elif "H" in flags:
            rtype = "local"
        elif "S" in flags:
            rtype = "static"
        elif "O" in flags:
            rtype = "ospf"
        elif "B" in flags:
            rtype = "bgp"
        elif "R" in flags:
            rtype = "rip"
        else:
            rtype = "other"
        rows.append({
            "network": dst,
            "gateway": nexthop,
            "interface": iface,
            "type": rtype,
            "raw_type": flags or rtype,
            "vrf": "" if vr in ("", "default") else vr,
            "distance": metric,
            "metric": metric,
        })
    return rows


def parse_panos_xml_interfaces(xml_text: str) -> List[Dict[str, str]]:
    """Parse PAN-OS `<show><interface>all</interface></show>` XML into interface records."""
    root = _safe_xml_root(xml_text)
    out: List[Dict[str, str]] = []
    seen = set()
    for node in root.findall(".//ifnet/entry") + root.findall(".//hw/entry"):
        name = (node.findtext("name") or "").strip()
        ip_cidr = (node.findtext("ip") or "").strip()
        zone = (node.findtext("zone") or "").strip()
        if not name or not ip_cidr or ip_cidr.lower() in ("n/a", "dhcp", "none"):
            continue
        ip_only = ip_cidr.split("/")[0].strip()
        try:
            net = str(ipaddress.ip_network(ip_cidr, strict=False))
        except ValueError:
            net = ""
        key = (name, ip_only)
        if key in seen:
            continue
        seen.add(key)
        out.append({"iface": name, "ip": ip_only, "network": net, "zone": zone})
    return out


def parse_panos_xml_config(xml_text: str) -> Dict[str, Any]:
    """Extract security policies, NAT rules, objects, zones, interfaces & static routes from XML config."""
    root = _safe_xml_root(xml_text)
    cfg = root.find(".//config") if root.tag != "config" else root
    if cfg is None:
        cfg = root

    hostname = (cfg.findtext(".//deviceconfig/system/hostname") or "").strip()
    addresses: Dict[str, str] = {}
    address_groups: Dict[str, List[str]] = {}
    services: Dict[str, Dict[str, str]] = {}
    service_groups: Dict[str, List[str]] = {}
    zones: Dict[str, List[str]] = {}
    interfaces: Dict[str, Dict[str, str]] = {}
    security_rules: List[Dict[str, Any]] = []
    nat_rules: List[Dict[str, Any]] = []
    static_routes: List[Dict[str, Any]] = []

    for addr in cfg.findall(".//address/entry"):
        name = (addr.attrib.get("name") or "").strip()
        val = (
            addr.findtext("ip-netmask")
            or addr.findtext("ip-range")
            or addr.findtext("fqdn")
            or ""
        ).strip()
        if name and val:
            addresses[name] = val

    for grp in cfg.findall(".//address-group/entry"):
        name = (grp.attrib.get("name") or "").strip()
        members = [(m.text or "").strip() for m in grp.findall("./static/member") if (m.text or "").strip()]
        if name:
            address_groups[name] = members

    for svc in cfg.findall(".//service/entry"):
        name = (svc.attrib.get("name") or "").strip()
        if not name:
            continue
        for proto in ("tcp", "udp"):
            pnode = svc.find(f"./protocol/{proto}")
            if pnode is not None:
                port = (pnode.findtext("port") or "").strip()
                services[name] = {"proto": proto, "port": port}
                break

    for sgrp in cfg.findall(".//service-group/entry"):
        name = (sgrp.attrib.get("name") or "").strip()
        members = [(m.text or "").strip() for m in sgrp.findall("./members/member") if (m.text or "").strip()]
        if name:
            service_groups[name] = members

    for z in cfg.findall(".//zone/entry"):
        zname = (z.attrib.get("name") or "").strip()
        if not zname:
            continue
        ifaces = [
            (m.text or "").strip()
            for m in z.findall("./network/layer3/member") + z.findall("./network/layer2/member")
            if (m.text or "").strip()
        ]
        zones[zname] = ifaces
        for ifname in ifaces:
            interfaces.setdefault(ifname, {})["zone"] = zname

    for eth in cfg.findall(".//network/interface/ethernet/entry") + cfg.findall(".//network/interface/vlan/units/entry"):
        iname = (eth.attrib.get("name") or "").strip()
        ip_el = eth.find("./layer3/ip/entry")
        if ip_el is None:
            ip_el = eth.find("./ip/entry")
        if iname and ip_el is not None:
            ip_cidr = (ip_el.attrib.get("name") or "").strip()
            if ip_cidr:
                interfaces.setdefault(iname, {}).update({"ip_cidr": ip_cidr})
        for unit in eth.findall("./layer3/units/entry"):
            uname = (unit.attrib.get("name") or "").strip()
            uip = unit.find("./ip/entry")
            if uname and uip is not None and (uip.attrib.get("name") or "").strip():
                interfaces.setdefault(uname, {}).update({"ip_cidr": uip.attrib["name"].strip()})

    def _members(parent: ET.Element, tag: str) -> List[str]:
        return [(m.text or "").strip() for m in parent.findall(f"./{tag}/member") if (m.text or "").strip()]

    for rule in cfg.findall(".//rulebase/security/rules/entry"):
        rname = (rule.attrib.get("name") or "").strip()
        if not rname:
            continue
        disabled = (rule.attrib.get("disabled") or rule.findtext("disabled") or "").strip().lower() == "yes"
        action = (rule.findtext("action") or "allow").strip().lower()
        security_rules.append({
            "name": rname,
            "disabled": disabled,
            "action": "permit" if action == "allow" else "deny",
            "from": _members(rule, "from"),
            "to": _members(rule, "to"),
            "source": _members(rule, "source"),
            "destination": _members(rule, "destination"),
            "service": _members(rule, "service"),
            "application": _members(rule, "application"),
        })

    for nrule in cfg.findall(".//rulebase/nat/rules/entry"):
        nname = (nrule.attrib.get("name") or "").strip()
        if not nname:
            continue
        dnat = nrule.findtext(".//destination-translation/translated-address") or ""
        snat = nrule.findtext(".//source-translation//translated-address/member") or ""
        snat_intf = nrule.findtext(".//source-translation//interface-address/interface") or ""
        nat_rules.append({
            "name": nname,
            "disabled": (nrule.attrib.get("disabled") or nrule.findtext("disabled") or "").strip().lower() == "yes",
            "from": _members(nrule, "from"),
            "to": _members(nrule, "to"),
            "source": _members(nrule, "source"),
            "destination": _members(nrule, "destination"),
            "dnat": dnat.strip(),
            "snat": snat.strip() or snat_intf.strip(),
        })

    for vr in cfg.findall(".//network/virtual-router/entry"):
        vname = (vr.attrib.get("name") or "").strip()
        vrf = "" if vname in ("", "default") else vname
        for sr in vr.findall("./routing-table/ip/static-route/entry"):
            dest = (sr.findtext("destination") or "").strip()
            nh = (sr.findtext("./nexthop/ip-address") or "").strip()
            intf = (sr.findtext("interface") or "").strip()
            metric_s = (sr.findtext("metric") or "").strip()
            if dest:
                static_routes.append({
                    "name": (sr.attrib.get("name") or "").strip(),
                    "prefix": dest,
                    "next_hop": nh,
                    "interface": intf,
                    "vrf": vrf,
                    "metric": int(metric_s) if metric_s.isdigit() else 10,
                })

    return {
        "hostname": hostname,
        "addresses": addresses,
        "address_groups": address_groups,
        "services": services,
        "service_groups": service_groups,
        "zones": zones,
        "interfaces": interfaces,
        "security_rules": security_rules,
        "nat_rules": nat_rules,
        "static_routes": static_routes,
    }


def get_routes(device: Dict[str, Any], api_key: str) -> List[Dict[str, Any]]:
    body = api_request(str(device["IP"]), api_key, req_type="op", cmd="<show><routing><route></route></routing></show>")
    return parse_panos_xml_routes(body)


def get_interfaces(device: Dict[str, Any], api_key: str) -> List[Dict[str, str]]:
    body = api_request(str(device["IP"]), api_key, req_type="op", cmd="<show><interface>all</interface></show>")
    return parse_panos_xml_interfaces(body)


class PaloAltoDriver(BaseDriver):
    def get_version(self) -> str:
        output = str(self.connection.send_command("show system info") or "")
        match = re.search(r"sw-version:\s*(\S+)", output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_serial(self) -> str:
        output = str(self.connection.send_command("show system info") or "")
        match = re.search(r"^\s*serial:\s*(\S+)", output, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else ""

    def get_model(self) -> str:
        output = str(self.connection.send_command("show system info") or "")
        match = re.search(r"^\s*model:\s*(\S+)", output, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else "Non Rilevato"

    def get_backup_command(self) -> str:
        return "show config running"
