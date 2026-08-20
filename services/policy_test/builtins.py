# -*- coding: utf-8 -*-
"""FortiOS factory builtin objects.

FortiOS configurations reference built-in factory objects (e.g. service 'HTTPS',
address 'all') that are omitted from 'show full-configuration' backups.
This module provides a pure lookup table for standard FortiOS built-in objects.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from services.policy_test.model import Cube

BUILTIN_ADDRESSES: Dict[str, List[Cube]] = {
    "all": [Cube.any()],
    "none": [],
    "all_ipv4": [Cube.any()],
}

BUILTIN_SERVICES: Dict[str, Dict[str, Any]] = {
    "all": {"protos": None, "dst_ports": None},
    "all_tcp": {"protos": {6}, "dst_ports": [(1, 65535)]},
    "all_udp": {"protos": {17}, "dst_ports": [(1, 65535)]},
    "all_icmp": {"protos": {1}, "dst_ports": None},
    "ping": {"protos": {1}, "dst_ports": None},
    "http": {"protos": {6}, "dst_ports": [(80, 80)]},
    "https": {"protos": {6}, "dst_ports": [(443, 443)]},
    "ssh": {"protos": {6}, "dst_ports": [(22, 22)]},
    "telnet": {"protos": {6}, "dst_ports": [(23, 23)]},
    "dns": {"protos": {6, 17}, "dst_ports": [(53, 53)]},
    "smtp": {"protos": {6}, "dst_ports": [(25, 25)]},
    "smtps": {"protos": {6}, "dst_ports": [(465, 465)]},
    "ftp": {"protos": {6}, "dst_ports": [(21, 21)]},
    "ftp_get": {"protos": {6}, "dst_ports": [(21, 21)]},
    "ftp_put": {"protos": {6}, "dst_ports": [(21, 21)]},
    "ntp": {"protos": {17}, "dst_ports": [(123, 123)]},
    "snmp": {"protos": {17}, "dst_ports": [(161, 162)]},
    "rdp": {"protos": {6, 17}, "dst_ports": [(3389, 3389)]},
    "syslog": {"protos": {17}, "dst_ports": [(514, 514)]},
    "ike": {"protos": {17}, "dst_ports": [(500, 500), (4500, 4500)]},
    "ldap": {"protos": {6}, "dst_ports": [(389, 389)]},
    "ldaps": {"protos": {6}, "dst_ports": [(636, 636)]},
    "radius": {"protos": {17}, "dst_ports": [(1812, 1813)]},
    "radius-acct": {"protos": {17}, "dst_ports": [(1813, 1813)]},
    "kerberos": {"protos": {6, 17}, "dst_ports": [(88, 88)]},
    "imap": {"protos": {6}, "dst_ports": [(143, 143)]},
    "imaps": {"protos": {6}, "dst_ports": [(993, 993)]},
    "pop3": {"protos": {6}, "dst_ports": [(110, 110)]},
    "pop3s": {"protos": {6}, "dst_ports": [(995, 995)]},
    "mysql": {"protos": {6}, "dst_ports": [(3306, 3306)]},
    "mssql": {"protos": {6}, "dst_ports": [(1433, 1433)]},
    "ms-sql": {"protos": {6}, "dst_ports": [(1433, 1433)]},
    "oracle": {"protos": {6}, "dst_ports": [(1521, 1521)]},
    "sip": {"protos": {6, 17}, "dst_ports": [(5060, 5060)]},
    "squid": {"protos": {6}, "dst_ports": [(3128, 3128)]},
    "vnc": {"protos": {6}, "dst_ports": [(5900, 5900)]},
    "bgp": {"protos": {6}, "dst_ports": [(179, 179)]},
    "gre": {"protos": {47}, "dst_ports": None},
    "ah": {"protos": {51}, "dst_ports": None},
    "esp": {"protos": {50}, "dst_ports": None},
    "ospf": {"protos": {89}, "dst_ports": None},
    "webaccess": {"protos": {6}, "dst_ports": [(80, 80), (443, 443)]},
}


def lookup_builtin_address(name: str) -> Optional[List[Cube]]:
    """Look up a FortiOS factory built-in address."""
    return BUILTIN_ADDRESSES.get(name.strip().lower())


def lookup_builtin_service(name: str) -> Optional[Dict[str, Any]]:
    """Look up a FortiOS factory built-in service."""
    return BUILTIN_SERVICES.get(name.strip().lower())
