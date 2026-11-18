# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Lightweight line-indexed parser for PAN-OS, Junos, NX-OS, and OT switches."""

from dataclasses import dataclass, field
from typing import Any, List, Optional
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class MVLine:
    """Single non-empty, non-comment configuration line with 1-based line number."""
    line: int
    text: str
    lower: str


@dataclass
class MVConfig:
    """Parsed multi-vendor configuration container."""
    vendor: str
    lines: List[MVLine] = field(default_factory=list)
    records: List[MVLine] = field(default_factory=list)
    raw_text: str = ""
    xml_root: Optional[Any] = None


def parse_multivendor(config_text: Optional[str], vendor: str) -> MVConfig:
    """Parse PAN-OS, Junos, NX-OS, or OT switch config into MVConfig."""
    raw = config_text or ""
    lines: List[MVLine] = []
    for idx, ln in enumerate(raw.splitlines(), start=1):
        s = ln.strip()
        if not s or s.startswith(("!", "#")):
            continue
        lines.append(MVLine(line=idx, text=s, lower=s.lower()))

    xml_root = None
    if vendor == "panos" and raw.lstrip().startswith("<"):
        try:
            xml_root = ET.fromstring(raw)
        except ET.ParseError:
            xml_root = None

    return MVConfig(
        vendor=vendor,
        lines=lines,
        records=list(lines),
        raw_text=raw,
        xml_root=xml_root,
    )
