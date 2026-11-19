# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Siemens SCALANCE (X / XC / XR / W) industrial switch and AP driver."""

import re

from drivers.base_driver import BaseDriver


class SiemensScalanceDriver(BaseDriver):
    """CLI driver for Siemens SCALANCE X, XC, XR, and W families."""

    def _sys_info(self) -> str:
        return str(self.connection.send_command("show versions") or "")

    def get_version(self) -> str:
        output = self._sys_info()
        # Firmware : V04.04.00 | SW-Version: V6.5.2 | SCALANCE XC208 ... V04.05.00
        patterns = (
            r"(?:Firmware(?:\s+Version)?|SW-Version|Software\s+Version)\s*:?\s*V?([0-9]+(?:\.[0-9]+)+(?:[._-][A-Za-z0-9]+)*)",
            r"Hardware/Firmware[^\r\n]*\bV([0-9]+(?:\.[0-9]+)+)",
            r"\bV([0-9]+\.[0-9]+(?:\.[0-9]+)+)\b",
        )
        for pat in patterns:
            match = re.search(pat, output, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return "Unknown"

    def get_model(self) -> str:
        output = self._sys_info()
        # Order No / Article No (6GK5...) or SCALANCE model name (e.g. SCALANCE XC208)
        patterns = (
            r"(?:Order\s*(?:No|Number)\.?|Article\s*(?:No|Number)\.?|MLFB)\s*:?\s*(6GK5[0-9A-Za-z\-]+)",
            r"(?:Device\s+Type|Product\s+Name|Model)\s*:?\s*(SCALANCE\s+[A-Za-z0-9\-]+)",
            r"\b(SCALANCE\s+[A-Za-z0-9\-]+)\b",
            r"\b(6GK5[0-9]{3}-[0-9A-Za-z\-]+)\b",
        )
        for pat in patterns:
            match = re.search(pat, output, re.IGNORECASE)
            if match:
                return re.sub(r"\s+", " ", match.group(1)).strip()
        return "Non Rilevato"

    def get_serial(self) -> str:
        output = self._sys_info()
        patterns = (
            r"\b(S\s*C-[A-Za-z0-9]+|SVP[A-Za-z0-9]+)\b",
            r"(?:Serial\s*(?:No|Number)\.?|S/N)\s*:?\s*([A-Za-z0-9][A-Za-z0-9\- ]*?)(?:\r|\n|$)",
        )
        for pat in patterns:
            match = re.search(pat, output, re.IGNORECASE)
            if match:
                return re.sub(r"\s+", " ", match.group(1)).strip()
        return ""

    def get_backup_command(self) -> str:
        return "show running-config"
