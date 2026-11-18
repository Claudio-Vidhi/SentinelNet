# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Phoenix Contact FL Switch and mGuard industrial driver."""

import re

from drivers.base_driver import BaseDriver


class PhoenixContactDriver(BaseDriver):
    """CLI driver for Phoenix Contact FL Switch 2000/3000/4000 and FL mGuard."""

    def _version_output(self) -> str:
        return str(self.connection.send_command("show version") or "")

    def get_version(self) -> str:
        output = self._version_output()
        patterns = (
            r"(?:Firmware\s+Version|Software\s+Version|Bootloader/Firmware)\s*:?\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)*(?:-[A-Za-z0-9]+)?)",
            r"\bVersion\s*:?\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)*)",
        )
        for pat in patterns:
            match = re.search(pat, output, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return "Unknown"

    def get_model(self) -> str:
        output = self._version_output()
        patterns = (
            r"(?:Device\s+Type|Product\s+Name|Hardware\s+Type|Model)\s*:?\s*(FL\s+[A-Za-z0-9\-/ ]+?)(?:\r|\n|$)",
            r"\b(FL\s+(?:SWITCH|MGUARD|NAT)\s*[A-Za-z0-9\-/]+)\b",
            r"(?:Order\s*(?:No|Number)\.?|Article\s*(?:No|Number)\.?)\s*:?\s*([0-9]{7})\b",
        )
        for pat in patterns:
            match = re.search(pat, output, re.IGNORECASE)
            if match:
                return re.sub(r"\s+", " ", match.group(1)).strip()
        return "Non Rilevato"

    def get_serial(self) -> str:
        output = self._version_output()
        match = re.search(
            r"(?:Serial\s*(?:No|Number)\.?|S/N)\s*:?\s*([A-Za-z0-9\-]+)",
            output,
            re.IGNORECASE,
        )
        return match.group(1).strip() if match else ""

    def get_backup_command(self) -> str:
        return "show running-config"
