# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Hirschmann (Belden) HiOS and Classic industrial switch driver."""

import re

from drivers.base_driver import BaseDriver


class HirschmannDriver(BaseDriver):
    """CLI driver for Hirschmann HiOS and Classic switches."""

    def _sysinfo(self) -> str:
        return str(self.connection.send_command("show sysinfo") or "")

    def get_version(self) -> str:
        output = self._sysinfo()
        # Running Release: HiOS-2S-09.0.00 | Software Version: 09.0.00 | Classic: L2E-08.0.10
        patterns = (
            r"(?:Running\s+Release|Software\s+Version|Firmware\s+Version)\s*:?\s*(?:HiOS-\w+-|L\d+\w*-)?([0-9]+\.[0-9]+(?:\.[0-9]+)*)",
            r"\bHiOS-[A-Za-z0-9]+-([0-9]+\.[0-9]+(?:\.[0-9]+)*)\b",
            r"\bVersion\s*:?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)*)\b",
        )
        for pat in patterns:
            match = re.search(pat, output, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return "Unknown"

    def get_model(self) -> str:
        output = self._sysinfo()
        patterns = (
            r"(?:Hardware\s+Description|Product\s+Name|Device\s+Type|Model)\s*:?\s*([A-Za-z0-9][A-Za-z0-9\-/._ ]+?)(?:\r|\n|$)",
            r"\b((?:RS|BRS|MSP|GRS|OCTOPUS|MACH|EES)[A-Za-z0-9\-]+)\b",
        )
        for pat in patterns:
            match = re.search(pat, output, re.IGNORECASE)
            if match:
                val = match.group(1).strip().rstrip(",")
                if val:
                    return val
        return "Non Rilevato"

    def get_serial(self) -> str:
        output = self._sysinfo()
        match = re.search(
            r"(?:Serial\s*(?:No|Number)\.?|Chassis\s+Serial)\s*:?\s*([A-Za-z0-9\-]+)",
            output,
            re.IGNORECASE,
        )
        return match.group(1).strip() if match else ""

    def get_backup_command(self) -> str:
        return "show running-config script"
