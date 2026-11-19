# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Moxa industrial switch and router (EDS / EDR series) driver."""

import re

from drivers.base_driver import BaseDriver


class MoxaDriver(BaseDriver):
    """CLI driver for Moxa EDS / EDR industrial networking devices."""

    def _sys_output(self) -> str:
        return str(self.connection.send_command("show system") or "")

    def get_version(self) -> str:
        output = self._sys_output()
        patterns = (
            r"(?:Firmware\s+Version|Software\s+Version|OS\s+Version)\s*:?\s*V?([0-9]+\.[0-9]+(?:\.[0-9]+)*(?:-[A-Za-z0-9]+)?)",
            r"\bVersion\s*:?\s*V?([0-9]+\.[0-9]+(?:\.[0-9]+)*)",
        )
        for pat in patterns:
            match = re.search(pat, output, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return "Unknown"

    def get_model(self) -> str:
        output = self._sys_output()
        patterns = (
            r"(?:Model\s+Name|Hardware\s+Model|Product\s+Model)\s*:?\s*([A-Za-z0-9\-_]+)",
            r"\b((?:EDS|EDR|IKS|PT|TN)-[A-Za-z0-9\-]+)\b",
        )
        for pat in patterns:
            match = re.search(pat, output, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return "Non Rilevato"

    def get_serial(self) -> str:
        output = self._sys_output()
        match = re.search(
            r"(?:Serial\s*(?:No|Number)\.?|S/N)\s*:?\s*([A-Za-z0-9\-]+)",
            output,
            re.IGNORECASE,
        )
        return match.group(1).strip() if match else ""

    def get_backup_command(self) -> str:
        return "show running-config"
