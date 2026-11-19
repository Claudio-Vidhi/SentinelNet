# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Juniper Junos OS CLI driver."""

import re
from drivers.base_driver import BaseDriver


class JuniperJunosDriver(BaseDriver):
    def get_version(self) -> str:
        output = str(self.connection.send_command("show version") or "")
        match = re.search(r"Junos:\s*(\S+)", output, re.IGNORECASE)
        if not match:
            match = re.search(r"JUNOS\b.*?\[([^\]]+)\]", output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_model(self) -> str:
        output = str(self.connection.send_command("show version") or "")
        match = re.search(r"^\s*Model:\s*(\S+)", output, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else "Non Rilevato"

    def get_serial(self) -> str:
        output = str(self.connection.send_command("show chassis hardware") or "")
        match = re.search(r"^\s*Chassis\s+\S+\s+([A-Za-z0-9\-]+)", output, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else ""

    def get_backup_command(self) -> str:
        return "show configuration | display set"
