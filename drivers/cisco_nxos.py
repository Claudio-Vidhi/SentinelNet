# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Cisco NX-OS (Nexus) CLI driver."""

import re

from drivers.cisco_ios import CiscoIosDriver


class CiscoNxosDriver(CiscoIosDriver):
    """CLI driver for Cisco Nexus switches running NX-OS."""

    def get_version(self) -> str:
        output = str(self.connection.send_command("show version") or "")
        patterns = (
            r"NXOS:\s*version\s+(\S+)",
            r"system:\s*version\s+(\S+)",
            r"kickstart:\s*version\s+(\S+)",
        )
        for pat in patterns:
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return super().get_version()

    def get_model(self) -> str:
        output = str(self.connection.send_command("show version") or "")
        m = re.search(r"cisco\s+(Nexus\d+\s+\S+|N\d+K\-\S+)", output, re.IGNORECASE)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()
        return super().get_model()

    def get_backup_command(self) -> str:
        return "show running-config"
