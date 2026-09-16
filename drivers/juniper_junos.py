# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import re
from drivers.base_driver import BaseDriver

class JuniperJunosDriver(BaseDriver):
    def get_version(self):
        output = self.connection.send_command("show version")
        match = re.search(r'Junos:\s*(\S+)', output, re.IGNORECASE)
        if not match:
            match = re.search(r'JUNOS\b.*?\[([^\]]+)\]', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_backup_command(self):
        return "show configuration | display set"
