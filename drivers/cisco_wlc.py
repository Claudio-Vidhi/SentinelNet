import re
from drivers.base_driver import BaseDriver

class CiscoWlcDriver(BaseDriver):
    """Cisco AireOS WLC (serie 2500/3500/5500/8500, vWLC)."""

    def get_version(self):
        # Esempio output: "Product Version.................................. 8.10.190.0"
        output = self.connection.send_command("show sysinfo")
        match = re.search(r'Product Version\.*\s+(\S+)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_backup_command(self):
        return "show run-config commands"
