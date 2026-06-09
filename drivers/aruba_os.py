import re
from drivers.base_driver import BaseDriver

class ArubaOsDriver(BaseDriver):
    def get_version(self):
        output = self.connection.send_command("show version")
        match = re.search(r'Version\s+([0-9][\w.\-]+)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_backup_command(self):
        return "show running-config"
