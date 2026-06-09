import re
from drivers.base_driver import BaseDriver

class FortinetDriver(BaseDriver):
    def get_version(self):
        # Esempio output: "Version: FortiGate-VM64 v7.2.5,build1517,230615 (GA)"
        output = self.connection.send_command("get system status")
        match = re.search(r'Version:\s*\S+\s+v([^,\s]+)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_backup_command(self):
        return "show full-configuration"
