import re
from drivers.base_driver import BaseDriver

class FortinetDriver(BaseDriver):
    def get_version(self) -> str:
        # Example output: "Version: FortiGate-VM64 v7.2.5,build1517,230615 (GA)"
        output = self.connection.send_command("get system status")
        match = re.search(r'Version:\s*\S+\s+v([^,\s]+)', output, re.IGNORECASE)
        if not match:
            match = re.search(r'Version:\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_model(self) -> str:
        output = self.connection.send_command("get system status")
        match = re.search(r'Version:\s*([A-Za-z0-9\-_]+)\s+v', output, re.IGNORECASE)
        if not match:
            match = re.search(r'Platform\s*Name\s*:\s*(\S+)', output, re.IGNORECASE)
        if not match:
            match = re.search(r'Model\s*name\s*:\s*(\S+)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Non Rilevato"

    def get_backup_command(self) -> str:
        return "show full-configuration"
