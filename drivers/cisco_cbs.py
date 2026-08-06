import re
from drivers.base_driver import BaseDriver

class CiscoCbsDriver(BaseDriver):
    """Cisco Business / Small Business (CBS220/250/350, SG/SF300-500).
    Uses netmiko's 'cisco_s300' CLI: some of these switches don't respond
    like Catalysts (different prompt, pagination, and SSH algorithms)."""

    def get_version(self):
        output = self.connection.send_command("show version")
        # CBS examples: "Version: 3.2.0.84" / "Active-image ... version 2.5.7.85"
        match = re.search(r'[Vv]ersion[:\s]+([0-9]+(?:\.[0-9]+)+)', output)
        return match.group(1).strip() if match else "Unknown"

    def get_backup_command(self):
        return "show running-config"
