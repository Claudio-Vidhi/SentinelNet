import re
from drivers.base_driver import BaseDriver

class PaloAltoDriver(BaseDriver):
    def get_version(self):
        output = self.connection.send_command("show system info")
        match = re.search(r'sw-version:\s*(\S+)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_backup_command(self):
        return "show config running"
