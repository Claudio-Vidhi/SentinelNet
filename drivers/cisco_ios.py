import re
from drivers.base_driver import BaseDriver

class CiscoIosDriver(BaseDriver):
    def get_version(self) -> str:
        output = self.connection.send_command("show version")
        match = re.search(r', Version\s+([^,\r\n]+)', output, re.IGNORECASE)
        if not match:
            match = re.search(r'\bVersion\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-z0-9().]*)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_model(self) -> str:
        output = self.connection.send_command("show version")
        match = re.search(r'Model\s*(?:Number)?\s*:\s*(\S+)', output, re.IGNORECASE)
        if not match:
            match = re.search(r'\b(WS-C[A-Za-z0-9\-]+|C[0-9]{4}[A-Za-z0-9\-]*|N9K-[A-Za-z0-9\-]+)\b', output)
        if not match:
            match = re.search(r'cisco\s+([A-Za-z0-9\-]+)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Non Rilevato"

    def get_serial(self) -> str:
        output = self.connection.send_command("show version")
        # Catalyst/ISR: "System Serial Number            : FOC0000X0XX"
        match = re.search(r'System Serial Number\s*:\s*(\S+)', output, re.IGNORECASE)
        if not match:
            # Older IOS only prints "Processor board ID FOC0000X0XX".
            match = re.search(r'Processor board ID\s+(\S+)', output, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def get_backup_command(self) -> str:
        return "show running-config"
