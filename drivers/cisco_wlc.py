import re
from drivers.base_driver import BaseDriver

class CiscoWlcDriver(BaseDriver):
    """Cisco AireOS WLC (series 2500/3500/5500/8500, vWLC)."""

    def get_version(self):
        # Example output: "Product Version.................................. 8.10.190.0"
        # AireOS scrive lentamente: con i 10 secondi di default di netmiko il
        # triage muore prima della fine di 'show sysinfo', e l'errore che
        # netmiko riporta parla del prompt invece che del tempo.
        output = self.connection.send_command("show sysinfo", read_timeout=60)
        match = re.search(r'Product Version\.*\s+(\S+)', output, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    def get_backup_command(self):
        return "show run-config commands"
