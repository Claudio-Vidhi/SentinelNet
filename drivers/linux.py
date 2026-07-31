import re
from drivers.base_driver import BaseDriver

# File di configurazione leggibili da un account NON privilegiato. Sono anche
# l'input dell'audit CIS Linux: i marcatori '--- <path> ---' che li separano
# sono la stessa forma che _backup_section() gia' riconosce.
BACKUP_FILES = (
    "/etc/os-release",
    "/etc/ssh/sshd_config",
    "/etc/login.defs",
    "/etc/sysctl.conf",
    "/etc/fstab",
    "/etc/hosts",
    "/etc/resolv.conf",
)


class LinuxDriver(BaseDriver):
    def get_version(self):
        output = self.connection.send_command("cat /etc/os-release; uname -r")
        pretty = re.search(r'^PRETTY_NAME="?([^"\r\n]+)"?', output, re.MULTILINE)
        kernel = re.search(r'^(\d+\.\d+\.\S+)\s*$', output, re.MULTILINE)
        if not pretty:
            return "Unknown"
        return (f"{pretty.group(1).strip()} ({kernel.group(1)})" if kernel
                else pretty.group(1).strip())

    def get_backup_command(self):
        files = " ".join(f'"{f}"' for f in BACKUP_FILES)
        return (f'for f in {files}; do echo "--- $f ---"; '
                f'cat "$f" 2>/dev/null; done')
