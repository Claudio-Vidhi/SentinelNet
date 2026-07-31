import re
from drivers.base_driver import BaseDriver

# Sequenze OSC di "shell integration" (Fedora, e sempre piu' distro, le emettono
# attorno al prompt: ESC ] 8003 ; start=<uuid> ... ESC \). Netmiko ripulisce solo
# le sequenze CSI, quindi queste finiscono dentro find_prompt() — e con esse un
# UUID DIVERSO A OGNI COMANDO. send_command costruisce il pattern di terminazione
# proprio dal prompt, quindi dopo il primo comando il pattern non corrisponde mai
# piu' e ogni lettura va in timeout.
_SHELL_INTEGRATION = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')


def sanitize_session(net_connect):
    """Toglie le sequenze OSC da tutto cio' che netmiko legge sulla sessione.

    ``strip_ansi_escape_codes`` e' gia' il punto in cui netmiko ripulisce
    l'output (LinuxSSH attiva ``ansi_escape_codes``): lo si estende invece di
    filtrare a valle, cosi' anche il prompt che netmiko usa per riconoscere la
    fine di un comando nasce pulito. ``set_base_prompt`` viene rifatto perche'
    quello calcolato alla connessione contiene ancora le sequenze.
    """
    original = net_connect.strip_ansi_escape_codes
    net_connect.strip_ansi_escape_codes = \
        lambda text: _SHELL_INTEGRATION.sub("", original(text))
    net_connect.set_base_prompt()

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
