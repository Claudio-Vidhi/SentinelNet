import re
from drivers.base_driver import BaseDriver

# OSC sequences of "shell integration" (Fedora, and increasingly more distros,
# emit them around the prompt: ESC ] 8003 ; start=<uuid> ... ESC \). Netmiko
# only cleans CSI sequences, so these end up inside find_prompt() — and with
# them a DIFFERENT UUID ON EVERY COMMAND. send_command builds the termination
# pattern right from the prompt, so after the first command the pattern never
# matches again and every read times out.
_SHELL_INTEGRATION = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')

# Generic CSI sequences (color, bold, cursor movement). Netmiko only removes
# a closed list of them, not the general form: systemd's color codes
# (ESC[0;1;32m around "enabled") aren't in that list and ended up in the
# artifact, and from there into the UI tables.
_ANSI_CSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')


def sanitize_session(net_connect):
    """Strips escape sequences from everything netmiko reads on the session.

    ``strip_ansi_escape_codes`` is already the point at which netmiko cleans
    the output (LinuxSSH enables ``ansi_escape_codes``): it's extended rather
    than filtering downstream, so the prompt netmiko uses to detect the end of
    a command is also born clean. ``set_base_prompt`` is redone because the
    one computed at connection still contains the sequences.
    """
    original = net_connect.strip_ansi_escape_codes
    net_connect.strip_ansi_escape_codes = \
        lambda text: _ANSI_CSI.sub("", _SHELL_INTEGRATION.sub("", original(text)))
    net_connect.set_base_prompt()

# Configuration files readable by a NON-privileged account. They're also the
# input to the CIS Linux audit: the '--- <path> ---' markers that separate
# them are the same form _backup_section() already recognizes.
BACKUP_FILES = (
    "/etc/os-release",
    "/etc/ssh/sshd_config",
    "/etc/login.defs",
    "/etc/sysctl.conf",
    "/etc/fstab",
    "/etc/hosts",
    "/etc/resolv.conf",
    # Local users and groups. /etc/shadow is deliberately left out: password
    # hashes don't belong in an artifact that gets archived and re-read.
    "/etc/passwd",
    "/etc/group",
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
