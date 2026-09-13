# -*- coding: utf-8 -*-
"""Windows SSH transport: netmiko 'generic' against cmd.exe behind ConPTY.

The fake shell below replays what a real Windows 11 OpenSSH session sent
(captured 2026-09-13, hostnames and paths replaced with example values):

- ConPTY opens with mode switches, a screen clear, hundreds of blank lines and
  an OSC window title, and repeats the title AFTER every prompt, so the last
  line never ends in '>';
- the title while a command runs carries the command itself, '|' included, on
  the same line as the output;
- a bare '\\n' does not submit a line: only '\\r' does. netmiko's default
  RETURN is '\\n', so find_prompt got no answer at all.
"""

import unittest

from netmiko import BaseConnection

from drivers.windows import (TRIAGE_COMMANDS, WindowsDriver, prepare_session,
                             ps, _fields)

PROMPT = "admin@WIN-01 C:\\Users\\admin>"
TITLE = "\x1b]0;Amministratore: C:\\WINDOWS\\system32\\conhost.exe\x07"
PREAMBLE = ("\x1b[?9001h\x1b[?1004h\x1b[?25l\x1b[2J\x1b[m\x1b[H" + "\n" * 300
            + "\x1b[H\x1b]0;C:\\WINDOWS\\system32\\conhost.exe\x07\x1b[?25h\x1b[?25l"
            "Microsoft Windows [Versione 10.0.26200.6584]\n"
            "(c) Microsoft Corporation. Tutti i diritti riservati.\x1b[4;1H"
            + PROMPT + TITLE + "\x1b[?25h")
VERSION_CMD = ps("$o = Get-CimInstance Win32_OperatingSystem; "
                 + _fields("o", "Caption", "Version", "OSArchitecture"))
HOSTNAME_CMD = TRIAGE_COMMANDS[0][0]
BACKUP_CMD = WindowsDriver(None).get_backup_command()
# Everything between the running-command title and the next prompt, verbatim.
# ConPTY replaces line breaks with cursor moves where it can: ESC[<r>;<c>H for
# a skipped line, ESC[<n>C for a run of spaces. Deleting those glued the
# HOSTNAME output onto the prompt line, and netmiko removed it as the prompt.
OUTPUTS = {
    VERSION_CMD: "Microsoft Windows 11 Home|10.0.26200|64 bit\n\n",
    HOSTNAME_CMD: "hostname WIN-01\x1b[?25l\x1b[31;1H",
    BACKUP_CMD: ("--- C:\\Windows\\System32\\drivers\\etc\\hosts ---\n"
                 "#       192.0.2.10     x.example.com          # x client host"
                 "\x1b[24;1H# localhost name resolution is handled within DNS itself.\n"
                 "#\x1b[7C127.0.0.1       localhost\n\x1b[?25h\n"),
}


class FakeConPtyCmd:
    """cmd.exe behind ConPTY, as the capture showed it."""

    def __init__(self):
        self.pending = PREAMBLE
        self.typed = ""

    def write_channel(self, data):
        self.typed += data
        while "\r" in self.typed:
            line, _, self.typed = self.typed.partition("\r")
            self.typed = self.typed.lstrip("\n")
            if not line:
                self.pending += "\n" + PROMPT + TITLE
                continue
            title = TITLE[:-1] + " - " + line + "\x07"
            self.pending += (line + "\n" + title + OUTPUTS.get(line, "\n\n")
                             + PROMPT + TITLE)

    def read_channel(self):
        out, self.pending = self.pending, ""
        return out


def _session():
    conn = BaseConnection(host="192.0.2.50", username="admin", password="x",
                          auto_connect=False)
    conn.channel = FakeConPtyCmd()
    return conn


class TestConPtySession(unittest.TestCase):

    def test_prompt_and_command_after_prepare_session(self):
        conn = _session()
        prepare_session(conn)
        self.assertEqual(conn.base_prompt, PROMPT[:-1])
        # cmd.exe prints a blank line before the next prompt: kept, harmless.
        self.assertEqual(conn.send_command(VERSION_CMD, read_timeout=5).strip(),
                         "Microsoft Windows 11 Home|10.0.26200|64 bit")

    def test_cursor_move_before_the_prompt_keeps_the_output(self):
        conn = _session()
        prepare_session(conn)
        # The triage order: the hosts backup first, then HOSTNAME.
        conn.send_command(BACKUP_CMD, read_timeout=5)
        self.assertEqual(conn.send_command(HOSTNAME_CMD, read_timeout=5).strip(),
                         "hostname WIN-01")

    def test_cursor_moves_inside_output_are_line_breaks_and_spaces(self):
        conn = _session()
        prepare_session(conn)
        lines = conn.send_command(BACKUP_CMD, read_timeout=5).splitlines()
        self.assertIn("# localhost name resolution is handled within DNS itself.", lines)
        self.assertIn("#       127.0.0.1       localhost", lines)


if __name__ == "__main__":
    unittest.main()
