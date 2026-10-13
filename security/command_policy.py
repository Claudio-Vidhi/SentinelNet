# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Single source of truth for the dangerous-CLI-command policy (WP5,
docs/app-review-fix-plan.md).

Before this module the same policy lived in THREE hand-maintained places
with three matching semantics (substring in core/core_engine.py, regex in
routers/commands.py, a smaller regex subset for bulk runs). The lists and
the matchers now live here; the old call sites keep their names and import
from here.

Three tiers:

- INTERACTIVE_PATTERNS — regexes applied to one-shot commands and to every
  line typed in the WebSocket terminal. Admins bypass; operators are subject
  while the 'cli_blacklist_operators' setting is on (default: on).
- BULK_ALWAYS_PATTERNS — regexes applied to bulk runs with NO role bypass:
  one destructive command against twenty devices at once is not an admin
  power, it is a mistake amplifier.
- SYSTEM_SUBSTRINGS — coarse substring net applied inside
  core_engine.send_custom_command as the last guard of the relay paths.

This is a parachute, not a sandbox: CLI abbreviations and vendor variants
can defeat any blacklist. The durable answer remains a per-vendor allowlist.
"""

import re
from typing import Optional

def _abbrev(word: str, shortest: int) -> str:
    """The word and every prefix of it down to ``shortest`` letters: IOS takes
    any unambiguous abbreviation, so 'rel' is reload and 'del' is delete."""
    return r"\b(?:%s)\b" % "|".join(word[:n] for n in range(len(word), shortest - 1, -1))


# Tier 1 — interactive (one-shot API + WS terminal). Vendor config-mode,
# reboot and erase-class commands. 'show/get/display' never match.
INTERACTIVE_PATTERNS = [
    _abbrev("reload", 3),
    _abbrev("erase", 3),
    _abbrev("delete", 3),
    _abbrev("format", 4),
    r"\breboot\b",
    # Config mode in any spelling: 'conf t', 'config term', 'configure',
    # FortiOS 'config system ...'. Anchored, so 'show configuration' passes.
    r"^conf\w*\b",
    r"\bconf\w*\s+t\w*\b",
    r"\bcopy\s+.*?startup-config\b",
    # Hardening aggiuntivo (denylist): altri comandi distruttivi/di riavvio o di
    # scrittura config sui vari vendor. Restano fuori i comandi 'show/get/display'.
    _abbrev("write", 2),             # 'wr', 'wri mem', 'write erase'
    r"\bboot\s+system\b",
    r"\bfactory[-\s]?reset\b",
    r"\brequest\s+system\b",         # Junos: reboot/halt/zeroize/software
    r"\brollback\b",
    r"\bhalt\b",
    r"\bzeroize\b",
    r"\bclear\s+config\b",
]

# Tier 2 — bulk runs, enforced for every role including admin.
BULK_ALWAYS_PATTERNS = [
    r"\breload\b",
    r"\breboot\b",
    r"\berase\b",
    r"\bformat\b",
    r"\bwrite\s+erase\b",
]

# Tier 3 — substring net inside core_engine.send_custom_command. Substring
# matching by design: it does not cover variants ('rm -fr', '--recursive'),
# it catches the destructive command typed by mistake on a relay path.
SYSTEM_SUBSTRINGS = [
    # Network CLI
    "write erase", "reload", "delete", "format", "no boot", "erase",
    # Linux: without these, a managed host has no protection net.
    # 'shutdown' is NOT included: on Cisco it is the normal command to shut
    # down a port, and blocking it would break everyday use.
    "rm -rf", "mkfs", "dd if=", "shred ", "reboot", "poweroff", ":(){",
]


def _first_match(command: str, patterns) -> Optional[str]:
    cmd_clean = command.strip().lower()
    for pattern in patterns:
        if re.search(pattern, cmd_clean):
            return pattern
    return None


def matches_interactive(command: str) -> Optional[str]:
    """First interactive-tier pattern matched, or None."""
    return _first_match(command, INTERACTIVE_PATTERNS)


def matches_bulk(command: str) -> Optional[str]:
    """First bulk-tier pattern matched, or None."""
    return _first_match(command, BULK_ALWAYS_PATTERNS)


READ_ONLY_VERBS = ("show", "display", "get")


def is_read_only(command: str) -> bool:
    """One line starting with a read verb (IOS/NX-OS 'show', Comware/Huawei
    'display', FortiOS 'get'). For commands stored now and run unattended
    later, where a denylist is the wrong tool."""
    parts = command.strip().lower().split()
    if "\n" in command or "\r" in command or not parts:
        return False
    verb = parts[0]
    # 'sh' / 'sho' are the usual IOS spellings of show.
    return verb in READ_ONLY_VERBS or (len(verb) >= 2 and "show".startswith(verb))


def matches_system(command: str) -> Optional[str]:
    """First system-tier substring matched, or None."""
    cmd_clean = command.lower()
    for needle in SYSTEM_SUBSTRINGS:
        if needle in cmd_clean:
            return needle
    return None
