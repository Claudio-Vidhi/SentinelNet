# -*- coding: utf-8 -*-
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

# Tier 1 — interactive (one-shot API + WS terminal). Vendor config-mode,
# reboot and erase-class commands. 'show/get/display' never match.
INTERACTIVE_PATTERNS = [
    r"\breload\b",
    r"\berase\b",
    r"\bdelete\b",
    r"\bformat\b",
    r"\breboot\b",
    r"\bconf\s+t\b",
    r"\bconfigure\s+terminal\b",
    r"\bcopy\s+.*?startup-config\b",
    # Hardening aggiuntivo (denylist): altri comandi distruttivi/di riavvio o di
    # scrittura config sui vari vendor. Restano fuori i comandi 'show/get/display'.
    r"\bwr\b",                       # 'wr', 'wr mem', 'wr erase'
    r"\bwrite\b",                    # 'write memory', 'write erase'
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


def matches_system(command: str) -> Optional[str]:
    """First system-tier substring matched, or None."""
    cmd_clean = command.lower()
    for needle in SYSTEM_SUBSTRINGS:
        if needle in cmd_clean:
            return needle
    return None
