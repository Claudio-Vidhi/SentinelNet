# -*- coding: utf-8 -*-
"""Per-tenant config baseline: required and forbidden lines.

A whole-file diff against a golden config produces noise, not signal: every
device legitimately differs in hostname, management address, VLAN set and port
ranges. So the baseline is a set of line rules instead.

This is not an audit. There is no score, no grade and no severity — the netsec
audit already owns that question, with its own benchmarks and export.
"""
import json
import re

from services.config_drift import normalize


def _store_path() -> str:
    from core import data_config
    return data_config.get_path("config_baselines.json")


def parse(text: str) -> list:
    """Turn baseline text into rules. Unmarked lines and comments are ignored,
    so a half-typed line never silently becomes a requirement."""
    rules = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line[0] not in "+-":
            continue
        pattern = line[1:].strip()
        if not pattern:
            continue
        is_regex = len(pattern) > 1 and pattern.startswith("/") and pattern.endswith("/")
        rules.append({"rule": line[0],
                      "pattern": pattern[1:-1] if is_regex else pattern,
                      "regex": is_regex})
    return rules


def _matches(rule: dict, config_text: str) -> bool:
    if rule["regex"]:
        try:
            return re.search(rule["pattern"], config_text, re.MULTILINE) is not None
        except re.error:
            # A malformed regex is the operator's typo, not a deviation: treat
            # it as unmatched rather than crashing the whole report.
            return False
    return rule["pattern"] in config_text


def evaluate(vendor: str, config_text: str, baseline_text: str) -> list:
    """Return only the deviations: required lines missing, forbidden present."""
    body = normalize.normalize(vendor, config_text)
    problems = []
    for rule in parse(baseline_text):
        found = _matches(rule, body)
        if rule["rule"] == "+" and not found:
            problems.append({"rule": "+", "pattern": rule["pattern"], "problem": "missing"})
        elif rule["rule"] == "-" and found:
            problems.append({"rule": "-", "pattern": rule["pattern"], "problem": "present"})
    return problems


def _load_all() -> dict:
    try:
        with open(_store_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def load(tenant: str) -> str:
    return _load_all().get(tenant, "")


def save(tenant: str, text: str) -> None:
    store = _load_all()
    store[tenant] = text or ""
    with open(_store_path(), "w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=1)


# Lines worth proposing as a baseline: the security-relevant surface, not the
# device's own identity. Hostname, addresses and VLANs differ per device by
# design, and a baseline containing them would fail on the second switch.
_SEED_PREFIXES = (
    "service password-encryption", "ip dhcp snooping", "login block-for",
    "aaa new-model", "aaa authentication", "aaa authorization",
    "spanning-tree portfast bpduguard", "no ip http", "ip ssh",
    "snmp-server group", "logging host", "ntp server",
    "set strong-crypto", "set admin-lockout", "config system snmp",
)


def seed_from_config(vendor: str, config_text: str) -> str:
    """Candidate '+' rules from one device's config, for the operator to prune."""
    from security import redaction
    body = normalize.normalize(vendor, config_text)
    seen, out = set(), []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith(_SEED_PREFIXES):
            continue
        safe = redaction.redact(stripped)
        if safe not in seen:
            seen.add(safe)
            out.append(f"+ {safe}")
    return "\n".join(out) + "\n" if out else ""
