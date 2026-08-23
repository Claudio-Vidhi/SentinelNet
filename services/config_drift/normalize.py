# -*- coding: utf-8 -*-
"""Strip the parts of a config that change on their own.

A device rewrites byte counts, timestamps and clock drift without anyone
configuring anything. Hashing the raw text would archive a new version on
every collection run, so drift detection compares configs with those lines
removed.

This applies to the HASH and the DIFF only. The archived file is always the
config exactly as collected — a stripped archive could not be read back or
restored from.
"""
import re

# Lines that change by themselves, whatever the vendor is.
_COMMON = (
    re.compile(r"^\s*Building configuration\.\.\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*$"),
)

_IOS = (
    re.compile(r"^\s*Current configuration\s*:\s*\d+\s*bytes\s*$", re.IGNORECASE),
    re.compile(r"^\s*!\s*Last configuration change .*$", re.IGNORECASE),
    re.compile(r"^\s*!\s*NVRAM config last updated .*$", re.IGNORECASE),
    re.compile(r"^\s*ntp clock-period\s+\d+\s*$", re.IGNORECASE),
    re.compile(r"^\s*!\s*Time:\s.*$", re.IGNORECASE),
)

_FORTIOS = (
    re.compile(r"^\s*#config-version=.*$", re.IGNORECASE),
    re.compile(r"^\s*#conf_file_ver=.*$", re.IGNORECASE),
    re.compile(r"^\s*#buildno=.*$", re.IGNORECASE),
    re.compile(r"^\s*#global_vdom=.*$", re.IGNORECASE),
)

# Vendor strings as they appear in the inventory's Vendor column (the
# canonical values in services.inventory_manager.VENDOR_ALIASES / get_all_vendors,
# not the raw CSV spellings the alias table maps away from cisco_ios/fortigate
# never reach here, so there is no alias to keep for them).
_BY_VENDOR = {
    "cisco": _IOS,
    "cisco_9800": _IOS,
    "cisco_cbs": _IOS,
    "cisco_wlc": _IOS,
    "fortinet": _FORTIOS,
}


def normalize(vendor: str, text: str) -> str:
    """Return ``text`` without the lines that change on their own.

    An unknown vendor gets the vendor-neutral rules only: noisier drift is an
    acceptable answer, a crash or a skipped device is not.
    """
    patterns = _COMMON + _BY_VENDOR.get((vendor or "").strip().lower(), ())
    kept = [line.rstrip()
            for line in (text or "").splitlines()
            if not any(p.match(line) for p in patterns)]
    return "\n".join(kept) + "\n" if kept else ""
