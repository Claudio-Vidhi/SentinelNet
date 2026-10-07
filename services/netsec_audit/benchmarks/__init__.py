# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Registry of the benchmarks: one module per benchmark.

Adding a benchmark means adding a module here with four names and listing it
in ``_MODULES``; the scan engine, the ``/api/netsec-audit/benchmarks``
endpoint and the benchmark picker in the UI all read from this registry.

  ``KEY``    identifier sent by the UI and stored in the audit history.
  ``TITLE``  name shown in the UI and in the report.
  ``GROUP``  ``"cis"`` for a per-product CIS benchmark (one platform),
             ``"framework"`` for a cross-platform standard (NIST, PCI).
  ``RULES``  the rule entries, described below.

Rules shared between benchmarks (e.g. the TLS version counts for CIS and for
NIST SC-13) point to the SAME check function: only the citation, the title and
the remediation text change. No logic is duplicated.

CIS versions its benchmarks per product, there is no global "CIS Benchmark
v4.0", hence one module per product:

  - ``cis_fortigate``: CIS Fortinet FortiGate Benchmark v1.0.1 (``fortios``)
  - ``cis_ios``: CIS Cisco IOS XE 17.x Benchmark v2.2.1 (``ios``)
  - ``cis_ubuntu``: CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0 (``linux``)

Fields of each rule entry:

  ``vendor``      platform the rule applies to: ``fortios``, ``ios`` or
                  ``linux``. The engine drops rules of a vendor other than the
                  one recognised in the configuration, instead of evaluating
                  them and producing a meaningless UNKNOWN.
  ``ref``         recommendation number in the source benchmark, empty when
                  the rule has none (NIST/PCI put their own code in the title).
  ``level``       CIS profile: 1 = applicable everywhere, 2 = high-security
                  environments, with possible functional impact.
  ``automated``   the benchmark marks it as automatically verifiable.
                  ``False`` means the document wants it checked by hand: a
                  check exists here anyway, but on what the configuration
                  declares, not on the real behaviour.
  ``audit``       the benchmark's CLI command to verify by hand on the device.
  ``remediation`` CLI command to remediate.

LANGUAGE: ``title`` and the few prose ``remediation`` values are
``{"it": ..., "en": ...}`` dicts; CLI commands stay strings, they are not
translated. The "why" and "impact" of each check live in ``guidance.py``,
keyed by check function name: the reason for a setting does not change with
the standard that cites it.
"""

from typing import Any, Dict, List, Optional

from . import cis_fortigate, cis_ios, cis_ubuntu, nist, pci
from .vendors import FORTIOS, IOS, LINUX

_MODULES = (cis_fortigate, cis_ios, cis_ubuntu, nist, pci)

BENCHMARKS: Dict[str, List[Dict[str, Any]]] = {m.KEY: m.RULES for m in _MODULES}
BENCHMARK_TITLES: Dict[str, str] = {m.KEY: m.TITLE for m in _MODULES}
BENCHMARK_GROUPS: Dict[str, str] = {m.KEY: m.GROUP for m in _MODULES}

# The per-product CIS benchmark of each platform: what "cis" (automatic)
# resolves to, and what the engine suggests when the chosen benchmark has no
# rule for the platform found in the configuration.
CIS_BY_VENDOR: Dict[str, str] = {
    rules[0]["vendor"]: key
    for key, rules in BENCHMARKS.items()
    if BENCHMARK_GROUPS[key] == "cis" and rules
}


def vendors_of(key: str) -> List[str]:
    """Platforms a benchmark has rules for, in a stable order."""
    return sorted({r["vendor"] for r in BENCHMARKS.get(key, [])})


def cis_for(vendor: Optional[str]) -> str:
    """CIS benchmark for a platform; FortiOS when the platform is unknown,
    the engine's historical platform (see ``run_netsec_audit``)."""
    return CIS_BY_VENDOR.get(vendor or FORTIOS, CIS_BY_VENDOR[FORTIOS])


__all__ = ["BENCHMARKS", "BENCHMARK_TITLES", "BENCHMARK_GROUPS", "CIS_BY_VENDOR",
           "FORTIOS", "IOS", "LINUX", "cis_for", "vendors_of"]
