# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Benchmark rules on a multi-VDOM FortiOS backup.

The rules read top-level sections (``("firewall policy", "1")``). In a
multi-VDOM backup those live under ``("vdom", <vd>, ...)`` and the shared
ones under ``("global", ...)``, so every rule saw nothing. Stripping the
prefix over the whole file would merge policy 1 of every VDOM into one entry;
instead each VDOM becomes its own ParsedConfig (global + that VDOM), every
rule runs per VDOM, and the outcomes fold into one per rule.
"""

from typing import Callable, List, Tuple

from .model import FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome
from .parser import ParsedConfig

# Worst first. UNKNOWN is last: a verdict in any VDOM beats "could not tell",
# and only a rule no VDOM could assess stays UNKNOWN.
_RANK = {FAIL: 0, WARN: 1, PASS: 2, UNKNOWN: 3}


def split_vdoms(cfg: ParsedConfig) -> List[Tuple[str, ParsedConfig]]:
    """One (name, ParsedConfig) per VDOM with content, or [] for a
    single-VDOM file. Each scope = ``config global`` + that VDOM, prefixes
    stripped; records keep their file line and raw text, so evidence still
    points at the real line."""
    # File order; a VDOM with no ``set`` at all has nothing to assess.
    names = list(dict.fromkeys(r.path[1] for r in cfg.records
                               if len(r.path) >= 3 and r.path[0] == "vdom"))
    scopes = []
    for vd in names:
        def strip(path: Tuple[str, ...]):
            if path[:1] == ("global",):
                return path[1:]
            if path[:2] == ("vdom", vd):
                return path[2:]
            return None
        records = [r._replace(path=p) for r in cfg.records
                   if (p := strip(r.path)) is not None]
        sections = {p for s in cfg.sections if (p := strip(s))}
        scopes.append((vd, ParsedConfig(records, sections, cfg.header)))
    return scopes


def _key(e: Evidence) -> tuple:
    # params is a dict: not hashable as is.
    return (e.line, e.text, e.context, e.message, repr(sorted((e.params or {}).items())))


def evaluate(check: Callable[[ParsedConfig], RuleOutcome],
             scopes: List[Tuple[str, ParsedConfig]]
             ) -> Tuple[RuleOutcome, List[Tuple[str, RuleOutcome]]]:
    """One outcome for ``check`` over every VDOM, plus the per-VDOM outcomes
    that carry the verdict (for the detail text).

    Worst status wins (``_RANK``); message and params are those of the first
    VDOM with it. Evidence comes from the VDOMs at that status (with FAIL,
    the WARN ones too). Evidence identical in every scope is the same global
    line or the same absence everywhere: kept once, unprefixed. The rest is
    prefixed with its VDOM in ``context``."""
    per = [(vd, check(scope)) for vd, scope in scopes]
    status = min((o.status for _vd, o in per), key=lambda s: _RANK.get(s, 9))
    keep = {FAIL, WARN} if status in (FAIL, WARN) else {status}
    carriers = [(vd, o) for vd, o in per if o.status in keep]
    shared = set.intersection(*({_key(e) for e in o.evidence} for _vd, o in per))
    evidence: List[Evidence] = []
    seen: set = set()
    for vd, o in carriers:
        for e in o.evidence:
            if _key(e) in shared:
                if _key(e) not in seen:
                    seen.add(_key(e))
                    evidence.append(e)
                continue
            ctx = " / ".join(p for p in (f"vdom {vd}", e.context) if p)
            evidence.append(e._replace(context=ctx))
    first = next(o for _vd, o in per if o.status == status)
    verdict = [(vd, o) for vd, o in per if o.status == status]
    return RuleOutcome(status, first.message, evidence, first.params), verdict


def same_detail(verdict: List[Tuple[str, RuleOutcome]]) -> bool:
    """True when every VDOM reached the verdict with the same message on the
    same evidence (a global setting). "1 policy" in two VDOMs is two
    different policies and must read as two details."""
    return len({(o.message, repr(sorted((o.params or {}).items())),
                 frozenset(_key(e) for e in o.evidence))
                for _vd, o in verdict}) <= 1
