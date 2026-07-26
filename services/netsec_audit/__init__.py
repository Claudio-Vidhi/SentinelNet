# -*- coding: utf-8 -*-
"""services/netsec_audit — motore di compliance di rete.

Valuta una configurazione FortiOS contro benchmark reali:
  - CIS Fortinet FortiGate Benchmark
  - NIST SP 800-53 Rev. 5 (SC-7, AC-17, SC-13, AU-2/AU-12)
  - PCI-DSS v4.0 (requisiti 1.2, 1.3, 2.2, 10.2)

Ogni verdetto nasce da una valutazione sulla configurazione PARSATA e, quando
non e' PASS, cita la riga esatta che lo motiva.
"""

from typing import Any, Dict, List, Optional

from .benchmarks import BENCHMARKS
from .model import score_rules
from .parser import parse_with_lines

__all__ = ["run_netsec_audit", "BENCHMARKS"]

_DEFAULT_BENCHMARK = "cis"


def run_netsec_audit(config_text: Optional[str] = None,
                     device_name: Optional[str] = None,
                     benchmark: str = _DEFAULT_BENCHMARK) -> Dict[str, Any]:
    """Valuta ``config_text`` contro il benchmark richiesto."""
    key = (benchmark or _DEFAULT_BENCHMARK).lower().strip()
    if key not in BENCHMARKS:
        key = _DEFAULT_BENCHMARK

    cfg = parse_with_lines(config_text)
    device = device_name or "Dispositivo analizzato"

    evaluated: List[Dict[str, Any]] = []
    for tmpl in BENCHMARKS[key]:
        outcome = tmpl["check"](cfg)
        evaluated.append({
            "id": tmpl["id"],
            "title": tmpl["title"],
            "severity": tmpl["severity"],
            "category": tmpl["category"],
            "status": outcome.status,
            "device": device,
            "detail": outcome.detail,
            "remediation": tmpl["remediation"],
            "evidence": [
                {"line": e.line, "text": e.text, "context": e.context}
                for e in outcome.evidence
            ],
        })

    score, summary = score_rules(evaluated)
    return {
        "benchmark": key,
        "score": score,
        "summary": summary,
        "rules": evaluated,
    }
