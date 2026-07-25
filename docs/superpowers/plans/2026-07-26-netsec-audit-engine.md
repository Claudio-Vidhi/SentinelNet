# NetSec Audit Real Check Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the NetSec Audit engine's substring-matching heuristics with real evaluations over a line-tracked FortiOS config parse, so every verdict is defensible and points at the exact offending line.

**Architecture:** `services/netsec_audit.py` becomes a package. A parser turns config text into flat `ConfigRecord` tuples carrying block path and line number. Each rule is a pure function `ParsedConfig -> RuleOutcome`. Benchmark definitions (CIS / NIST / PCI) are metadata that bind rule functions to citations, so rules shared between benchmarks have one implementation. A fourth status `UNKNOWN` covers "config absent, not assessable" and is excluded from scoring.

**Tech Stack:** Python 3 stdlib only, FastAPI, `unittest`. Frontend is vanilla JS. No new dependencies.

## Global Constraints

- Python is only available as `uv run python`. Bare `python` is NOT on PATH.
- Run `uv run pyrefly check` before every commit. Must report `0 errors`.
- Run `uv run python -m unittest discover -s tests -p "test_*.py"` before every commit. Currently 516 tests, all passing. Never commit with failures.
- There is NO CI. All verification is local.
- Node.js is NOT installed. To syntax-check JS use:
  `uv run --with tree-sitter --with tree-sitter-javascript python -c "..."` and assert no `ERROR` / missing nodes. `esprima` in the venv CANNOT parse this codebase (optional chaining) — do not use it.
- UI strings are Italian, matching surrounding tone. User-facing JS strings follow the existing `currentLang === 'en' ? '...' : '...'` pattern.
- All interpolated values in JS templates must be wrapped in `escapeHtml()`.
- Do NOT modify `_forti_tree` or `_forti_tokens` in `fw_analyzers/fortios.py` — `config_analyzer` depends on their exact shape. Import `_forti_tokens`; do not change it.
- Do NOT delete or move `checklist_x_c.docx` at the repo root. Do not modify `.gitignore`.
- POST requests in tests require the anti-CSRF header: `CSRF = {"X-Requested-With": "SentinelNet"}`.
- Rebuild the exe as the final step of the whole plan: `uv run pyinstaller SentinelNet.spec --noconfirm`.

## File Structure

`services/netsec_audit.py` (260 lines) is replaced by a package. The current file mixes benchmark metadata, evaluation logic, and result assembly; the rewrite roughly triples the logic, so the three responsibilities are separated.

| File | Responsibility |
|---|---|
| `services/netsec_audit/__init__.py` | Public API. Exports `run_netsec_audit`. Preserves `from services import netsec_audit; netsec_audit.run_netsec_audit(...)` used by `routers/analyzer.py` and `tests/test_netsec_audit_scan.py`. |
| `services/netsec_audit/parser.py` | `ConfigRecord`, `ParsedConfig`, `parse_with_lines`, and accessors (`section_entries`, `section_present`, `setting`). |
| `services/netsec_audit/model.py` | `Evidence`, `RuleOutcome`, status constants, `score_rules`. |
| `services/netsec_audit/rules.py` | The rule functions. Pure: `ParsedConfig -> RuleOutcome`. |
| `services/netsec_audit/benchmarks.py` | Benchmark → rule metadata (id, title, severity, category, remediation, check function). |
| `tests/fixtures/fortigate_violations.conf` | Config with a known violation per rule. |
| `tests/fixtures/fortigate_clean.conf` | Config that passes every rule. |
| `tests/fixtures/fortigate_partial.conf` | Config exercising `UNKNOWN`. |
| `tests/test_netsec_audit_parser.py` | Parser unit tests. |
| `tests/test_netsec_audit_rules.py` | Per-rule status + evidence line assertions. |
| `tests/test_netsec_audit_scan.py` | EXISTS — endpoint tests. Extended, not replaced. |

---

### Task 1: Parser with line tracking

**Files:**
- Create: `services/netsec_audit/__init__.py`
- Create: `services/netsec_audit/parser.py`
- Delete: `services/netsec_audit.py` (converted to package — see Step 1)
- Test: `tests/test_netsec_audit_parser.py`

**Interfaces:**
- Consumes: `_forti_tokens` from `fw_analyzers.fortios`.
- Produces:
  - `ConfigRecord(path: Tuple[str, ...], key: str, values: List[str], line: int, raw: str)` — NamedTuple
  - `ParsedConfig(records: List[ConfigRecord], sections: Set[Tuple[str, ...]])` — NamedTuple
  - `parse_with_lines(text: Optional[str]) -> ParsedConfig`
  - `section_entries(cfg: ParsedConfig, section: str) -> Dict[str, List[ConfigRecord]]`
  - `section_present(cfg: ParsedConfig, section: str) -> bool`
  - `setting(cfg: ParsedConfig, section: str, key: str) -> Optional[ConfigRecord]`

- [ ] **Step 1: Convert the module to a package**

The existing `services/netsec_audit.py` must become `services/netsec_audit/`. Do this with git so history follows:

```bash
cd c:/Users/vidhi/dev_ved/SentinelNet
mkdir -p services/netsec_audit
git mv services/netsec_audit.py services/netsec_audit/__init__.py
```

Leave `__init__.py` contents alone for now — it still holds the old engine and keeps the app working until Task 6 replaces it.

- [ ] **Step 2: Write the failing parser test**

Create `tests/test_netsec_audit_parser.py`:

```python
# -*- coding: utf-8 -*-
"""Test del parser FortiOS con tracciamento di riga usato dal motore di audit."""

import unittest

from services.netsec_audit.parser import (
    parse_with_lines, section_entries, section_present, setting)

SAMPLE = """\
#config-version=FGT
config system global
    set admintimeout 5
    set strong-crypto enable
end
config system interface
    edit "port1"
        set allowaccess ping https telnet
    next
    edit "port2"
        set allowaccess ping https
    next
end
config system snmp community
end
"""


class TestParser(unittest.TestCase):
    def test_records_carry_path_key_values_and_line(self):
        cfg = parse_with_lines(SAMPLE)
        rec = setting(cfg, "system global", "admintimeout")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.path, ("system global",))
        self.assertEqual(rec.key, "admintimeout")
        self.assertEqual(rec.values, ["5"])
        self.assertEqual(rec.line, 3)
        self.assertIn("admintimeout 5", rec.raw)

    def test_edit_blocks_are_grouped_by_key(self):
        cfg = parse_with_lines(SAMPLE)
        ifaces = section_entries(cfg, "system interface")
        self.assertEqual(set(ifaces), {"port1", "port2"})
        port1 = [r for r in ifaces["port1"] if r.key == "allowaccess"][0]
        self.assertEqual(port1.values, ["ping", "https", "telnet"])
        self.assertEqual(port1.line, 7)

    def test_empty_section_is_still_reported_present(self):
        """Un blocco senza 'set' non produce record ma esiste: serve a
        distinguere 'assente' (UNKNOWN) da 'presente e conforme' (PASS)."""
        cfg = parse_with_lines(SAMPLE)
        self.assertTrue(section_present(cfg, "system snmp community"))
        self.assertEqual(section_entries(cfg, "system snmp community"), {})
        self.assertFalse(section_present(cfg, "log syslogd setting"))

    def test_comments_and_blank_lines_ignored(self):
        cfg = parse_with_lines(SAMPLE)
        self.assertTrue(all(not r.raw.strip().startswith("#") for r in cfg.records))

    def test_quoted_values_are_unquoted(self):
        cfg = parse_with_lines(
            'config firewall policy\n'
            '    edit 1\n'
            '        set srcaddr "all"\n'
            '    next\n'
            'end\n')
        pol = section_entries(cfg, "firewall policy")["1"]
        self.assertEqual([r for r in pol if r.key == "srcaddr"][0].values, ["all"])

    def test_none_and_empty_input_are_safe(self):
        for bad in (None, "", "   \n\n"):
            cfg = parse_with_lines(bad)
            self.assertEqual(cfg.records, [])
            self.assertEqual(cfg.sections, set())

    def test_unclosed_blocks_do_not_raise(self):
        cfg = parse_with_lines(
            'config system global\n    set admintimeout 5\n')
        self.assertIsNotNone(setting(cfg, "system global", "admintimeout"))

    def test_stray_end_does_not_raise(self):
        cfg = parse_with_lines('end\nend\nconfig system global\n set a b\nend\n')
        self.assertIsNotNone(setting(cfg, "system global", "a"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run python -m unittest tests.test_netsec_audit_parser -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'services.netsec_audit.parser'`

- [ ] **Step 4: Implement the parser**

Create `services/netsec_audit/parser.py`:

```python
# -*- coding: utf-8 -*-
"""Parser FortiOS con tracciamento di riga per il motore di audit.

Riusa la tokenizzazione di ``fw_analyzers.fortios`` (che gestisce le stringhe
tra apici) ma produce record PIATTI con numero di riga, invece dell'albero di
``_forti_tree``: le regole hanno bisogno sia del contesto strutturale (il path
del blocco) sia dell'evidenza (la riga esatta da citare nel report).

Tollerante quanto ``_forti_tree``: blocchi non chiusi, annidamenti anomali e
righe malformate vengono saltati, mai sollevati.
"""

from typing import Dict, List, NamedTuple, Optional, Set, Tuple

from fw_analyzers.fortios import _forti_tokens


class ConfigRecord(NamedTuple):
    """Una direttiva ``set`` con il suo contesto e la sua posizione."""
    path: Tuple[str, ...]   # es. ("system interface", "port1")
    key: str                # es. "allowaccess" (sempre minuscolo)
    values: List[str]       # es. ["ping", "https", "telnet"]
    line: int               # 1-based, per l'evidenza nel report
    raw: str                # riga originale, senza newline finale


class ParsedConfig(NamedTuple):
    records: List[ConfigRecord]
    # Ogni path di blocco incontrato, anche se privo di 'set'. Serve a
    # distinguere "sezione assente" (UNKNOWN) da "sezione presente e vuota".
    sections: Set[Tuple[str, ...]]


def parse_with_lines(text: Optional[str]) -> ParsedConfig:
    records: List[ConfigRecord] = []
    sections: Set[Tuple[str, ...]] = set()
    stack: List[str] = []
    for lineno, raw in enumerate((text or "").splitlines(), start=1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        low = s.lower()
        try:
            if low.startswith("config "):
                stack.append(s[7:].strip().strip('"'))
                sections.add(tuple(stack))
            elif low.startswith("edit "):
                stack.append(s[5:].strip().strip('"'))
                sections.add(tuple(stack))
            elif low in ("next", "end"):
                if stack:
                    stack.pop()
            elif low.startswith("set "):
                toks = _forti_tokens(s)
                if len(toks) >= 2:
                    records.append(ConfigRecord(
                        path=tuple(stack),
                        key=toks[1].lower(),
                        values=list(toks[2:]),
                        line=lineno,
                        raw=raw.rstrip("\r\n"),
                    ))
        except Exception:
            continue
    return ParsedConfig(records=records, sections=sections)


def _parts(section: str) -> Tuple[str, ...]:
    return (section,)


def section_present(cfg: ParsedConfig, section: str) -> bool:
    """True se il blocco ``config <section>`` compare, anche se vuoto."""
    return _parts(section) in cfg.sections


def section_entries(cfg: ParsedConfig,
                    section: str) -> Dict[str, List[ConfigRecord]]:
    """Record di ``config <section>`` raggruppati per chiave di ``edit``.

    Un blocco senza voci ``edit`` restituisce un dizionario vuoto: usare
    ``section_present`` per distinguerlo da una sezione assente.
    """
    base = _parts(section)
    out: Dict[str, List[ConfigRecord]] = {}
    for entry in cfg.sections:
        if len(entry) == len(base) + 1 and entry[:len(base)] == base:
            out.setdefault(entry[len(base)], [])
    for r in cfg.records:
        if len(r.path) >= len(base) + 1 and r.path[:len(base)] == base:
            out.setdefault(r.path[len(base)], []).append(r)
    return out


def setting(cfg: ParsedConfig, section: str,
            key: str) -> Optional[ConfigRecord]:
    """Primo record ``set <key>`` direttamente sotto ``config <section>``."""
    base = _parts(section)
    key = key.lower()
    for r in cfg.records:
        if r.path == base and r.key == key:
            return r
    return None
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run python -m unittest tests.test_netsec_audit_parser -v`
Expected: PASS, 8 tests.

- [ ] **Step 6: Verify nothing else broke**

Run: `uv run pyrefly check` — expect `0 errors`.
Run: `uv run python -m unittest discover -s tests -p "test_*.py" 2>&1 | grep -E "^(Ran|OK|FAILED)"` — expect `OK`, 524 tests.

- [ ] **Step 7: Commit**

```bash
git add services/netsec_audit/ tests/test_netsec_audit_parser.py
git commit -m "feat(audit): line-tracked FortiOS parser for the audit engine

Converts services/netsec_audit.py into a package and adds a parser producing
flat ConfigRecord tuples with block path and line number, so a finding can cite
the exact offending directive. Reuses _forti_tokens from fw_analyzers.fortios
without altering it, since config_analyzer depends on its shape.

ParsedConfig tracks every block path seen, including empty ones, so a rule can
tell 'section absent' from 'section present and compliant'."
```

---

### Task 2: Status model, evidence, and scoring

**Files:**
- Create: `services/netsec_audit/model.py`
- Test: `tests/test_netsec_audit_rules.py` (created here, extended in Tasks 3-5)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - Constants `PASS = "PASS"`, `FAIL = "FAIL"`, `WARN = "WARN"`, `UNKNOWN = "UNKNOWN"`
  - `Evidence(line: int, text: str, context: str)` — NamedTuple
  - `RuleOutcome(status: str, detail: str, evidence: List[Evidence])` — NamedTuple, `evidence` defaults to `()`
  - `score_rules(rules: List[dict]) -> Tuple[Optional[int], dict]` returning `(score_or_None, summary_dict)` where summary has keys `total, passed, failed, warned, unknown`

- [ ] **Step 1: Write the failing test**

Create `tests/test_netsec_audit_rules.py`:

```python
# -*- coding: utf-8 -*-
"""Test del modello di stato e delle singole regole del motore di audit."""

import unittest

from services.netsec_audit.model import (
    FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome, score_rules)


class TestScoring(unittest.TestCase):
    def _rules(self, *statuses):
        return [{"status": s} for s in statuses]

    def test_unknown_is_excluded_from_the_denominator(self):
        """Una sezione assente non deve ne' gonfiare ne' deprimere il punteggio."""
        score, summary = score_rules(self._rules(PASS, PASS, FAIL, UNKNOWN))
        self.assertEqual(score, 67)          # 2 su 3, non 2 su 4
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["total"], 4)

    def test_all_unknown_yields_no_score(self):
        score, summary = score_rules(self._rules(UNKNOWN, UNKNOWN))
        self.assertIsNone(score)
        self.assertEqual(summary["unknown"], 2)

    def test_warn_counts_against_the_score(self):
        score, _ = score_rules(self._rules(PASS, WARN))
        self.assertEqual(score, 50)

    def test_empty_rule_list(self):
        score, summary = score_rules([])
        self.assertIsNone(score)
        self.assertEqual(summary["total"], 0)


class TestRuleOutcome(unittest.TestCase):
    def test_evidence_defaults_to_empty(self):
        o = RuleOutcome(PASS, "tutto a posto")
        self.assertEqual(list(o.evidence), [])

    def test_evidence_carries_line_and_context(self):
        e = Evidence(42, "set allowaccess telnet", "system interface / port1")
        o = RuleOutcome(FAIL, "telnet abilitato", [e])
        self.assertEqual(o.evidence[0].line, 42)
        self.assertEqual(o.evidence[0].context, "system interface / port1")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run python -m unittest tests.test_netsec_audit_rules -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'services.netsec_audit.model'`

- [ ] **Step 3: Implement the model**

Create `services/netsec_audit/model.py`:

```python
# -*- coding: utf-8 -*-
"""Stati, evidenze e calcolo del punteggio del motore di audit."""

from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
UNKNOWN = "UNKNOWN"


class Evidence(NamedTuple):
    """Riga di configurazione che motiva un esito diverso da PASS."""
    line: int      # 1-based; 0 quando l'evidenza e' un'ASSENZA
    text: str      # direttiva incriminata, o descrizione dell'assenza
    context: str   # path del blocco, es. "system interface / port1"


class RuleOutcome(NamedTuple):
    status: str
    detail: str
    evidence: Sequence[Evidence] = ()


def score_rules(rules: List[Dict[str, Any]]) -> Tuple[Optional[int],
                                                      Dict[str, int]]:
    """Punteggio e riepilogo.

    UNKNOWN e' ESCLUSO dal denominatore: una sezione assente non e' ne' una
    conformita' ne' una violazione, e contarla falserebbe il punteggio in un
    verso o nell'altro. Se ogni regola e' UNKNOWN il punteggio non e'
    determinabile e vale ``None`` (la UI mostra un trattino, non 0 o 100).
    """
    summary = {
        "total": len(rules),
        "passed": sum(1 for r in rules if r.get("status") == PASS),
        "failed": sum(1 for r in rules if r.get("status") == FAIL),
        "warned": sum(1 for r in rules if r.get("status") == WARN),
        "unknown": sum(1 for r in rules if r.get("status") == UNKNOWN),
    }
    assessed = summary["passed"] + summary["failed"] + summary["warned"]
    score = round(summary["passed"] / assessed * 100) if assessed else None
    return score, summary
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run python -m unittest tests.test_netsec_audit_rules -v`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add services/netsec_audit/model.py tests/test_netsec_audit_rules.py
git commit -m "feat(audit): status model with UNKNOWN and evidence

Adds a fourth status for 'config absent, not assessable'. Previously a missing
config block scored as PASS, so a partial config inflated the grade. UNKNOWN is
excluded from the scoring denominator, and an all-UNKNOWN scan reports no score
rather than 0 or 100."
```

---

### Task 3: Hardening rules

**Files:**
- Create: `services/netsec_audit/rules.py`
- Create: `tests/fixtures/fortigate_violations.conf`
- Create: `tests/fixtures/fortigate_clean.conf`
- Create: `tests/fixtures/fortigate_partial.conf`
- Modify: `tests/test_netsec_audit_rules.py`

**Interfaces:**
- Consumes: `parse_with_lines`, `section_entries`, `section_present`, `setting` (Task 1); `PASS/FAIL/WARN/UNKNOWN`, `Evidence`, `RuleOutcome` (Task 2).
- Produces:
  - `check_management_protocols(cfg: ParsedConfig) -> RuleOutcome`
  - `check_tls_version(cfg) -> RuleOutcome`
  - `check_idle_timeout(cfg) -> RuleOutcome`
  - `check_strong_crypto(cfg) -> RuleOutcome`

- [ ] **Step 1: Create the three fixtures**

Create `tests/fixtures/fortigate_violations.conf` — one known violation per rule:

```
#config-version=FGT100F-7.4.1
config system global
    set admintimeout 0
    set ssl-min-proto-version TLSv1-1
    set strong-crypto disable
end
config system interface
    edit "port1"
        set role wan
        set allowaccess ping https telnet http
    next
    edit "port2"
        set role lan
        set allowaccess ping https ssh
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
    edit "mario.rossi"
        set trusthost1 0.0.0.0 0.0.0.0
    next
end
config system snmp community
    edit 1
        set name "public"
    next
end
config firewall service custom
    edit "GESTIONE-REMOTA"
        set tcp-portrange 3389
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
    edit 2
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "server-farm"
        set service "GESTIONE-REMOTA"
        set action accept
    next
end
```

Create `tests/fixtures/fortigate_clean.conf` — passes every rule:

```
#config-version=FGT100F-7.4.1
config system global
    set admintimeout 10
    set ssl-min-proto-version TLSv1-2
    set strong-crypto enable
end
config system interface
    edit "port1"
        set role wan
        set allowaccess ping
    next
    edit "port2"
        set role lan
        set allowaccess ping https ssh
    next
end
config system admin
    edit "mario.rossi"
        set trusthost1 10.0.1.0 255.255.255.0
    next
end
config system snmp community
    edit 1
        set name "sn-monitor-v3"
    next
end
config system password-policy
    set status enable
end
config firewall policy
    edit 1
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "lan-users"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
    next
end
config log syslogd setting
    set status enable
    set server "10.0.1.100"
    set port 5514
end
```

Create `tests/fixtures/fortigate_partial.conf` — only a global block, everything else absent:

```
#config-version=FGT100F-7.4.1
config system global
    set admintimeout 10
    set ssl-min-proto-version TLSv1-2
    set strong-crypto enable
end
```

- [ ] **Step 2: Write the failing tests**

Append to `tests/test_netsec_audit_rules.py` (add `import os` at the top, and these imports):

```python
import os

from services.netsec_audit import rules
from services.netsec_audit.parser import parse_with_lines

_FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(_FIX, name), encoding="utf-8") as fh:
        return parse_with_lines(fh.read())


class _RuleBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bad = _load("fortigate_violations.conf")
        cls.good = _load("fortigate_clean.conf")
        cls.partial = _load("fortigate_partial.conf")

    def assertEvidenceLine(self, outcome, needle):
        """L'evidenza deve citare una riga che contiene davvero la direttiva."""
        self.assertTrue(outcome.evidence, "nessuna evidenza allegata")
        joined = " | ".join(e.text for e in outcome.evidence)
        self.assertIn(needle, joined)
        for e in outcome.evidence:
            self.assertGreater(e.line, 0)


class TestHardeningRules(_RuleBase):
    def test_management_protocols_fails_on_telnet(self):
        o = rules.check_management_protocols(self.bad)
        self.assertEqual(o.status, FAIL)
        self.assertEvidenceLine(o, "telnet")
        self.assertIn("port1", " ".join(e.context for e in o.evidence))

    def test_management_protocols_passes_when_clean(self):
        self.assertEqual(
            rules.check_management_protocols(self.good).status, PASS)

    def test_management_protocols_unknown_without_interfaces(self):
        self.assertEqual(
            rules.check_management_protocols(self.partial).status, UNKNOWN)

    def test_tls_fails_on_deprecated_version(self):
        o = rules.check_tls_version(self.bad)
        self.assertEqual(o.status, FAIL)
        self.assertEvidenceLine(o, "TLSv1-1")

    def test_tls_passes_on_12(self):
        self.assertEqual(rules.check_tls_version(self.good).status, PASS)

    def test_tls_warns_when_unset_but_global_present(self):
        cfg = parse_with_lines("config system global\n set admintimeout 5\nend\n")
        self.assertEqual(rules.check_tls_version(cfg).status, WARN)

    def test_tls_unknown_without_global_block(self):
        self.assertEqual(rules.check_tls_version(parse_with_lines("")).status,
                         UNKNOWN)

    def test_idle_timeout_fails_on_zero(self):
        o = rules.check_idle_timeout(self.bad)
        self.assertEqual(o.status, FAIL)
        self.assertEvidenceLine(o, "admintimeout 0")

    def test_idle_timeout_fails_when_too_long(self):
        cfg = parse_with_lines(
            "config system global\n set admintimeout 480\nend\n")
        self.assertEqual(rules.check_idle_timeout(cfg).status, FAIL)

    def test_idle_timeout_passes_at_ten(self):
        self.assertEqual(rules.check_idle_timeout(self.good).status, PASS)

    def test_idle_timeout_unknown_without_global(self):
        self.assertEqual(
            rules.check_idle_timeout(parse_with_lines("")).status, UNKNOWN)

    def test_strong_crypto_warns_when_disabled(self):
        o = rules.check_strong_crypto(self.bad)
        self.assertEqual(o.status, WARN)
        self.assertEvidenceLine(o, "strong-crypto")

    def test_strong_crypto_passes_when_enabled(self):
        self.assertEqual(rules.check_strong_crypto(self.good).status, PASS)
```

- [ ] **Step 3: Run to verify it fails**

Run: `uv run python -m unittest tests.test_netsec_audit_rules -v`
Expected: FAIL — `ImportError: cannot import name 'rules'`

- [ ] **Step 4: Implement the hardening rules**

Create `services/netsec_audit/rules.py`:

```python
# -*- coding: utf-8 -*-
"""Valutazioni di audit su configurazione FortiOS parsata.

Ogni regola e' una funzione pura ``ParsedConfig -> RuleOutcome``. Le regole
NON inventano verdetti: quando il blocco necessario alla valutazione non
esiste restituiscono UNKNOWN, tranne dove l'assenza E' essa stessa la
violazione (assenza di logging remoto, admin senza trusthost) — in quei casi
il comportamento e' documentato sulla singola regola.
"""

from typing import List, Set

from .model import FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome
from .parser import ParsedConfig, section_entries, section_present, setting

# --- Hardening ---------------------------------------------------------------

_INSECURE_ACCESS = {"telnet", "http"}
_WEAK_TLS = {"sslv3", "tlsv1-0", "tlsv1-1", "tlsv1.0", "tlsv1.1"}
_MAX_ADMINTIMEOUT = 30


def _ctx(*parts: str) -> str:
    return " / ".join(p for p in parts if p)


def check_management_protocols(cfg: ParsedConfig) -> RuleOutcome:
    """Telnet/HTTP abilitati su un'interfaccia (allowaccess)."""
    ifaces = section_entries(cfg, "system interface")
    if not ifaces:
        return RuleOutcome(
            UNKNOWN,
            "Sezione 'config system interface' assente: impossibile valutare "
            "i protocolli di gestione.")
    ev: List[Evidence] = []
    for name in sorted(ifaces):
        for r in ifaces[name]:
            if r.key != "allowaccess":
                continue
            bad = sorted({v.lower() for v in r.values} & _INSECURE_ACCESS)
            if bad:
                ev.append(Evidence(r.line, r.raw.strip(),
                                   _ctx("system interface", name)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Protocolli di amministrazione non cifrati (Telnet/HTTP) abilitati "
            "su %d interfaccia/e." % len(ev),
            ev)
    return RuleOutcome(
        PASS, "Tutte le interfacce usano solo protocolli di gestione cifrati.")


def check_tls_version(cfg: ParsedConfig) -> RuleOutcome:
    """Versione minima SSL/TLS ammessa per l'accesso amministrativo."""
    rec = (setting(cfg, "system global", "ssl-min-proto-version")
           or setting(cfg, "system global", "admin-https-ssl-versions"))
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(
                UNKNOWN, "Sezione 'config system global' assente: impossibile "
                         "valutare la versione minima TLS.")
        return RuleOutcome(
            WARN,
            "Versione minima TLS non impostata esplicitamente: si applica il "
            "default della piattaforma, che varia con la versione di FortiOS.")
    weak = sorted({v.lower() for v in rec.values} & _WEAK_TLS)
    if weak:
        return RuleOutcome(
            FAIL,
            "Versione TLS deprecata ammessa: %s." % ", ".join(weak),
            [Evidence(rec.line, rec.raw.strip(), _ctx("system global"))])
    return RuleOutcome(PASS, "Versione minima SSL/TLS conforme (TLS 1.2+).")


def check_idle_timeout(cfg: ParsedConfig) -> RuleOutcome:
    """Timeout di inattivita' della sessione amministrativa."""
    rec = setting(cfg, "system global", "admintimeout")
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(
                UNKNOWN, "Sezione 'config system global' assente: impossibile "
                         "valutare il timeout amministrativo.")
        return RuleOutcome(
            WARN, "'admintimeout' non configurato: si applica il default "
                  "della piattaforma.")
    try:
        val = int(rec.values[0])
    except (IndexError, ValueError):
        return RuleOutcome(
            WARN, "Valore di 'admintimeout' non interpretabile.",
            [Evidence(rec.line, rec.raw.strip(), _ctx("system global"))])
    if val == 0:
        return RuleOutcome(
            FAIL, "Timeout amministrativo disabilitato (0): le sessioni non "
                  "scadono mai.",
            [Evidence(rec.line, rec.raw.strip(), _ctx("system global"))])
    if val > _MAX_ADMINTIMEOUT:
        return RuleOutcome(
            FAIL, "Timeout amministrativo troppo alto (%d minuti, massimo "
                  "consigliato %d)." % (val, _MAX_ADMINTIMEOUT),
            [Evidence(rec.line, rec.raw.strip(), _ctx("system global"))])
    return RuleOutcome(
        PASS, "Timeout di inattivita' amministrativa configurato a %d minuti."
              % val)


def check_strong_crypto(cfg: ParsedConfig) -> RuleOutcome:
    """'set strong-crypto enable' (cifrari deboli disabilitati)."""
    rec = setting(cfg, "system global", "strong-crypto")
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(
                UNKNOWN, "Sezione 'config system global' assente: impossibile "
                         "valutare 'strong-crypto'.")
        return RuleOutcome(
            WARN, "'strong-crypto' non impostato: cifrari deboli "
                  "potenzialmente ammessi.")
    if rec.values and rec.values[0].lower() == "enable":
        return RuleOutcome(PASS, "'strong-crypto' abilitato.")
    return RuleOutcome(
        WARN, "'strong-crypto' disabilitato: cifrari deboli ammessi.",
        [Evidence(rec.line, rec.raw.strip(), _ctx("system global"))])
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run python -m unittest tests.test_netsec_audit_rules -v`
Expected: PASS, 19 tests.

- [ ] **Step 6: Commit**

```bash
git add services/netsec_audit/rules.py tests/fixtures/ tests/test_netsec_audit_rules.py
git commit -m "feat(audit): real hardening rules with line-level evidence

Management protocols, TLS version, admin idle timeout and strong-crypto are now
evaluated against parsed config blocks instead of substring matches against the
whole file. Each non-PASS verdict cites the offending line and its block path.

Adds three fixtures: one violation per rule, one fully clean, one partial to
exercise UNKNOWN."
```

---

### Task 4: Access rule checks

**Files:**
- Modify: `services/netsec_audit/rules.py`
- Modify: `tests/test_netsec_audit_rules.py`

**Interfaces:**
- Consumes: everything from Task 3.
- Produces:
  - `check_any_any_policy(cfg) -> RuleOutcome`
  - `check_boundary_protection(cfg) -> RuleOutcome`
  - `check_inbound_admin_ports(cfg) -> RuleOutcome`
  - `wan_interfaces(cfg) -> Set[str]` (helper, used by two rules)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_netsec_audit_rules.py`:

```python
class TestAccessRules(_RuleBase):
    def test_any_any_policy_fails(self):
        o = rules.check_any_any_policy(self.bad)
        self.assertEqual(o.status, FAIL)
        self.assertIn("firewall policy / 1",
                      " ".join(e.context for e in o.evidence))

    def test_any_any_policy_passes_when_scoped(self):
        self.assertEqual(rules.check_any_any_policy(self.good).status, PASS)

    def test_any_any_policy_unknown_without_policies(self):
        self.assertEqual(
            rules.check_any_any_policy(self.partial).status, UNKNOWN)

    def test_wan_interfaces_resolved_by_role(self):
        self.assertEqual(rules.wan_interfaces(self.bad), {"port1"})

    def test_wan_interfaces_fallback_by_name(self):
        cfg = parse_with_lines(
            'config system interface\n'
            '    edit "wan1"\n'
            '        set allowaccess ping\n'
            '    next\n'
            'end\n')
        self.assertEqual(rules.wan_interfaces(cfg), {"wan1"})

    def test_boundary_protection_fails_on_wan_to_all(self):
        o = rules.check_boundary_protection(self.bad)
        self.assertEqual(o.status, FAIL)
        self.assertTrue(o.evidence)

    def test_boundary_protection_passes_when_egress_only(self):
        """La policy pulita esce DA lan VERSO wan: non e' un ingresso."""
        self.assertEqual(
            rules.check_boundary_protection(self.good).status, PASS)

    def test_inbound_admin_ports_detects_custom_service(self):
        """GESTIONE-REMOTA risolve a TCP 3389 via firewall service custom."""
        o = rules.check_inbound_admin_ports(self.bad)
        self.assertEqual(o.status, FAIL)
        self.assertIn("firewall policy / 2",
                      " ".join(e.context for e in o.evidence))

    def test_inbound_admin_ports_passes_when_absent(self):
        self.assertEqual(
            rules.check_inbound_admin_ports(self.good).status, PASS)

    def test_inbound_admin_ports_unknown_without_policies(self):
        self.assertEqual(
            rules.check_inbound_admin_ports(self.partial).status, UNKNOWN)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m unittest tests.test_netsec_audit_rules -v`
Expected: FAIL — `AttributeError: module 'services.netsec_audit.rules' has no attribute 'check_any_any_policy'`

- [ ] **Step 3: Implement the access rules**

Append to `services/netsec_audit/rules.py`:

```python
# --- Regole di accesso -------------------------------------------------------

_ANY_ADDR = {"all", "any"}
_ANY_SERVICE = {"all", "any"}
_ADMIN_PORTS = (22, 3389)
_BUILTIN_ADMIN_SERVICES = {"ssh", "rdp"}


def _policy_values(recs):
    """Mappa chiave -> valori minuscoli per una singola voce di policy."""
    out = {}
    for r in recs:
        out.setdefault(r.key, []).extend(v.lower() for v in r.values)
    return out


def _policy_line(recs, prefer="action"):
    for r in recs:
        if r.key == prefer:
            return r.line, r.raw.strip()
    return (recs[0].line, recs[0].raw.strip()) if recs else (0, "")


def wan_interfaces(cfg: ParsedConfig) -> Set[str]:
    """Interfacce con ruolo WAN.

    Preferisce 'set role wan'. Se nessuna interfaccia dichiara un ruolo
    (comune sulle configurazioni piu' vecchie) ricade sui nomi convenzionali.
    """
    ifaces = section_entries(cfg, "system interface")
    named = set()
    for name, recs in ifaces.items():
        for r in recs:
            if r.key == "role" and r.values and r.values[0].lower() == "wan":
                named.add(name)
    if named:
        return named
    return {n for n in ifaces
            if n.lower().startswith("wan") or n.lower() == "port1"}


def check_any_any_policy(cfg: ParsedConfig) -> RuleOutcome:
    """Policy che accetta qualunque sorgente verso qualunque destinazione."""
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config firewall policy' assente: impossibile "
                     "valutare le regole di accesso.")
    ev: List[Evidence] = []
    for pid in sorted(policies, key=lambda k: (len(k), k)):
        vals = _policy_values(policies[pid])
        if "accept" not in vals.get("action", []):
            continue
        if (set(vals.get("srcaddr", [])) & _ANY_ADDR
                and set(vals.get("dstaddr", [])) & _ANY_ADDR
                and set(vals.get("service", [])) & _ANY_SERVICE):
            line, raw = _policy_line(policies[pid])
            ev.append(Evidence(line, raw, _ctx("firewall policy", pid)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Trovate %d policy che accettano traffico any-to-any su qualunque "
            "servizio." % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessuna policy any-to-any: sorgente, destinazione e servizio "
              "sono sempre specificati.")


def check_boundary_protection(cfg: ParsedConfig) -> RuleOutcome:
    """Traffico in INGRESSO da un'interfaccia WAN verso qualunque destinazione."""
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config firewall policy' assente: impossibile "
                     "valutare la protezione del perimetro.")
    wan = wan_interfaces(cfg)
    if not wan:
        return RuleOutcome(
            UNKNOWN, "Nessuna interfaccia WAN identificabile: impossibile "
                     "valutare il confine di rete.")
    ev: List[Evidence] = []
    for pid in sorted(policies, key=lambda k: (len(k), k)):
        vals = _policy_values(policies[pid])
        if "accept" not in vals.get("action", []):
            continue
        srcintf = set(vals.get("srcintf", []))
        if not srcintf & {w.lower() for w in wan}:
            continue
        if set(vals.get("dstaddr", [])) & _ANY_ADDR:
            line, raw = _policy_line(policies[pid])
            ev.append(Evidence(line, raw, _ctx("firewall policy", pid)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Trovate %d policy in ingresso da WAN verso qualunque "
            "destinazione interna." % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessuna policy in ingresso da WAN verso destinazioni generiche.")


def _range_hits_admin_port(token: str) -> bool:
    """True se un token 'tcp-portrange' copre la 22 o la 3389."""
    token = token.split(":")[0]           # scarta la parte source-port
    for part in token.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = part.split("-", 1)
                lo_i, hi_i = int(lo), int(hi)
            else:
                lo_i = hi_i = int(part)
        except ValueError:
            continue
        if any(lo_i <= p <= hi_i for p in _ADMIN_PORTS):
            return True
    return False


def _admin_service_names(cfg: ParsedConfig) -> Set[str]:
    """Servizi che risolvono a TCP 22/3389, inclusi i custom."""
    names = set(_BUILTIN_ADMIN_SERVICES)
    for name, recs in section_entries(cfg, "firewall service custom").items():
        for r in recs:
            if r.key == "tcp-portrange" and any(
                    _range_hits_admin_port(v) for v in r.values):
                names.add(name.lower())
    return names


def check_inbound_admin_ports(cfg: ParsedConfig) -> RuleOutcome:
    """SSH/RDP esposti da WAN verso sorgenti generiche (PCI-DSS 1.2)."""
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config firewall policy' assente: impossibile "
                     "valutare l'esposizione delle porte amministrative.")
    wan = {w.lower() for w in wan_interfaces(cfg)}
    admin_services = _admin_service_names(cfg)
    ev: List[Evidence] = []
    for pid in sorted(policies, key=lambda k: (len(k), k)):
        vals = _policy_values(policies[pid])
        if "accept" not in vals.get("action", []):
            continue
        if not set(vals.get("srcintf", [])) & wan:
            continue
        if not set(vals.get("srcaddr", [])) & _ANY_ADDR:
            continue
        if set(vals.get("service", [])) & admin_services:
            line, raw = _policy_line(policies[pid], prefer="service")
            ev.append(Evidence(line, raw, _ctx("firewall policy", pid)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Porte amministrative (SSH 22 / RDP 3389) raggiungibili da "
            "Internet in %d policy." % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessuna esposizione diretta di SSH/RDP verso reti pubbliche.")
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m unittest tests.test_netsec_audit_rules -v`
Expected: PASS, 29 tests.

- [ ] **Step 5: Commit**

```bash
git add services/netsec_audit/rules.py tests/test_netsec_audit_rules.py
git commit -m "feat(audit): access rule checks over parsed policies

Any-to-any detection now requires action accept AND srcaddr all AND dstaddr all
AND service ALL on the same policy, instead of matching those words anywhere in
the file. Boundary protection resolves WAN interfaces from 'set role wan' with a
name-based fallback. Inbound admin port exposure resolves service names through
firewall service custom tcp-portrange, so a renamed RDP service is still caught."
```

---

### Task 5: Identity and logging checks

**Files:**
- Modify: `services/netsec_audit/rules.py`
- Modify: `tests/test_netsec_audit_rules.py`

**Interfaces:**
- Consumes: everything from Tasks 3-4.
- Produces:
  - `check_admin_trusthost(cfg) -> RuleOutcome`
  - `check_snmp_community(cfg) -> RuleOutcome`
  - `check_syslog(cfg) -> RuleOutcome`
  - `check_vendor_defaults(cfg) -> RuleOutcome`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_netsec_audit_rules.py`:

```python
class TestIdentityAndLoggingRules(_RuleBase):
    def test_trusthost_fails_for_admin_without_any(self):
        """L'account 'admin' non ha trusthost: assenza = violazione."""
        o = rules.check_admin_trusthost(self.bad)
        self.assertEqual(o.status, FAIL)
        ctxs = " ".join(e.context for e in o.evidence)
        self.assertIn("admin", ctxs)
        self.assertIn("mario.rossi", ctxs)   # trusthost 0.0.0.0 0.0.0.0

    def test_trusthost_passes_when_restricted(self):
        self.assertEqual(rules.check_admin_trusthost(self.good).status, PASS)

    def test_trusthost_unknown_without_admin_block(self):
        self.assertEqual(
            rules.check_admin_trusthost(self.partial).status, UNKNOWN)

    def test_snmp_fails_on_public_community(self):
        o = rules.check_snmp_community(self.bad)
        self.assertEqual(o.status, FAIL)
        self.assertEvidenceLine(o, "public")

    def test_snmp_passes_on_named_community(self):
        self.assertEqual(rules.check_snmp_community(self.good).status, PASS)

    def test_snmp_unknown_when_section_absent(self):
        self.assertEqual(
            rules.check_snmp_community(self.partial).status, UNKNOWN)

    def test_snmp_passes_when_section_present_but_empty(self):
        cfg = parse_with_lines("config system snmp community\nend\n")
        self.assertEqual(rules.check_snmp_community(cfg).status, PASS)

    def test_syslog_fails_when_section_absent(self):
        """Assenza di logging remoto E' la violazione, non UNKNOWN."""
        o = rules.check_syslog(self.partial)
        self.assertEqual(o.status, FAIL)

    def test_syslog_passes_when_enabled_with_server(self):
        self.assertEqual(rules.check_syslog(self.good).status, PASS)

    def test_syslog_fails_when_status_disabled(self):
        cfg = parse_with_lines(
            "config log syslogd setting\n set status disable\n"
            ' set server "10.0.1.100"\nend\n')
        self.assertEqual(rules.check_syslog(cfg).status, FAIL)

    def test_syslog_fails_without_server(self):
        cfg = parse_with_lines(
            "config log syslogd setting\n set status enable\nend\n")
        self.assertEqual(rules.check_syslog(cfg).status, FAIL)

    def test_vendor_defaults_flags_admin_account(self):
        o = rules.check_vendor_defaults(self.bad)
        self.assertEqual(o.status, FAIL)

    def test_vendor_defaults_passes_when_clean(self):
        self.assertEqual(rules.check_vendor_defaults(self.good).status, PASS)

    def test_vendor_defaults_unknown_when_nothing_to_inspect(self):
        self.assertEqual(
            rules.check_vendor_defaults(self.partial).status, UNKNOWN)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m unittest tests.test_netsec_audit_rules -v`
Expected: FAIL — `AttributeError: ... has no attribute 'check_admin_trusthost'`

- [ ] **Step 3: Implement the rules**

Append to `services/netsec_audit/rules.py`:

```python
# --- Identita' e logging -----------------------------------------------------

_DEFAULT_COMMUNITIES = {"public", "private"}
_UNRESTRICTED_TRUSTHOST = ({"0.0.0.0", "0.0.0.0"}, {"0.0.0.0/0"}, {"0.0.0.0"})


def check_admin_trusthost(cfg: ParsedConfig) -> RuleOutcome:
    """Account amministrativi raggiungibili da qualunque IP (NIST AC-17).

    ASSENZA COME VIOLAZIONE: un account senza alcun 'trusthost' e' raggiungibile
    da ovunque per default FortiOS, quindi vale FAIL e non UNKNOWN. E' invece
    UNKNOWN l'assenza dell'intero blocco 'config system admin'.
    """
    admins = section_entries(cfg, "system admin")
    if not admins:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config system admin' assente: impossibile "
                     "valutare le restrizioni di accesso amministrativo.")
    ev: List[Evidence] = []
    for name in sorted(admins):
        recs = admins[name]
        hosts = [r for r in recs if r.key.startswith("trusthost")]
        if not hosts:
            line = recs[0].line if recs else 0
            ev.append(Evidence(
                line, "nessun 'trusthost' definito per l'account",
                _ctx("system admin", name)))
            continue
        for r in hosts:
            vals = {v.lower() for v in r.values}
            if any(vals == unrestricted for unrestricted in _UNRESTRICTED_TRUSTHOST):
                ev.append(Evidence(r.line, r.raw.strip(),
                                   _ctx("system admin", name)))
    if ev:
        return RuleOutcome(
            FAIL,
            "%d account amministrativi accessibili da qualunque IP sorgente."
            % len(ev), ev)
    return RuleOutcome(
        PASS, "Tutti gli account amministrativi sono ristretti a sottoreti "
              "di gestione fidate.")


def check_snmp_community(cfg: ParsedConfig) -> RuleOutcome:
    """Community string SNMP v1/v2c di default."""
    if not section_present(cfg, "system snmp community"):
        return RuleOutcome(
            UNKNOWN, "Sezione 'config system snmp community' assente: "
                     "impossibile valutare le community SNMP.")
    ev: List[Evidence] = []
    for name in sorted(section_entries(cfg, "system snmp community")):
        for r in section_entries(cfg, "system snmp community")[name]:
            if (r.key == "name" and r.values
                    and r.values[0].lower() in _DEFAULT_COMMUNITIES):
                ev.append(Evidence(r.line, r.raw.strip(),
                                   _ctx("system snmp community", name)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Community SNMP di default in chiaro ('public'/'private'): %d."
            % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessuna community SNMP di default configurata.")


def check_syslog(cfg: ParsedConfig) -> RuleOutcome:
    """Inoltro dei log verso un syslog remoto (NIST AU-2/AU-12, PCI 10.2).

    ASSENZA COME VIOLAZIONE: se il blocco non esiste non c'e' alcun logging
    remoto configurato, che e' esattamente il controllo che fallisce.
    """
    if not section_present(cfg, "log syslogd setting"):
        return RuleOutcome(
            FAIL,
            "Nessun inoltro syslog remoto configurato: la sezione "
            "'config log syslogd setting' non esiste.",
            [Evidence(0, "blocco 'config log syslogd setting' assente",
                      "log syslogd setting")])
    status = setting(cfg, "log syslogd setting", "status")
    server = setting(cfg, "log syslogd setting", "server")
    ev: List[Evidence] = []
    if status is None or not status.values or status.values[0].lower() != "enable":
        ev.append(Evidence(
            status.line if status else 0,
            status.raw.strip() if status else "'status' non impostato a enable",
            _ctx("log syslogd setting")))
    if server is None or not server.values:
        ev.append(Evidence(
            server.line if server else 0,
            server.raw.strip() if server else "nessun 'server' syslog definito",
            _ctx("log syslogd setting")))
    if ev:
        return RuleOutcome(
            FAIL, "Inoltro syslog remoto non attivo o privo di destinazione.",
            ev)
    return RuleOutcome(
        PASS, "Inoltro dei log verso syslog remoto attivo e configurato.")


def check_vendor_defaults(cfg: ParsedConfig) -> RuleOutcome:
    """Account di default e policy password (PCI-DSS 2.2)."""
    admins = section_entries(cfg, "system admin")
    has_policy_block = section_present(cfg, "system password-policy")
    if not admins and not has_policy_block:
        return RuleOutcome(
            UNKNOWN, "Ne' 'config system admin' ne' "
                     "'config system password-policy' presenti: impossibile "
                     "valutare i default di fabbrica.")
    ev: List[Evidence] = []
    for name in sorted(admins):
        if name.lower() == "admin":
            recs = admins[name]
            ev.append(Evidence(
                recs[0].line if recs else 0,
                "account amministrativo di default 'admin' presente",
                _ctx("system admin", name)))
    if has_policy_block:
        status = setting(cfg, "system password-policy", "status")
        if status is None or not status.values or status.values[0].lower() != "enable":
            ev.append(Evidence(
                status.line if status else 0,
                status.raw.strip() if status
                else "'status' della password-policy non abilitato",
                _ctx("system password-policy")))
    else:
        ev.append(Evidence(
            0, "nessuna 'config system password-policy' definita",
            _ctx("system password-policy")))
    if ev:
        return RuleOutcome(
            FAIL,
            "Rilevati default di fabbrica o policy password non applicata "
            "(%d riscontri)." % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessun account di default e policy password attiva.")
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m unittest tests.test_netsec_audit_rules -v`
Expected: PASS, 43 tests.

- [ ] **Step 5: Commit**

```bash
git add services/netsec_audit/rules.py tests/test_netsec_audit_rules.py
git commit -m "feat(audit): identity and logging checks

Trusthost, SNMP communities, remote syslog and vendor defaults evaluated per
admin account and per community entry, with evidence naming the account or
entry.

Two rules treat absence as the finding rather than UNKNOWN, because absence is
the violation: an admin with no trusthost is unrestricted by FortiOS default,
and a missing log syslogd block means no remote logging exists at all."
```

---

### Task 6: Benchmark wiring and the public API

**Files:**
- Create: `services/netsec_audit/benchmarks.py`
- Rewrite: `services/netsec_audit/__init__.py`
- Modify: `tests/test_netsec_audit_scan.py`

**Interfaces:**
- Consumes: all rule functions (Tasks 3-5), `score_rules` (Task 2), `parse_with_lines` (Task 1).
- Produces:
  - `BENCHMARKS: Dict[str, List[dict]]` keyed `"cis" | "nist" | "pci"`
  - `run_netsec_audit(config_text: Optional[str] = None, device_name: Optional[str] = None, benchmark: str = "cis") -> dict` returning
    `{"benchmark": str, "score": Optional[int], "summary": {...}, "rules": [...]}` where each rule dict has keys `id, title, severity, category, status, device, detail, remediation, evidence` and `evidence` is a list of `{"line": int, "text": str, "context": str}`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_netsec_audit_scan.py`:

```python
class TestAuditEngineResults(unittest.TestCase):
    def _cfg(self, name):
        import os
        p = os.path.join(os.path.dirname(__file__), "fixtures", name)
        with open(p, encoding="utf-8") as fh:
            return fh.read()

    def test_violations_config_scores_low_and_cites_lines(self):
        res = netsec_audit.run_netsec_audit(
            config_text=self._cfg("fortigate_violations.conf"),
            benchmark="cis")
        self.assertIsNotNone(res["score"])
        self.assertLess(res["score"], 50)
        failing = [r for r in res["rules"] if r["status"] == "FAIL"]
        self.assertTrue(failing)
        for r in failing:
            self.assertTrue(r["evidence"], "%s senza evidenza" % r["id"])
            for e in r["evidence"]:
                self.assertIn("line", e)
                self.assertIn("context", e)

    def test_clean_config_scores_full(self):
        res = netsec_audit.run_netsec_audit(
            config_text=self._cfg("fortigate_clean.conf"), benchmark="cis")
        self.assertEqual(res["score"], 100)
        self.assertEqual(res["summary"]["failed"], 0)

    def test_partial_config_reports_unknown_not_pass(self):
        """Regressione: prima una sezione assente valeva PASS e gonfiava il voto."""
        res = netsec_audit.run_netsec_audit(
            config_text=self._cfg("fortigate_partial.conf"), benchmark="cis")
        self.assertGreater(res["summary"]["unknown"], 0)
        for r in res["rules"]:
            if r["status"] == "UNKNOWN":
                self.assertEqual(r["evidence"], [])

    def test_all_benchmarks_run(self):
        for bench in ("cis", "nist", "pci"):
            res = netsec_audit.run_netsec_audit(
                config_text=self._cfg("fortigate_violations.conf"),
                benchmark=bench)
            self.assertEqual(res["benchmark"], bench)
            self.assertTrue(res["rules"])

    def test_unknown_benchmark_falls_back_to_cis(self):
        res = netsec_audit.run_netsec_audit(
            config_text=self._cfg("fortigate_clean.conf"), benchmark="nope")
        self.assertEqual(res["benchmark"], "cis")

    def test_summary_keys_present(self):
        res = netsec_audit.run_netsec_audit(
            config_text=self._cfg("fortigate_clean.conf"))
        for key in ("total", "passed", "failed", "warned", "unknown"):
            self.assertIn(key, res["summary"])
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m unittest tests.test_netsec_audit_scan -v`
Expected: FAIL — `KeyError: 'unknown'` (the old engine's summary has no such key).

- [ ] **Step 3: Write the benchmark definitions**

Create `services/netsec_audit/benchmarks.py`:

```python
# -*- coding: utf-8 -*-
"""Definizioni dei benchmark: metadati che legano una citazione a una regola.

Regole condivise fra benchmark (es. la versione TLS vale sia per CIS sia per
NIST SC-13) puntano alla STESSA funzione: cambia solo la citazione, il titolo e
il testo di rimedio. Nessuna logica e' duplicata.

Nomenclatura: CIS versiona i benchmark per prodotto (esiste un "CIS Fortinet
FortiGate Benchmark"), non esiste una "CIS Benchmark v4.0" globale.
"""

from typing import Any, Dict, List

from . import rules

BENCHMARKS: Dict[str, List[Dict[str, Any]]] = {
    "cis": [
        {"id": "AUD-CIS-01",
         "title": "Protocolli di gestione non sicuri (Telnet / HTTP)",
         "severity": "CRITICAL", "category": "Hardening",
         "check": rules.check_management_protocols,
         "remediation": "set allowaccess ssh https (rimuovere telnet e http)"},
        {"id": "AUD-CIS-02",
         "title": "Policy permissiva any-to-any",
         "severity": "CRITICAL", "category": "Access Rules",
         "check": rules.check_any_any_policy,
         "remediation": "Specificare srcaddr, dstaddr e service espliciti."},
        {"id": "AUD-CIS-03",
         "title": "Cifrari SSL/TLS legacy (TLS < 1.2)",
         "severity": "HIGH", "category": "Encryption",
         "check": rules.check_tls_version,
         "remediation": "set ssl-min-proto-version TLSv1-2"},
        {"id": "AUD-CIS-04",
         "title": "Timeout di inattivita' della console di gestione",
         "severity": "MEDIUM", "category": "Hardening",
         "check": rules.check_idle_timeout,
         "remediation": "set admintimeout 10"},
        {"id": "AUD-CIS-05",
         "title": "Community SNMP v1/v2c di default",
         "severity": "HIGH", "category": "Management",
         "check": rules.check_snmp_community,
         "remediation": "Disabilitare SNMP v1/v2c e configurare SNMPv3."},
        {"id": "AUD-CIS-06",
         "title": "Cifratura forte non applicata (strong-crypto)",
         "severity": "MEDIUM", "category": "Encryption",
         "check": rules.check_strong_crypto,
         "remediation": "set strong-crypto enable"},
    ],
    "nist": [
        {"id": "AUD-NIST-01",
         "title": "Protezione del perimetro (SC-7)",
         "severity": "CRITICAL", "category": "Access Rules",
         "check": rules.check_boundary_protection,
         "remediation": "Restringere le destinazioni delle policy in ingresso "
                        "da WAN."},
        {"id": "AUD-NIST-02",
         "title": "Restrizione dell'accesso amministrativo remoto (AC-17)",
         "severity": "CRITICAL", "category": "Hardening",
         "check": rules.check_admin_trusthost,
         "remediation": "set trusthost1 <subnet gestione> <netmask>"},
        {"id": "AUD-NIST-03",
         "title": "Protezione crittografica dei dati in transito (SC-13)",
         "severity": "HIGH", "category": "Encryption",
         "check": rules.check_tls_version,
         "remediation": "Imporre TLS 1.2+ e suite AES-256."},
        {"id": "AUD-NIST-04",
         "title": "Audit trail centralizzato (AU-2 / AU-12)",
         "severity": "MEDIUM", "category": "Logging",
         "check": rules.check_syslog,
         "remediation": "set status enable; set server <IP syslog>"},
    ],
    "pci": [
        {"id": "AUD-PCI-01",
         "title": "Req 1.2 — Porte di amministrazione esposte (22, 3389)",
         "severity": "CRITICAL", "category": "Access Rules",
         "check": rules.check_inbound_admin_ports,
         "remediation": "Bloccare SSH/RDP in ingresso da Internet; usare "
                        "VPN o bastion host."},
        {"id": "AUD-PCI-02",
         "title": "Req 1.3 — Traffico diretto fra Internet e CDE",
         "severity": "CRITICAL", "category": "Access Rules",
         "check": rules.check_any_any_policy,
         "remediation": "Isolare la rete cardholder dietro una DMZ."},
        {"id": "AUD-PCI-03",
         "title": "Req 2.2 — Default di fabbrica e policy password",
         "severity": "HIGH", "category": "Hardening",
         "check": rules.check_vendor_defaults,
         "remediation": "Rimuovere l'account 'admin' di default e abilitare "
                        "la password policy."},
        {"id": "AUD-PCI-04",
         "title": "Req 10.2 — Audit trail automatici",
         "severity": "MEDIUM", "category": "Logging",
         "check": rules.check_syslog,
         "remediation": "Configurare l'inoltro syslog verso il collector."},
    ],
}
```

- [ ] **Step 4: Rewrite the public API**

Replace the ENTIRE contents of `services/netsec_audit/__init__.py`:

```python
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
from .model import UNKNOWN, score_rules
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
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run python -m unittest tests.test_netsec_audit_scan -v`
Expected: PASS, 12 tests.

**If `test_clean_config_scores_full` fails**, print the non-PASS rules to see which rule disagrees with the clean fixture, then fix the FIXTURE (not the rule) unless the rule is genuinely wrong:

```bash
uv run python -c "
from services import netsec_audit
cfg=open('tests/fixtures/fortigate_clean.conf',encoding='utf-8').read()
for r in netsec_audit.run_netsec_audit(config_text=cfg)['rules']:
    if r['status']!='PASS': print(r['id'], r['status'], r['detail'])
"
```

- [ ] **Step 6: Full verification**

Run: `uv run pyrefly check` — expect `0 errors`.
Run: `uv run python -m unittest discover -s tests -p "test_*.py" 2>&1 | grep -E "^(Ran|OK|FAILED)"` — expect `OK`.

- [ ] **Step 7: Commit**

```bash
git add services/netsec_audit/ tests/test_netsec_audit_scan.py
git commit -m "feat(audit): wire benchmarks to real rules, expose evidence

Benchmark definitions become metadata binding a citation to a rule function, so
rules shared across benchmarks (TLS for CIS-03 and NIST SC-13, any-any for
CIS-02 and PCI 1.3, syslog for AU-2 and PCI 10.2) have one implementation.

The response gains per-rule evidence and an 'unknown' count in the summary, and
score is null rather than 0 or 100 when nothing could be assessed.

Corrects the benchmark naming: CIS versions per product, there is no global
'CIS Benchmark v4.0'."
```

---

### Task 7: Frontend — UNKNOWN status, evidence rows, real counts

**Files:**
- Modify: `templates/dashboard.html:2323-2340` (KPI grid), `:2385-2390` (severity filter)
- Modify: `static/js/netsec-audit.js` (`renderAuditOverview`, `renderAuditRulesTable`)

**Interfaces:**
- Consumes: the API response shape from Task 6 (`summary.unknown`, `score: null`, `rule.evidence[]`).
- Produces: `window.toggleAuditEvidence(ruleId)` for the expandable evidence row.

- [ ] **Step 1: Add the UNKNOWN KPI tile and fix the hardcoded rule count**

In `templates/dashboard.html`, the KPI grid at line 2323 hardcodes `<strong>6</strong>` for "Regole Auditate" — a stale literal. Replace the whole grid (lines 2323-2340):

```html
      <div class="kpi-grid" style="grid-template-columns:repeat(5, minmax(0,1fr)); margin-bottom:18px;">
        <div class="kpi">
          <h4>Regole Auditate</h4>
          <strong id="auditStatTotal">0</strong>
        </div>
        <div class="kpi">
          <h4>Vulnerabili / Fail</h4>
          <strong id="auditStatFailed" style="color:var(--danger);">0</strong>
        </div>
        <div class="kpi">
          <h4>Conformi / Pass</h4>
          <strong id="auditStatPassed" style="color:var(--success);">0</strong>
        </div>
        <div class="kpi">
          <h4>Warning / Attenzione</h4>
          <strong id="auditStatWarned" style="color:var(--warning);">0</strong>
        </div>
        <div class="kpi" title="Sezioni di configurazione assenti: non valutabili, escluse dal punteggio.">
          <h4>Non valutabili</h4>
          <strong id="auditStatUnknown" style="color:var(--text-muted);">0</strong>
        </div>
      </div>
```

- [ ] **Step 2: Update the severity filter to match the engine**

The engine emits only `CRITICAL`, `HIGH`, `MEDIUM`. The existing options already match, so leave `auditSevFilter` alone. No change needed in this step — verify by reading lines 2385-2390 and confirming the three values are `critical`, `high`, `medium`.

- [ ] **Step 3: Update `renderAuditOverview` to consume the summary**

In `static/js/netsec-audit.js`, replace the whole `renderAuditOverview` function. It must read from a stored summary rather than recounting, because the engine now owns the scoring rule (UNKNOWN excluded):

```javascript
    // Riepilogo restituito dal motore. Non ricalcolato lato client: la
    // regola di punteggio (UNKNOWN escluso dal denominatore) vive nel motore,
    // e duplicarla qui vorrebbe dire farle divergere.
    let _auditSummary = null;
    let _auditScore = null;

    function renderAuditOverview() {
        const s = _auditSummary || { total: 0, passed: 0, failed: 0, warned: 0, unknown: 0 };
        const score = _auditScore;

        const scoreEl = document.getElementById('auditScoreValue');
        if (scoreEl) scoreEl.textContent = (score === null || score === undefined) ? '—' : `${score}%`;

        const gradeEl = document.getElementById('auditGradeBadge');
        if (gradeEl) {
            if (score === null || score === undefined) {
                gradeEl.textContent = !s.total
                    ? (currentLang === 'en' ? 'NO SCAN RUN YET' : 'NESSUNA SCANSIONE ESEGUITA')
                    : (currentLang === 'en' ? 'NOT ASSESSABLE' : 'NON DETERMINABILE');
                gradeEl.style.color = 'var(--text-muted)';
            } else {
                gradeEl.textContent = score >= 80 ? 'GRADE A' : score >= 60 ? 'GRADE B' : 'GRADE C - RISK DETECTED';
                gradeEl.style.color = score >= 80 ? 'var(--success)' : score >= 60 ? 'var(--warning)' : 'var(--danger)';
            }
        }

        const set = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };
        set('auditStatTotal', s.total);
        set('auditStatFailed', s.failed);
        set('auditStatPassed', s.passed);
        set('auditStatWarned', s.warned);
        set('auditStatUnknown', s.unknown || 0);
    }
```

- [ ] **Step 4: Store the summary when a scan returns**

In `runAuditScan`, inside the `if (res && res.ok)` branch, replace the assignment block so the summary and score are captured:

```javascript
                const data = await res.json();
                _auditRules = data.rules || [];
                _auditSummary = data.summary || null;
                _auditScore = (data.score === undefined) ? null : data.score;
                renderAuditOverview();
                renderAuditRulesTable();
```

- [ ] **Step 5: Render the UNKNOWN badge and the evidence row**

In `renderAuditRulesTable`, replace the `statusBadge` expression and the returned row markup:

```javascript
            const statusBadge = r.status === 'PASS'
                ? `<span class="badge" style="background:rgba(34, 197, 94, 0.15); color:var(--success);"><i class="fa-solid fa-check"></i> PASS</span>`
                : r.status === 'FAIL'
                ? `<span class="badge" style="background:rgba(239, 68, 68, 0.15); color:var(--danger);"><i class="fa-solid fa-xmark"></i> FAIL</span>`
                : r.status === 'WARN'
                ? `<span class="badge" style="background:rgba(245, 158, 11, 0.15); color:var(--warning);"><i class="fa-solid fa-triangle-exclamation"></i> WARN</span>`
                : `<span class="badge" style="background:var(--surface-3); color:var(--text-muted);" title="${currentLang==='en'?'Config section absent: excluded from the score.':'Sezione di configurazione assente: esclusa dal punteggio.'}"><i class="fa-solid fa-circle-question"></i> N/D</span>`;

            const ev = r.evidence || [];
            const evBtn = ev.length
                ? `<button class="btn btn-sm btn-secondary" style="padding:2px 8px; font-size:11px; margin-top:4px;" onclick="toggleAuditEvidence('${escapeHtml(String(r.id))}')">
                       <i class="fa-solid fa-code"></i> ${ev.length} ${currentLang==='en'?'evidence':'evidenze'}
                   </button>`
                : '';

            const evRows = ev.map(e => `
                <div style="display:flex; gap:8px; padding:3px 0; font-family:var(--font-code); font-size:11px;">
                    <span style="color:var(--text-muted); min-width:56px;">${e.line ? ('riga ' + escapeHtml(String(e.line))) : '—'}</span>
                    <span style="color:var(--text-muted); min-width:180px;">${escapeHtml(e.context || '')}</span>
                    <span style="color:var(--danger);">${escapeHtml(e.text || '')}</span>
                </div>`).join('');

            return `<tr style="font-size:12px; border-top:1px solid var(--border);">
                <td style="padding:8px; font-family:var(--font-code); font-weight:700;">${escapeHtml(r.id)}</td>
                <td style="padding:8px;">
                    <div style="font-weight:700;">${escapeHtml(r.title)}</div>
                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">${escapeHtml(r.detail)}</div>
                    ${evBtn}
                </td>
                <td style="padding:8px;">${sevBadge}</td>
                <td style="padding:8px;"><span class="badge">${escapeHtml(r.category)}</span></td>
                <td style="padding:8px;">${statusBadge}</td>
                <td style="padding:8px;">
                    <code style="font-size:11px; color:var(--primary); background:var(--surface-2); padding:3px 6px; border-radius:4px; display:inline-block; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                        ${escapeHtml(r.remediation)}
                    </code>
                </td>
            </tr>
            ${ev.length ? `<tr id="auditEv-${escapeHtml(String(r.id))}" style="display:none;">
                <td colspan="6" style="padding:8px 8px 12px 24px; background:var(--surface-2);">${evRows}</td>
            </tr>` : ''}`;
```

Then add the toggle function and export it (place it beside the other functions, before the `window.` exports):

```javascript
    function toggleAuditEvidence(ruleId) {
        const row = document.getElementById('auditEv-' + ruleId);
        if (row) row.style.display = (row.style.display === 'none') ? '' : 'none';
    }
```

And add to the export block at the bottom:

```javascript
    window.toggleAuditEvidence = toggleAuditEvidence;
```

- [ ] **Step 6: Verify the JS parses**

```bash
uv run --with tree-sitter --with tree-sitter-javascript python -c "
import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser
p=Parser(Language(tsjs.language()))
t=p.parse(open('static/js/netsec-audit.js','rb').read()); e=[]
def w(n):
    if n.type=='ERROR' or n.is_missing: e.append((n.type,n.start_point))
    for c in n.children: w(c)
w(t.root_node); print('OK' if not e else ('FAIL '+str(e[:3])))
"
```
Expected: `OK`

- [ ] **Step 7: Confirm no stale references**

```bash
grep -n "auditStatTotal\|auditStatUnknown\|toggleAuditEvidence" templates/dashboard.html static/js/netsec-audit.js
```
Expected: `auditStatTotal` and `auditStatUnknown` in both files; `toggleAuditEvidence` defined, called, and exported in the JS.

- [ ] **Step 8: Full verification and commit**

Run: `uv run pyrefly check` — expect `0 errors`.
Run: `uv run python -m unittest discover -s tests -p "test_*.py" 2>&1 | grep -E "^(Ran|OK|FAILED)"` — expect `OK`.

```bash
git add templates/dashboard.html static/js/netsec-audit.js
git commit -m "feat(audit): surface UNKNOWN status and per-rule evidence

Adds a fifth KPI tile for non-assessable rules and replaces the hardcoded
'6' rule count with the engine's actual total. A rule whose config section is
absent renders as N/D with an explanatory tooltip rather than being silently
counted as compliant.

Each finding gains an expandable evidence row showing line number, block path
and the offending directive, so a FAIL can be traced to the config.

The score and counts now come from the engine's summary instead of being
recomputed client-side, since the scoring rule (UNKNOWN excluded from the
denominator) belongs in one place."
```

---

### Task 8: Replace the alert() export with a real report

**Files:**
- Modify: `static/js/netsec-audit.js` (`exportAuditReport`)

**Interfaces:**
- Consumes: `_auditRules`, `_auditSummary`, `_auditScore` (Task 7).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Replace `exportAuditReport`**

The current implementation calls `alert()` and produces no artifact. Replace the whole function:

```javascript
    // Report HTML scaricabile. Nessuna dipendenza esterna: si costruisce il
    // documento e lo si scarica via Blob, coerentemente col resto dell'app.
    function exportAuditReport() {
        if (!_auditRules.length) {
            showToast(currentLang === 'en'
                ? 'Run a scan before exporting a report.'
                : 'Esegui una scansione prima di esportare il report.', 'warning');
            return;
        }
        const benchSel = document.getElementById('auditBenchmarkSelect');
        const benchmark = benchSel ? benchSel.options[benchSel.selectedIndex].text : 'CIS';
        const devSel = document.getElementById('auditDeviceSelect');
        const device = devSel ? devSel.options[devSel.selectedIndex].text : '—';
        const s = _auditSummary || { total: 0, passed: 0, failed: 0, warned: 0, unknown: 0 };
        const scoreTxt = (_auditScore === null || _auditScore === undefined) ? 'N/D' : (_auditScore + '%');
        const generated = new Date().toLocaleString();

        const rows = _auditRules.map(r => {
            const ev = (r.evidence || []).map(e =>
                `<div class="ev"><span>${e.line ? ('riga ' + escapeHtml(String(e.line))) : '—'}</span>`
                + `<span>${escapeHtml(e.context || '')}</span>`
                + `<code>${escapeHtml(e.text || '')}</code></div>`).join('');
            return `<tr class="st-${escapeHtml(r.status)}">
                <td><strong>${escapeHtml(r.id)}</strong></td>
                <td>${escapeHtml(r.title)}<div class="detail">${escapeHtml(r.detail)}</div>${ev}</td>
                <td>${escapeHtml(r.severity)}</td>
                <td>${escapeHtml(r.status)}</td>
                <td><code>${escapeHtml(r.remediation)}</code></td>
            </tr>`;
        }).join('');

        const html = `<!doctype html><html lang="it"><head><meta charset="utf-8">
<title>Report Audit — ${escapeHtml(device)}</title>
<style>
body{font-family:system-ui,sans-serif;margin:32px;color:#111;}
h1{font-size:20px;margin:0 0 4px;} .meta{color:#666;font-size:13px;margin-bottom:20px;}
.kpis{display:flex;gap:20px;margin-bottom:20px;flex-wrap:wrap;}
.kpi{border:1px solid #ddd;border-radius:8px;padding:10px 16px;min-width:110px;}
.kpi b{display:block;font-size:22px;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th,td{border-bottom:1px solid #e5e5e5;padding:8px;text-align:left;vertical-align:top;}
th{background:#f6f6f6;}
.detail{color:#666;margin-top:3px;}
.ev{display:flex;gap:10px;margin-top:4px;font-family:ui-monospace,monospace;font-size:11px;}
.ev span:first-child{color:#999;min-width:60px;} .ev span:nth-child(2){color:#999;min-width:170px;}
.ev code{color:#b00;}
.st-FAIL td:nth-child(4){color:#b00;font-weight:700;}
.st-WARN td:nth-child(4){color:#a60;font-weight:700;}
.st-PASS td:nth-child(4){color:#070;font-weight:700;}
.st-UNKNOWN td:nth-child(4){color:#888;font-weight:700;}
.note{margin-top:20px;font-size:12px;color:#666;border-top:1px solid #ddd;padding-top:10px;}
</style></head><body>
<h1>Report di Compliance — ${escapeHtml(benchmark)}</h1>
<div class="meta">Apparato: ${escapeHtml(device)} · Generato il ${escapeHtml(generated)}</div>
<div class="kpis">
  <div class="kpi"><b>${escapeHtml(scoreTxt)}</b>Score</div>
  <div class="kpi"><b>${s.passed}</b>Conformi</div>
  <div class="kpi"><b>${s.failed}</b>Non conformi</div>
  <div class="kpi"><b>${s.warned}</b>Warning</div>
  <div class="kpi"><b>${s.unknown || 0}</b>Non valutabili</div>
</div>
<table><thead><tr><th>ID</th><th>Controllo ed evidenze</th><th>Severita'</th><th>Esito</th><th>Rimedio</th></tr></thead>
<tbody>${rows}</tbody></table>
<div class="note">I controlli "non valutabili" corrispondono a sezioni di configurazione assenti nel file analizzato: sono esclusi dal calcolo dello score e non vanno letti come conformita'.</div>
</body></html>`;

        const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit-${(device || 'device').replace(/[^\w.-]+/g, '_')}-${new Date().toISOString().slice(0, 10)}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
```

- [ ] **Step 2: Verify the JS parses**

```bash
uv run --with tree-sitter --with tree-sitter-javascript python -c "
import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser
p=Parser(Language(tsjs.language()))
t=p.parse(open('static/js/netsec-audit.js','rb').read()); e=[]
def w(n):
    if n.type=='ERROR' or n.is_missing: e.append((n.type,n.start_point))
    for c in n.children: w(c)
w(t.root_node); print('OK' if not e else ('FAIL '+str(e[:3])))
"
```
Expected: `OK`

- [ ] **Step 3: Confirm no `alert(` remains in the file**

```bash
grep -n "alert(" static/js/netsec-audit.js
```
Expected: no output.

- [ ] **Step 4: Full verification and commit**

Run: `uv run pyrefly check` — expect `0 errors`.
Run: `uv run python -m unittest discover -s tests -p "test_*.py" 2>&1 | grep -E "^(Ran|OK|FAILED)"` — expect `OK`.

```bash
git add static/js/netsec-audit.js
git commit -m "feat(audit): downloadable HTML compliance report

Replaces the alert() stub with a real self-contained report carrying the score,
the per-status counts, and every finding with its evidence lines. Includes an
explicit note that non-assessable checks are absent config sections excluded
from the score, so a reader cannot mistake them for compliance."
```

---

### Task 9: Rebuild the exe

**Files:** none modified.

- [ ] **Step 1: Rebuild**

```bash
uv run pyinstaller SentinelNet.spec --noconfirm
```
Expected: `Build complete!` and a fresh `dist/SentinelNet.exe`.

- [ ] **Step 2: Confirm the binary is newer than the last commit**

```bash
ls -la dist/SentinelNet.exe && git log --oneline -1
```

- [ ] **Step 3: Report to the user**

State plainly: what changed, that the engine now refuses to invent verdicts, and that the UI changes have NOT been exercised in a browser (no Node.js in this environment; JS was validated by parsing only).

---

## Self-Review

**Spec coverage** — every Part A requirement maps to a task:

| Spec requirement | Task |
|---|---|
| `_parse_with_lines` reusing `_forti_tokens`, flat records | 1 |
| Accessors `blocks`/`setting` (implemented as `section_entries`/`setting`) | 1 |
| `UNKNOWN` status, absence≠PASS | 2 |
| Score excludes UNKNOWN, `None` when nothing assessable | 2 |
| "Absence is the finding" exceptions (syslog, trusthost) | 5 |
| CIS rules 01-06 incl. new strong-crypto | 3, 5, 6 |
| NIST SC-7 / AC-17 / SC-13 / AU-2 | 4, 5, 6 |
| PCI 1.2 / 1.3 / 2.2 / 10.2 incl. custom service resolution | 4, 5, 6 |
| WAN role resolution with name fallback | 4 |
| Shared evaluations, one implementation | 6 |
| Evidence `{line, text, context}` on the API | 6 |
| Frontend UNKNOWN badge + fourth/fifth tile | 7 |
| Evidence expandable row | 7 |
| Remove `Math_round` | 6 (old `__init__.py` fully replaced) |
| Fix "CIS Benchmark v4.0" naming | 6 (docstring), already fixed in UI |
| Real report replacing `alert()` | 8 |
| Tests: fixtures, per-rule status + evidence lines, scoring | 1-6 |

**Deviations from the spec, deliberate:**
- The spec named accessors `blocks()`/`setting()`; this plan uses `section_entries()`/`setting()` plus `section_present()`. `section_present` is required to distinguish an empty-but-present block from an absent one — without it the UNKNOWN rule cannot be implemented correctly.
- The spec left `services/netsec_audit.py` a single module. This plan makes it a package, because the rewrite roughly triples the code across three distinct responsibilities. The public import path is unchanged.
- Frontend gains a fifth KPI tile, not a fourth: the existing grid already had four, and the hardcoded literal `6` in "Regole Auditate" is a stale value that needed an id regardless.

**Placeholder scan:** no TBD/TODO; every code step carries complete code; no "similar to Task N".

**Type consistency:** `ParsedConfig` is produced by `parse_with_lines` (Task 1) and consumed by every rule (Tasks 3-5) and by `run_netsec_audit` (Task 6). `RuleOutcome`/`Evidence` are defined in Task 2 and used unchanged thereafter. `score_rules` takes the list of rule dicts built in Task 6, matching the `{"status": ...}` shape its Task 2 tests assert. The JS reads `data.summary`, `data.score`, `rule.evidence[]` — exactly the keys Task 6 emits.

**Known risk to watch during execution:** Task 6's `test_clean_config_scores_full` asserts 100 on the clean fixture. If any rule legitimately warns on that fixture (most likely `check_vendor_defaults`, since the clean fixture must contain a `system password-policy` block with `status enable` — it does), fix the fixture rather than weakening the rule. Step 5 of Task 6 includes the diagnostic command.
