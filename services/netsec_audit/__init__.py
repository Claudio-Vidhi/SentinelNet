# -*- coding: utf-8 -*-
"""services/netsec_audit — motore di compliance di rete.

Valuta una configurazione contro benchmark reali:
  - CIS Fortinet FortiGate Benchmark v1.0.1
  - CIS Cisco IOS XE 17.x Benchmark v2.2.1
  - NIST SP 800-53 Rev. 5 (SC-7, SC-8, SC-13, AC-7, AC-12, AC-17, AU-2/8/12, IA-5)
  - PCI-DSS v4.0 (requisiti 1.2, 1.3, 2.2, 4.2, 5.2, 8.3, 10.2, 10.3, 10.6)

Ogni verdetto nasce da una valutazione sulla configurazione PARSATA e, quando
non e' PASS, cita la riga esatta che lo motiva.

Le due famiglie di apparati hanno grammatiche di configurazione diverse, quindi
il motore riconosce il vendor PRIMA di scegliere il parser e le regole: dare in
pasto una running-config Cisco al parser FortiOS produrrebbe zero record e un
audit interamente UNKNOWN, cioe' un risultato che sembra un esito ma non lo e'.

Questo modulo e' anche l'unico punto in cui l'audit diventa testo: le regole
restituiscono chiavi, qui si sceglie la lingua. Un report si consegna, e la
lingua in cui va consegnato non e' necessariamente quella con cui l'operatore
sta lavorando — per questo ``lang`` e' un parametro, non una preferenza globale.
"""

from typing import Any, Dict, List, Optional

from .benchmarks import BENCHMARK_TITLES, BENCHMARKS, FORTIOS, IOS
from .guidance import guidance_for
from .ios_parser import parse_ios
from .messages import DEFAULT_LANG, LANGS, normalize_lang, render
from .model import UNKNOWN, RuleOutcome, score_rules
from .parser import parse_with_lines

__all__ = ["run_netsec_audit", "detect_vendor", "BENCHMARKS",
           "BENCHMARK_TITLES", "FORTIOS", "IOS", "LANGS"]

_DEFAULT_BENCHMARK = "cis"

# Marcatori cercati riga per riga. Sono strutturali (parole chiave della
# grammatica), non descrittivi: un commento che nomina "fortigate" dentro una
# config Cisco non deve spostare il verdetto.
_FORTIOS_MARKERS = ("config system global", "config firewall policy",
                    "config system interface", "#config-version=",
                    "config vdom", "config system admin")
_IOS_MARKERS = ("line vty", "line con 0", "interface gigabitethernet",
                "ip http server", "aaa new-model", "boot system flash",
                "service password-encryption", "interface vlan")


def detect_vendor(config_text: Optional[str]) -> Optional[str]:
    """Vendor riconosciuto, o ``None`` se il testo non e' attribuibile.

    Conta i marcatori invece di fermarsi al primo: un backup puo' contenere
    entrambe le grammatiche (un file concatenato, un incolla parziale) e in
    quel caso vince la piu' rappresentata.
    """
    if not config_text:
        return None
    low = config_text.lower()
    forti = sum(low.count(m) for m in _FORTIOS_MARKERS)
    ios = sum(low.count(m) for m in _IOS_MARKERS)
    if forti == 0 and ios == 0:
        return None
    return FORTIOS if forti >= ios else IOS


def _localized(value: Any, lang: str) -> str:
    """Campo che puo' essere una stringa (comando CLI) o un dizionario per lingua.

    I comandi CLI non si traducono e restano stringhe; solo i testi discorsivi
    sono dizionari. Distinguere qui evita di duplicare in due lingue centinaia
    di righe di ``config system global / set ...`` identiche.
    """
    if isinstance(value, dict):
        return value.get(lang) or value.get(DEFAULT_LANG) or ""
    return value or ""


def _render_evidence(outcome: RuleOutcome, lang: str) -> List[Dict[str, Any]]:
    out = []
    for e in outcome.evidence:
        text = (render(e.message, lang, e.params) if e.message else e.text)
        out.append({"line": e.line, "text": text, "context": e.context})
    return out


def run_netsec_audit(config_text: Optional[str] = None,
                     device_name: Optional[str] = None,
                     benchmark: str = _DEFAULT_BENCHMARK,
                     lang: str = DEFAULT_LANG) -> Dict[str, Any]:
    """Valuta ``config_text`` contro il benchmark richiesto, nella lingua data."""
    key = (benchmark or _DEFAULT_BENCHMARK).lower().strip()
    if key not in BENCHMARKS:
        key = _DEFAULT_BENCHMARK
    code = normalize_lang(lang)

    vendor = detect_vendor(config_text)
    # Vendor non riconosciuto: si tenta comunque FortiOS, che e' la piattaforma
    # storica di questo motore, ma il payload lo dichiara e la UI puo' dirlo.
    cfg = (parse_ios(config_text) if vendor == IOS
           else parse_with_lines(config_text))
    device = device_name or "-"

    applicable = [t for t in BENCHMARKS[key]
                  if t["vendor"] == (vendor or FORTIOS)]

    # Diverse regole trattano l'assenza di un blocco come la violazione stessa
    # (nessun DNS, nessun NTP, nessun syslog): lettura corretta su una
    # configurazione reale, sbagliata su un testo vuoto o illeggibile, dove
    # l'assenza non dice nulla dell'apparato. Il caso "niente da valutare" si
    # decide qui una volta sola, invece di ripeterlo in ogni regola.
    parsed_anything = bool(getattr(cfg, "records", None)
                           or getattr(cfg, "lines", None))
    nothing = RuleOutcome(UNKNOWN, "engine.nothing_to_assess")

    evaluated: List[Dict[str, Any]] = []
    for tmpl in applicable:
        check = tmpl["check"]
        outcome = check(cfg) if parsed_anything else nothing
        evaluated.append({
            "id": tmpl["id"],
            "title": _localized(tmpl["title"], code),
            "severity": tmpl["severity"],
            "category": tmpl["category"],
            "vendor": tmpl["vendor"],
            "ref": tmpl["ref"],
            "level": tmpl["level"],
            "automated": tmpl["automated"],
            "audit": tmpl["audit"],
            "status": outcome.status,
            "device": device,
            "detail": render(outcome.message, code, outcome.params),
            "remediation": _localized(tmpl["remediation"], code),
            # Perche' l'impostazione dovrebbe essere in un certo modo, cosa
            # comporta cambiarla e qual e' il default di fabbrica. Dizionario
            # vuoto se il controllo non ha ancora una voce di guida.
            "guidance": guidance_for(check.__name__, code),
            "evidence": _render_evidence(outcome, code),
        })

    score, summary = score_rules(evaluated)
    return {
        "benchmark": key,
        "benchmark_title": BENCHMARK_TITLES.get(key, key.upper()),
        "lang": code,
        "vendor": vendor,
        "score": score,
        "summary": summary,
        "rules": evaluated,
    }
