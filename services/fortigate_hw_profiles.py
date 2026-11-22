# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""FortiGate hardware capability profiling from model, version, or backup header.

Maps FortiGate appliance series/models to ASIC (NPU/CP), RAM tier, proxy
inspection support, and NPU sniffer syntax without external I/O.
"""

from dataclasses import asdict, dataclass
import re
from typing import Any, Dict, Optional, Tuple

_HEADER_RE = re.compile(
    r"^#config-version=([A-Za-z0-9_.-]+?)-v?(\d+\.\d+(?:\.\d+)?)(?:-|:|\s|$)",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?")
_MODEL_PREFIX_RE = re.compile(
    r"^(?:FORTIGATE[-_]?|FORTIWIFI[-_]?|FORTIRUGGED[-_]?|FGT[-_]?|FWF[-_]?|FGR[-_]?|FG[-_]?)"
)
_VM_TOKEN_RE = re.compile(r"(?:^|[-_])(VM|KVM|AWS|AZR|GCP|XEN|HV|ULM)(?:$|[-_0-9])")
_SERIES_CODE_RE = re.compile(r"^(\d{2,4}[DEFG])")

_ENTRY_2GB_SOC3 = frozenset({"30E", "50E", "60E", "61E", "80E"})
_ENTRY_2GB_SOC4 = frozenset({"40F", "41F", "60F", "61F", "70F", "71F"})
_SOC4_4GB = frozenset({"80F", "81F", "100F", "101F"})
_SP5_SERIES = frozenset({"90G", "91G", "120G", "121G"})
_NP6XLITE_SERIES = frozenset({"200F", "201F"})
_NP7_SERIES = frozenset({
    "400F", "401F", "600F", "601F", "900G", "901G", "1000F", "1001F",
    "1800F", "1801F", "2600F", "2601F", "3000F", "3500F", "4200F",
})
_NP6LITE_SERIES = frozenset({"100E", "101E", "200E", "201E"})
_NP6_SERIES = frozenset({
    "300E", "500E", "600E", "1100E", "1500D", "2000E", "3000D",
})


@dataclass(frozen=True)
class FortiGateHWProfile:
    model: str
    version: str
    family: str
    npu: str
    cp: str
    ram_tier: str
    is_vm: bool
    proxy_removed_2gb: bool
    sniffer_syntax: str


def parse_version_tuple(version: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """Parse a FortiOS version string into a comparable ``(major, minor, patch)`` tuple."""
    if not version:
        return None
    m = _VERSION_RE.search(version.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def parse_config_header(config_text: Optional[str]) -> Tuple[str, str]:
    """Extract ``(model_code, version)`` from a FortiOS ``#config-version=`` header."""
    if not config_text:
        return "", ""
    for line in config_text.splitlines()[:10]:
        s = line.strip()
        if not s.lower().startswith("#config-version="):
            continue
        m = _HEADER_RE.match(s)
        if m:
            return m.group(1), m.group(2)
    return "", ""


def _normalized_version(version: Optional[str], ver_tuple: Optional[Tuple[int, int, int]]) -> str:
    if not version:
        return ""
    raw = version.strip()
    if ver_tuple is None:
        return raw
    m = _VERSION_RE.search(raw)
    return m.group(0).lstrip("vV") if m else raw


def _normalized_model_label(raw_model: str, code: str, is_vm: bool) -> str:
    if raw_model:
        if raw_model.lower().startswith(("fgt", "fg", "fwf", "fgr")):
            return raw_model.upper()
        return raw_model
    if is_vm:
        return "FGVM"
    if code:
        return f"FGT{code}"
    return ""


def resolve_profile(
    model: Optional[str] = None,
    version: Optional[str] = None,
    serial: Optional[str] = None,
) -> FortiGateHWProfile:
    """Resolve hardware capabilities from FortiGate model, version, or serial."""
    raw_model = (model or "").strip()
    raw_serial = (serial or "").strip()
    token = (raw_model or raw_serial[:12]).upper()
    stripped = _MODEL_PREFIX_RE.sub("", token)

    ver_tuple = parse_version_tuple(version)
    ver_str = _normalized_version(version, ver_tuple)

    family = "generic"
    npu = "unknown"
    cp = "unknown"
    ram_tier = "unknown"
    is_vm = False
    sniffer_syntax = "generic"
    code = ""

    if stripped and _VM_TOKEN_RE.search(stripped):
        family = "vm"
        npu = "none"
        cp = "none"
        ram_tier = "unknown"
        is_vm = True
        sniffer_syntax = "none"
    else:
        m = _SERIES_CODE_RE.match(stripped)
        code = m.group(1) if m else ""
        if code in _ENTRY_2GB_SOC3:
            family, npu, cp, ram_tier, sniffer_syntax = "entry_2gb", "soc3", "soc", "2gb", "np6"
        elif code in _ENTRY_2GB_SOC4:
            family, npu, cp, ram_tier, sniffer_syntax = "entry_2gb", "soc4", "soc", "2gb", "np6"
        elif code in _SOC4_4GB:
            family, npu, cp, ram_tier, sniffer_syntax = "soc4_4gb", "soc4", "soc", "4gb", "np6"
        elif code in _SP5_SERIES:
            family, npu, cp, ram_tier, sniffer_syntax = "sp5", "sp5", "soc", "8gb+", "np7"
        elif code in _NP6XLITE_SERIES:
            family, npu, cp, ram_tier, sniffer_syntax = "np6xlite", "np6xlite", "cp9", "8gb+", "np6"
        elif code in _NP7_SERIES:
            family, npu, cp, ram_tier, sniffer_syntax = "np7", "np7", "cp9", "8gb+", "np7"
        elif code in _NP6LITE_SERIES:
            family, npu, cp, ram_tier, sniffer_syntax = "np6", "np6lite", "cp9", "8gb+", "np6"
        elif code in _NP6_SERIES:
            family, npu, cp, ram_tier, sniffer_syntax = "np6", "np6", "cp9", "8gb+", "np6"

    proxy_removed_2gb = ram_tier == "2gb" and ver_tuple is not None and ver_tuple >= (7, 4, 4)
    return FortiGateHWProfile(
        model=_normalized_model_label(raw_model, code, is_vm),
        version=ver_str,
        family=family,
        npu=npu,
        cp=cp,
        ram_tier=ram_tier,
        is_vm=is_vm,
        proxy_removed_2gb=proxy_removed_2gb,
        sniffer_syntax=sniffer_syntax,
    )


def detect_from_config(config_text: Optional[str]) -> FortiGateHWProfile:
    """Resolve hardware capabilities directly from a raw FortiOS configuration backup."""
    model, version = parse_config_header(config_text)
    return resolve_profile(model=model, version=version)


def _notes_for(profile: FortiGateHWProfile, lang: str) -> list[str]:
    en = (lang or "it").strip().lower().startswith("en")
    if profile.family == "entry_2gb":
        notes = [
            (
                "2GB RAM / SoC hardware: avoid generic 'default' or 'high_security' IPS sensors "
                "and keep flow-based inspection to prevent conserve mode."
                if en else
                "Hardware SoC con 2GB di RAM: evitare sensori IPS generici ('default'/'high_security') "
                "e mantenere l'ispezione flow-based per prevenire il conserve mode."
            )
        ]
        if profile.proxy_removed_2gb:
            notes.append(
                "FortiOS 7.4.4+ on 2GB models drops proxy-based inspection: convert proxy policies to flow."
                if en else
                "Su modelli 2GB con FortiOS 7.4.4+ la modalita' proxy non e' supportata: usare flow."
            )
        return notes
    if profile.family == "vm":
        return [
            (
                "FortiGate-VM has no hardware NPU/CP ASIC: NPU offload and 'diagnose npu sniffer' "
                "do not apply; size vCPU/RAM and prefer flow-based inspection."
                if en else
                "FortiGate-VM non dispone di NPU/CP hardware: offload NPU e 'diagnose npu sniffer' "
                "non si applicano; dimensionare vCPU/RAM e preferire la modalita' flow."
            )
        ]
    if profile.family == "np7":
        return [
            (
                "NP7 + CP9 architecture: IPS/AppCtrl sessions offload to NP7 after initial inspection; "
                "place high-volume backups in /32 bypass policies with auto-asic-offload enabled."
                if en else
                "Architettura NP7 + CP9: le sessioni IPS/AppCtrl vengono scaricate su NP7 dopo l'ispezione "
                "iniziale; isolare i backup ad alto volume in policy di bypass /32 con offload attivo."
            )
        ]
    if profile.family == "sp5":
        return [
            (
                "SP5 ASIC architecture: use flow-based single-pass inspection with targeted IPS sensors "
                "and /32 bypass policies for bulk backup traffic."
                if en else
                "Architettura SP5 ASIC: usare ispezione flow-based single-pass con sensori IPS mirati "
                "e policy di bypass /32 per i flussi bulk di backup."
            )
        ]
    if profile.family in ("np6", "np6xlite", "soc4_4gb"):
        return [
            (
                "NPU/SPU hardware offload active: keep auto-asic-offload enabled, prefer flow-based "
                "inspection, and move bulk backup/DB sync flows to /32 bypass rules."
                if en else
                "Offload hardware NPU/SPU attivo: mantenere auto-asic-offload abilitato, preferire "
                "modalita' flow e spostare backup/repliche DB su regole di bypass /32."
            )
        ]
    return [
        (
            "Model not recognized from header: apply flow-based inspection and targeted IPS sensors "
            "with explicit source/destination bypass policies for bulk traffic."
            if en else
            "Modello non riconosciuto dall'header: applicare ispezione flow-based, sensori IPS mirati "
            "e policy di bypass puntuali per il traffico ad alto volume."
        )
    ]


def profile_to_dict(profile: FortiGateHWProfile, lang: str = "it") -> Dict[str, Any]:
    """Serialize ``FortiGateHWProfile`` with concise localized advisory notes."""
    data: Dict[str, Any] = asdict(profile)
    data["notes"] = _notes_for(profile, lang)
    return data
