# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""AI suggestions for the "Dispositivi Scoperti & Classificazione" tab.

Two jobs, each one request regardless of how many devices it covers (free
tiers allow a handful of requests a day, not one per device):

* ``build_messages`` / ``parse_suggestions``: for the devices still waiting
  to be classified, propose category, subcategory, vendor, model and, when the
  current name breaks the tenant's naming convention, a name that follows it.
  The convention is learnt from the tenant's already classified devices.
* ``build_model_messages`` / ``parse_model_merges``: spot duplicates in the
  per-vendor model catalogue (``WS-C2960X-48FPD-L`` vs ``C2960X-48FPD``).

Everything here is a proposal. Nothing is written to a device record until
the user applies it through the normal save path; the parsers only keep
values that the rest of the app can accept (a known category, a subcategory
of that category, a hostname-safe name, models already in the catalogue).

No IP addresses are sent: the name, the model and who the device is cabled
to say what it is; the address says nothing more and is customer data.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

# One request has to fit a free tier's tokens-per-minute budget: a queue
# longer than this is done in more runs, the UI says how many are left.
MAX_DEVICES_PER_RUN = 50
# Classified devices shown per tenant as naming examples.
MAX_EXAMPLES_PER_TENANT = 60
MAX_NEIGHBOURS = 6

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

_LANG_NAMES = {"it": "Italian", "en": "English"}


def _clip(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def _extract_json(text: str) -> Optional[dict]:
    """First JSON object in a model reply, tolerating ```json fences and prose."""
    if not text:
        return None
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


# --- Classification + naming ---------------------------------------------------

def build_messages(queue: List[dict], examples: Dict[str, List[dict]],
                   categories: Dict[str, dict], lang: str = "it") -> List[dict]:
    """Prompt for one run. ``queue`` items: id, name, tenant, vendor, model,
    version, neighbours[{device, category, own_port}], where own_port is this
    device's port facing that neighbour. ``examples``: tenant -> classified
    devices [{name, category, subcategory, model, ha_group}]."""
    cat_lines = []
    for key, c in categories.items():
        subs = ", ".join(c.get("subcategories") or []) or "-"
        cat_lines.append(f"- {key} ({c.get('label', key)}); subcategories: {subs}")
    system = (
        "You classify network devices discovered via CDP/LLDP for a network "
        "inventory. Use ONLY the category keys and subcategories listed; leave a "
        "field empty when unsure instead of guessing. Infer the role from the "
        "model string, the software version and the neighbours (a device cabled "
        "to a core switch is usually access/distribution, an AP-like model is an "
        "access point). For each tenant, infer the naming convention from its "
        "classified devices; propose a new name ONLY when the device's current "
        "name does not follow that convention, otherwise return an empty name. "
        "A proposed name must be a hostname: letters, digits, '.', '-', '_'. "
        "Spot redundancy pairs (HA firewalls, stacked or VSS/vPC switches, WLC "
        "pairs): devices of the same model and version whose names differ only "
        "by a final A/B, 1/2, 01/02 or primary/secondary marker, often cabled to "
        "the same neighbours. The partner may be a device to classify or an "
        "already classified one. Give every member the same ha_group: reuse the "
        "partner's ha_group when it already has one, otherwise the shared part "
        "of the names (e.g. FW-CORE for FW-COREA/FW-COREB). Leave ha_group empty "
        "when there is no clear partner. ha_group uses the same characters as a "
        "hostname.\n\n"
        "Categories:\n" + "\n".join(cat_lines) + "\n\n"
        "Answer with ONE JSON object and nothing else:\n"
        '{"conventions": {"<tenant>": "<one sentence describing the pattern>"},\n'
        ' "suggestions": [{"id": "<device id>", "category": "<key>", '
        '"subcategory": "", "vendor": "", "model": "", "name": "", "ha_group": "", '
        '"confidence": 0-100, "reason": "<one short sentence>"}]}\n'
        f"Write conventions and reasons in {_LANG_NAMES.get(lang, 'Italian')}."
    )
    payload = {
        "classified_examples_by_tenant": {
            t: rows[:MAX_EXAMPLES_PER_TENANT] for t, rows in examples.items()},
        "devices_to_classify": queue[:MAX_DEVICES_PER_RUN],
    }
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
    ]


def _canon_sub(sub: str, allowed: List[str]) -> str:
    low = sub.lower()
    return next((s for s in allowed if s.lower() == low), "")


def parse_suggestions(text: str, queue_ids, categories: Dict[str, dict]
                      ) -> Tuple[Dict[str, dict], Dict[str, str]]:
    """Validated suggestions keyed by device id, plus conventions per tenant.

    Drops anything the app could not store: unknown ids, category keys that
    do not exist, subcategories of another category, names that are not
    hostnames. A reply that is not JSON yields nothing rather than an error,
    the caller says "no usable suggestion".
    """
    data = _extract_json(text) or {}
    ids = set(queue_ids)
    cat_keys = {k.lower(): k for k in categories}
    out: Dict[str, dict] = {}
    for item in data.get("suggestions") or []:
        if not isinstance(item, dict):
            continue
        dev_id = str(item.get("id") or "")
        if dev_id not in ids:
            continue
        category = cat_keys.get(_clip(item.get("category"), 40).lower(), "")
        allowed = (categories.get(category) or {}).get("subcategories") or []
        sub = _canon_sub(_clip(item.get("subcategory"), 60), allowed) if category else ""
        name = _clip(item.get("name"), 63)
        if name and not _NAME_RE.match(name):
            name = ""
        ha_group = _clip(item.get("ha_group"), 63)
        if ha_group and not _NAME_RE.match(ha_group):
            ha_group = ""
        try:
            confidence = max(0, min(100, int(item.get("confidence") or 0)))
        except (TypeError, ValueError):
            confidence = 0
        suggestion = {
            "category": category,
            "subcategory": sub,
            "vendor": _clip(item.get("vendor"), 60),
            "model": _clip(item.get("model"), 80),
            "name": name,
            "ha_group": ha_group,
            "confidence": confidence,
            "reason": _clip(item.get("reason"), 300),
        }
        if any(suggestion[k] for k in ("category", "vendor", "model", "name", "ha_group")):
            out[dev_id] = suggestion
    conventions = {
        _clip(t, 80): _clip(c, 300)
        for t, c in (data.get("conventions") or {}).items()
        if isinstance(c, str) and c.strip()
    } if isinstance(data.get("conventions"), dict) else {}
    return out, conventions


# --- Model catalogue -----------------------------------------------------------

def build_model_messages(models: Dict[str, List[str]], lang: str = "it") -> List[dict]:
    system = (
        "You review a catalogue of network device models, grouped by vendor. "
        "Find entries of the SAME vendor that name the same hardware model in "
        "different spellings (order codes with or without the WS-/FG- prefix or "
        "a power/licence suffix, case, spaces, hyphens). Do not merge different "
        "models (24 vs 48 ports, PoE vs non-PoE). For each group choose as "
        "canonical the most complete official spelling already in the list.\n"
        "Answer with ONE JSON object and nothing else:\n"
        '{"merges": [{"vendor": "<vendor key>", "canonical": "<model>", '
        '"duplicates": ["<model>", ...], "reason": "<one short sentence>"}]}\n'
        f"Write reasons in {_LANG_NAMES.get(lang, 'Italian')}."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(models, ensure_ascii=False)},
    ]


def parse_model_merges(text: str, models: Dict[str, List[str]]) -> List[dict]:
    """Only merges between models that exist, within one vendor, canonical
    excluded from its own duplicates."""
    data = _extract_json(text) or {}
    out = []
    for item in data.get("merges") or []:
        if not isinstance(item, dict):
            continue
        vendor = _clip(item.get("vendor"), 60).lower()
        known = models.get(vendor) or []
        canonical = _clip(item.get("canonical"), 80)
        if canonical not in known:
            continue
        dups = [d for d in dict.fromkeys(item.get("duplicates") or [])
                if isinstance(d, str) and d in known and d != canonical]
        if dups:
            out.append({"vendor": vendor, "canonical": canonical, "duplicates": dups,
                        "reason": _clip(item.get("reason"), 300)})
    return out
