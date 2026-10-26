# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""AI-assisted layout of the Schema map, without identities leaving the process.

The LLM sees an anonymous graph: opaque tokens (``n1``, ``z1``), a device
type from a fixed list, a level, link kinds and counts. Never a hostname, IP,
MAC, model, port, VLAN, tenant, site or user-made category name. Tokens are
shuffled per request, so ``n7`` today is not ``n7`` tomorrow.

``egress_check`` is the guarantee, not the builder: every string in the
payload must be a token or a word of the fixed vocabulary, or nothing is sent.

The model answers with rows of tokens; the frontend packs them with the same
code as "Riordina mappa". Pure functions, no I/O: the router does the call.
"""

import json
import random
import re

DEVICE_TYPES = ("firewall", "router", "switch", "wlc", "ap", "server",
                "phone", "camera", "pc", "other")
LINK_KINDS = ("link", "pc", "peer", "keepalive")
GOALS = {
    "min_crossings": "minimise cable crossings between rows",
    "core_center": "put the core switches in the middle of their row",
    "edge_top": "put firewalls and routers in the top row",
    "ap_under_switch": "keep each access point right under the switch it hangs from",
    "group_by_type": "inside a row, keep devices of the same type next to each other",
    "selected_together": "keep the nodes listed in 'selected' next to each other",
}
MAX_NODES = 400
MAX_LINKS = 2000

_TOKEN = re.compile(r"^[nz]\d{1,4}$")
_VOCAB = set(DEVICE_TYPES) | set(LINK_KINDS) | set(GOALS)

SYSTEM_PROMPT = (
    "You arrange the boxes of a network diagram. The diagram is drawn in "
    "rows, top to bottom; each row is packed left to right in the order you "
    "give. Nodes are opaque tokens with a device type; 'level' is the row "
    "they sit in now; 'zone' groups nodes of one site, and zones are drawn "
    "side by side, so only the order inside a zone matters. Follow the goals. "
    "Answer with JSON only, no prose around it: "
    '{"rows": [["n1"], ["n2", "n3"]], "note": "<one short sentence>"}. '
    "Every node must appear exactly once. Use only the tokens given."
)


def build_payload(nodes, links, goals, selected=()):
    """Anonymous graph for the LLM and the token -> id map to read it back.

    ``nodes``: [{"id", "type", "level", "zone"}]; ``links``: [{"a", "b",
    "kind", "count"}]. Ids and zone keys never enter the payload.
    """
    ids = [n["id"] for n in nodes]
    order = random.sample(range(len(ids)), len(ids))
    tok = {ids[i]: f"n{k + 1}" for k, i in enumerate(order)}
    zone_keys = list(dict.fromkeys(str(n.get("zone") or "") for n in nodes))
    random.shuffle(zone_keys)
    ztok = {z: f"z{k + 1}" for k, z in enumerate(zone_keys)}

    out_nodes = sorted((
        {"id": tok[n["id"]],
         "type": n.get("type") if n.get("type") in DEVICE_TYPES else "other",
         "level": int(n.get("level") or 0),
         "zone": ztok[str(n.get("zone") or "")]}
        for n in nodes), key=lambda n: int(n["id"][1:]))
    out_links = [
        {"a": tok[lk["a"]], "b": tok[lk["b"]],
         "kind": lk.get("kind") if lk.get("kind") in LINK_KINDS else "link",
         "count": max(1, int(lk.get("count") or 1))}
        for lk in links if lk["a"] in tok and lk["b"] in tok]
    payload = {
        "goals": [g for g in goals if g in GOALS],
        "nodes": out_nodes,
        "links": out_links,
        "selected": [tok[i] for i in selected if i in tok],
    }
    return payload, {t: i for i, t in tok.items()}


def egress_check(payload):
    """Raise ValueError unless every string in ``payload`` is a token or a
    vocabulary word. Keys are fixed by build_payload; values are what leaks."""
    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            if not (_TOKEN.match(v) or v in _VOCAB):
                raise ValueError("payload contains a value outside the allowed vocabulary")
        elif not isinstance(v, (int, float)):
            raise ValueError("payload contains an unexpected value type")
    walk(payload)


MAX_INSTRUCTION = 300
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b", re.I)
_MAC = re.compile(r"\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b|\b[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}\b", re.I)
# A word that joins letters and digits with - _ or . looks like a hostname
# (sw-core-01, ap_lobby2, fw1.example): refused even when not on the map.
_HOSTLIKE = re.compile(r"\b(?=[\w.-]*[a-z])(?=[\w.-]*\d)[a-z0-9]+(?:[-_.][a-z0-9]+)+\b", re.I)


def check_instruction(text, deny=()):
    """The user's free-text direction, cleaned, or ValueError saying why it
    may not leave: it names something (an address, a hostname-like word, or
    any of ``deny``: the names, ids and sites drawn on the map). The reason
    never repeats the matched value."""
    text = " ".join((text or "").split())
    if len(text) > MAX_INSTRUCTION:
        raise ValueError(f"la direzione supera {MAX_INSTRUCTION} caratteri")
    if not text:
        return ""
    if _IPV4.search(text) or _IPV6.search(text) or _MAC.search(text):
        raise ValueError("la direzione contiene un indirizzo IP o MAC")
    if _HOSTLIKE.search(text):
        raise ValueError("la direzione contiene un nome che sembra un hostname")
    # Three digits or more: a model (9300), a VLAN, a port count. Not sent.
    if re.search(r"\d{3,}", text):
        raise ValueError("la direzione contiene un numero che potrebbe essere un modello o una VLAN")
    low = text.lower()
    for term in deny:
        term = (term or "").strip().lower()
        if len(term) >= 3 and term in low:
            raise ValueError("la direzione nomina un dispositivo o una sede della mappa")
    return text


def build_messages(payload, instruction=""):
    """The two messages sent to the provider: fixed instructions + the graph,
    plus the user's direction when there is one (already through
    check_instruction)."""
    egress_check(payload)
    goals = "; ".join(GOALS[g] for g in payload["goals"]) or GOALS["min_crossings"]
    direction = ("\nUser direction (follow it where the graph allows; devices are "
                 f"named only by type or as 'the selected ones'): {instruction}"
                 if instruction else "")
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Goals: {goals}.{direction}\nGraph: {json.dumps(payload, separators=(',', ':'))}"},
    ]


def parse_reply(text, token_map):
    """Rows of real ids from the model's answer, plus its note.

    Unknown tokens are dropped, a node listed twice keeps its first place, and
    a node the model forgot is not placed (the caller keeps it where it is).
    Raises ValueError when no JSON object with rows can be read.
    """
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        raise ValueError("the AI answer holds no JSON object")
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError as e:
        raise ValueError(f"the AI answer is not valid JSON: {e}") from e
    rows_in = data.get("rows") if isinstance(data, dict) else None
    if not isinstance(rows_in, list):
        raise ValueError("the AI answer has no 'rows' list")
    seen, rows = set(), []
    for row in rows_in:
        if not isinstance(row, list):
            continue
        ids = []
        for t in row:
            i = token_map.get(t) if isinstance(t, str) else None
            if i is not None and i not in seen:
                seen.add(i)
                ids.append(i)
        if ids:
            rows.append(ids)
    if not rows:
        raise ValueError("the AI answer places no known node")
    note = data.get("note") if isinstance(data.get("note"), str) else ""
    return rows, note[:300]
