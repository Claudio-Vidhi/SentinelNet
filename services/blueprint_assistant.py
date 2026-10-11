# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Blueprint assistant (spec 2026-10-11 blueprint-assistant): draft operations
from the operator's text («Descrivi la rete») and from the configuration
backups («Ricava dalle configurazioni»). Everything lands in the draft through
blueprint.add_ops with source «assistant»: nothing here applies a draft."""
import json

from fastapi import HTTPException

from ai import classification_assist, config_analyzer
from services import blueprint, blueprint_derive, blueprint_model, inventory_manager, inventory_store

MAX_TEXT = 4000

_OPS = """Operations (JSON objects):
- {"op": "create_location", "ref": "+1", "name": str, "role": "hq|branch|datacenter|warehouse|other", "subnets": [CIDR], "gateway": IPv4 or ""}
  "ref" starts with "+" and names the new location in later operations of the same answer.
- {"op": "update_location", "id": id, "fields": {"name"?, "role"?, "subnets"?, "gateway"?}}  ("subnets" replaces the whole list)
- {"op": "add_subnet", "id": id, "subnet": CIDR}
- {"op": "set_gateway", "id": id, "ip": IPv4 of a device of that location}
- {"op": "delete_location", "id": id}
- {"op": "add_link", "a": id or ref, "b": id or ref, "kind": "vpn|wan|mpls|lan", "note": str}
- {"op": "remove_link", "id": a link id of the model}
"id" is a location id of the current model or a "+ref" created earlier in the same answer."""


def _view(st: dict) -> dict:
    return st["preview"] or {"locations": st["locations"], "links": st["links"]}


def _model(st: dict) -> str:
    view = _view(st)
    return json.dumps({
        "locations": [{"id": k, "name": l["name"], "role": l["role"], "subnets": l["subnets"],
                       "gateway": l.get("gateway") or ""} for k, l in sorted(view["locations"].items())],
        "links": [{"id": k, "a": v["a"], "b": v["b"], "kind": v["kind"]} for k, v in sorted(view["links"].items())],
    }, ensure_ascii=False)


def _conventions(instructions: str) -> str:
    return f"\n\nConventions of this organization (follow them):\n{instructions}" if instructions else ""


def _chat(messages: list) -> str:
    from routers.ai import chat_with_active_profile
    return chat_with_active_profile(messages)[0]


def _parse(reply: str):
    data = classification_assist._extract_json(reply)
    if data is None or not isinstance(data.get("ops"), list):
        raise ValueError('la risposta non è un oggetto JSON con una lista "ops"')
    for i, op in enumerate(data["ops"]):
        if not isinstance(op, dict):
            raise ValueError(f"operazione {i + 1}: non è un oggetto")
    return data["ops"], str(data.get("notes") or "")


def describe(org: str, text: str, by: str) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("Descrivi la rete: il testo è vuoto.")
    if len(text) > MAX_TEXT:
        raise ValueError(f"Testo troppo lungo: massimo {MAX_TEXT} caratteri.")
    st = blueprint.state(org)
    before = len(st["draft"]["ops"]) if st["draft"] else 0
    system = ("You turn an operator's description of a network into draft operations for the Network "
              "Blueprint of ONE organization in SentinelNet. A human reviews the draft before anything "
              "is applied.\n\n" + _OPS + "\n\nRules: change only this organization; never delete a location "
              "or a link unless the text asks for it; subnets in CIDR; do not repeat what the model already "
              "has." + _conventions(st["instructions"]) + '\n\nReply with one JSON object and nothing else: '
              '{"ops": [...], "notes": "short remarks for the operator, in the operator\'s language"}.')
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": f"Current model:\n{_model(st)}\n\nOperator:\n{text}"}]
    error = ""
    for _attempt in range(2):
        answer = _chat(messages)
        try:
            ops, notes = _parse(answer)
            return {"added": len(ops), "notes": notes, "state": blueprint.add_ops(org, ops, "assistant", by)}
        except blueprint_model.OpError as e:
            # apply_ops numbers the whole draft; the LLM knows only its own ops.
            error = f"operazione {e.index - before + 1}: {e.reason}" if e.index >= before else str(e)
        except ValueError as e:
            error = str(e)
        # A new list each time: the first call's messages stay as they were sent.
        messages = messages + [{"role": "assistant", "content": answer},
                               {"role": "user", "content": f"Error: {error}. Fix it and reply with the JSON object only."}]
    raise ValueError(f"L'assistente non ha prodotto una bozza valida: {error}")


def _renames(st: dict, derived: list) -> list:
    """Optional AI pass of derive: only update_location on existing locations,
    only name and role; anything else is dropped before validation."""
    view = _view(st)
    system = ("You review locations of ONE organization in SentinelNet. From the model and the operations "
              "derived from its configuration backups, propose better location names and roles. You may only "
              'answer {"op": "update_location", "id": id, "fields": {"name"?, "role"?}} operations on the '
              "locations listed; roles: hq|branch|datacenter|warehouse|other." + _conventions(st["instructions"])
              + '\n\nReply with one JSON object and nothing else: {"ops": [...]}.')
    answer = _chat([{"role": "system", "content": system},
                    {"role": "user", "content": f"Current model:\n{_model(st)}\n\nDerived operations:\n"
                                                f"{json.dumps(derived, ensure_ascii=False)}"}])
    data = classification_assist._extract_json(answer) or {}
    out = []
    for op in data.get("ops") if isinstance(data.get("ops"), list) else []:
        if not isinstance(op, dict) or op.get("op") != "update_location" or op.get("id") not in view["locations"]:
            continue
        fields = op.get("fields") if isinstance(op.get("fields"), dict) else {}
        fields = {k: v for k, v in fields.items() if k in ("name", "role")}
        if fields:
            out.append({"op": "update_location", "id": op["id"], "fields": fields})
    return out


def derive(org: str, by: str, use_ai: bool) -> dict:
    st = blueprint.state(org)
    view = _view(st)
    devices = [d for d in inventory_manager.get_all_devices() if d.get("Group") == org]
    analyses = {}
    for d in devices:
        if d.get("Location") in view["locations"]:
            try:
                analyses[d["IP"]] = config_analyzer.analyze_device(d["IP"], org)
            except Exception:  # an unreadable backup is counted in the notes, not fatal for the others
                analyses[d["IP"]] = {}
    ops, notes = blueprint_derive.derive(view, devices, analyses)
    if not ops:
        raise ValueError(" ".join(["Nessuna proposta dalle configurazioni."] + notes))
    # The deterministic ops go in first: the AI pass failing never loses them.
    out = blueprint.add_ops(org, ops, "assistant", by)
    added = len(ops)
    if use_ai and st["ai_available"]:
        try:
            renames = _renames(out, ops)
            if renames:
                out = blueprint.add_ops(org, renames, "assistant", by)
                added += len(renames)
        except (HTTPException, ValueError) as e:
            notes.append("Passaggio AI non riuscito, restano le proposte dalle configurazioni: "
                         f"{getattr(e, 'detail', None) or e}")
    return {"added": added, "notes": "\n".join(notes), "state": out}


def set_instructions(org: str, text: str) -> str:
    text = (text or "").strip()
    if len(text) > MAX_TEXT:
        raise ValueError(f"Istruzioni troppo lunghe: massimo {MAX_TEXT} caratteri.")
    with inventory_manager._db() as conn:
        inventory_store.write_instructions(conn, org, text)
    return text
