# -*- coding: utf-8 -*-
"""Parity test del refactor router (fase 2.6): lo schema OpenAPI post-refactor
deve coincidere con lo snapshot golden pre-refactor (tests_data/
openapi_golden.json) per percorsi, metodi, parametri, request/response.
Unica differenza ammessa: i ``tags`` (i router ne aggiungono).

Harness riusabile: aggiungere prefissi a MIGRATED_PREFIXES man mano che altri
domini vengono estratti (6.6)."""

import json
import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_parity_"))

import app_server  # noqa: E402

from typing import Any

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(_REPO_ROOT, "tests_data", "openapi_golden.json")

# Prefissi degli endpoint già migrati nei router modulari.
MIGRATED_PREFIXES = ("/api/fortigate", "/api/wlc", "/api/auth", "/api/users", "/api/local-devices", "/api/export", "/api/add-device", "/api/delete-device", "/api/rename-device", "/api/import-csv", "/api/promote-device", "/api/reassign-device", "/api/groups", "/api/vendors", "/api/models", "/api/device-categories", "/api/device-classification", "/api/settings", "/api/topology", "/api/network-map", "/api/portchannels", "/api/map/export", "/api/run-triage", "/api/triage", "/api/ping", "/api/send-command", "/api/bulk-command", "/api/ws-token", "/api/ws-terminal", "/api/download-backup", "/api/search", "/api/mac", "/api/config-analyzer")

def _clean_anyof(obj: Any) -> Any:
    if isinstance(obj, dict):
        if "anyOf" in obj and len(obj["anyOf"]) == 2 and any(isinstance(x, dict) and x.get("type") == "null" for x in obj["anyOf"]):
            non_null = [x for x in obj["anyOf"] if isinstance(x, dict) and x.get("type") != "null"][0]
            res = {k: v for k, v in obj.items() if k != "anyOf"}
            res.update(non_null)
            return _clean_anyof(res)
        return {k: _clean_anyof(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_anyof(x) for x in obj]
    return obj


def _normalize(op: dict) -> dict:
    out = dict(op)
    out.pop("tags", None)  # i router aggiungono tag: differenza voluta
    return _clean_anyof(out)


class TestRouterParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(GOLDEN, encoding="utf-8") as f:
            cls.golden = json.load(f)
        cls.current = app_server.app.openapi()

    def test_all_golden_paths_still_exist(self):
        missing = [p for p in self.golden["paths"] if p not in self.current["paths"]]
        self.assertEqual(missing, [], f"endpoint spariti dal refactor: {missing}")

    # Percorsi NUOVI legittimi (funzionalità aggiunte dopo lo snapshot golden).
    ALLOWED_NEW_PREFIXES = ("/api/observability", "/api/settings/app", "/api/settings/fortigate-preview", "/api/settings/netsec-audit", "/api/settings/flow-siem-preview", "/api/settings/audit-checklist", "/api/flow-siem", "/api/arp", "/api/ai", "/api/provisioner", "/api/mcp", "/api/sites", "/api/command-jobs", "/api/agent", "/api/fortigate/{ip}/firewall", "/api/fortigate/targets", "/api/identities", "/api/config-analyzer/convert", "/api/redundancy", "/api/netsec-audit", "/api/audit-checklist", "/api/incidents", "/api/settings/incidents")

    def test_no_unexpected_new_paths(self):
        new = [p for p in self.current["paths"]
               if p not in self.golden["paths"]
               and not p.startswith(self.ALLOWED_NEW_PREFIXES)]
        self.assertEqual(new, [], f"endpoint aggiunti fuori dai domini attesi: {new}")

    # Operazioni la cui DESCRIZIONE è cambiata per estensioni volute, a
    # parametri e risposta invariati per i client esistenti.
    ALLOWED_CHANGED_OPERATIONS = (
        # Il report Port-channel ora unisce due sorgenti (configurazione per i
        # membri, SNMP per lo stato) e aggiunge campi: nessun campo rimosso.
        ("get", "/api/portchannels"),
        # Rinomina/eliminazione tenant sono passate a require_admin: la voce di
        # nav "Gestione Tenant" e' requires-admin e un gate solo lato UI sarebbe
        # cosmetico. Cambia SOLO la descrizione (la docstring che motiva il
        # vincolo); parametri e risposta sono invariati, cambia chi puo'
        # chiamarli. Copertura: test_rbac_scope
        # .test_tenant_rename_and_delete_are_admin_only.
        ("post", "/api/groups/rename"),
        ("post", "/api/groups/delete"),
    )

    def test_migrated_operations_identical(self):
        for path, ops in self.golden["paths"].items():
            if not path.startswith(MIGRATED_PREFIXES):
                continue
            self.assertIn(path, self.current["paths"])
            cur_ops = self.current["paths"][path]
            self.assertEqual(set(ops), set(cur_ops), f"metodi diversi su {path}")
            for method, op in ops.items():
                if (method, path) in self.ALLOWED_CHANGED_OPERATIONS:
                    continue
                self.assertEqual(
                    json.dumps(_normalize(op), sort_keys=True),
                    json.dumps(_normalize(cur_ops[method]), sort_keys=True),
                    f"contratto cambiato: {method.upper()} {path}",
                )

    # Schemi con estensioni volute dopo lo snapshot golden (nuovi campi opzionali,
    # retrocompatibili): FgtTokenSchema ha guadagnato `name` per il multi-target
    # manager (Task 2, FortiGate LIVE).
    ALLOWED_CHANGED_SCHEMAS = ("FgtTokenSchema", "AgentDeviceSchema", "DeviceSchema")

    def test_migrated_schemas_identical(self):
        golden_schemas = self.golden.get("components", {}).get("schemas", {})
        cur_schemas = self.current.get("components", {}).get("schemas", {})
        for name, schema in golden_schemas.items():
            if not name.startswith(("Fgt",)):
                continue
            if name in self.ALLOWED_CHANGED_SCHEMAS:
                continue
            self.assertIn(name, cur_schemas, f"schema {name} sparito")
            self.assertEqual(
                json.dumps(schema, sort_keys=True),
                json.dumps(cur_schemas.get(name, {}), sort_keys=True),
                f"schema {name} cambiato",
            )


# ---------------------------------------------------------------------------
# Parity test post-destructuring (fase 6.6 finale): verifica che l'OpenAPI
# completa post-estrazione router sia IDENTICA a quella pre-estrazione (salvo
# i tag per-router ed i nuovi endpoint aggiunti legittimamente).
# ---------------------------------------------------------------------------

PRE_DESTRUCTURE = os.path.join(_REPO_ROOT, "tests_data", "openapi_pre_destructure.json")


class TestFullParity(unittest.TestCase):

    NEW_PREFIXES = ("/api/redundancy", "/api/agent/syslog", "/api/observability/protocol-distribution", "/api/sites/{site_id}/agent", "/api/settings/netsec-audit", "/api/settings/flow-siem-preview", "/api/settings/audit-checklist", "/api/flow-siem", "/api/wlc/{ip}/diagnose-client", "/api/ws-token", "/api/wlc/{ip}/wlan-summary", "/api/netsec-audit/scan", "/api/netsec-audit/benchmarks", "/api/audit-checklist", "/api/incidents", "/api/settings/incidents", "/api/observability/events")
    NEW_SCHEMAS = ("GroupWrite", "MemberWrite", "AgentSyslogBatchSchema", "AgentSyslogItemSchema", "AgentConfigUpdateSchema", "AgentInventorySaveSchema", "AlertSuppressSchema", "VisioExportSchema", "FlowControlSchema", "AgentMacSchema", "AgentItemSchema", "AgentMacItemSchema", "NetSecAuditSchema", "CreateEngagementRequest", "UpdateEngagementMetadataRequest", "UpdateItemAssessmentRequest", "AddEvidenceRequest", "TemplateItemRequest")
    # v7: /anomalies ora restituisce INCIDENTI invece di singoli eventi
    # correlati. Parametri e forma della risposta restano quelli storici (li
    # consumano il tab Flussi e il tool MCP), è cambiata la descrizione.
    ALLOWED_CHANGED_OPERATIONS = (
        # Rinomina/eliminazione tenant ora require_admin: cambia solo la
        # descrizione (docstring che motiva il vincolo), parametri e
        # risposta invariati. Chi puo' chiamarli e' coperto da
        # test_rbac_scope.test_tenant_rename_and_delete_are_admin_only.
        ("post", "/api/groups/rename"),
        ("post", "/api/groups/delete"),
        ("post", "/api/agent/heartbeat"),
        ("get", "/api/observability/anomalies"),
        ("post", "/api/observability/anomalies/{event_id}/status"),
        # Poller SNMP: la config accetta la chiave in più ``snmp_poll_s``.
        # Aggiunta puramente additiva — nessun client esistente cambia — ma la
        # descrizione dell'operazione elenca le chiavi ammesse, e quella è
        # cambiata.
        ("post", "/api/observability/config"),
        # Port-channel: stato vivo da SNMP accanto ai membri da configurazione.
        # Campi aggiunti, nessuno rimosso.
        ("get", "/api/portchannels"),
    )

    ALLOWED_CHANGED_SCHEMAS = ("AgentDeviceSchema", "DeviceSchema")

    @classmethod
    def setUpClass(cls):
        with open(PRE_DESTRUCTURE, encoding="utf-8") as f:
            cls.snap = json.load(f)
        cls.current = app_server.app.openapi()

    def test_path_set_identical(self):
        snap_paths = [p for p in self.snap["paths"] if not p.startswith(self.NEW_PREFIXES)]
        cur_paths = [p for p in self.current["paths"] if not p.startswith(self.NEW_PREFIXES)]
        self.assertEqual(sorted(snap_paths), sorted(cur_paths),
                         "l'insieme dei percorsi è cambiato")

    def test_every_operation_identical(self):
        for path, ops in self.snap["paths"].items():
            if path not in self.current["paths"]:
                continue
            cur_ops = self.current["paths"][path]
            self.assertEqual(set(ops), set(cur_ops), f"metodi diversi su {path}")
            for method, op in ops.items():
                if (method, path) in self.ALLOWED_CHANGED_OPERATIONS:
                    continue
                self.assertEqual(
                    json.dumps(_normalize(op), sort_keys=True),
                    json.dumps(_normalize(cur_ops[method]), sort_keys=True),
                    f"contratto cambiato: {method.upper()} {path}",
                )

    def test_every_schema_identical(self):
        snap_schemas = {k: v for k, v in self.snap.get("components", {}).get("schemas", {}).items() if k not in self.NEW_SCHEMAS}
        cur_schemas = {k: v for k, v in self.current.get("components", {}).get("schemas", {}).items() if k not in self.NEW_SCHEMAS}
        self.assertEqual(sorted(snap_schemas), sorted(cur_schemas),
                         "l'insieme degli schemi componenti è cambiato")
        for name, schema in snap_schemas.items():
            if name in self.ALLOWED_CHANGED_SCHEMAS:
                continue
            self.assertEqual(
                json.dumps(schema, sort_keys=True),
                json.dumps(cur_schemas[name], sort_keys=True),
                f"schema {name} cambiato",
            )


if __name__ == "__main__":
    unittest.main()
