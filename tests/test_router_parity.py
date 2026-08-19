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
    ALLOWED_NEW_PREFIXES = ("/api/observability", "/api/settings/app", "/api/settings/netsec-audit", "/api/settings/flow-siem-preview", "/api/settings/audit-checklist", "/api/flow-siem", "/api/arp", "/api/ai", "/api/provisioner", "/api/mcp", "/api/sites", "/api/command-jobs", "/api/agent", "/api/fortigate/{ip}/firewall", "/api/fortigate/targets", "/api/identities", "/api/config-analyzer/convert", "/api/redundancy", "/api/netsec-audit", "/api/audit-checklist", "/api/incidents", "/api/settings/incidents", "/api/diagnose", "/api/fortigate/{ip}/system", "/api/fortigate/{ip}/vpn", "/api/fortigate/{ip}/sdwan", "/api/endpoints", "/api/settings/snmp-defaults", "/api/settings/ping-monitor", "/api/ping-monitor", "/api/settings/ui-variant", "/api/mac/port-control", "/api/wlc", "/api/scan-verify", "/api/version")

    def test_no_unexpected_new_paths(self):
        new = [p for p in self.current["paths"]
               if p not in self.golden["paths"]
               and not p.startswith(self.ALLOWED_NEW_PREFIXES)]
        self.assertEqual(new, [], f"endpoint aggiunti fuori dai domini attesi: {new}")

    # Operazioni la cui DESCRIZIONE è cambiata per estensioni volute, a
    # parametri e risposta invariati per i client esistenti.
    ALLOWED_CHANGED_OPERATIONS = (
        ("delete", "/api/fortigate/{ip}/sessions"),
        # Il report Port-channel ora unisce due sorgenti (configurazione per i
        # membri, SNMP per lo stato) e aggiunge campi: nessun campo rimosso.
        ("get", "/api/portchannels"),
        # Rinomina/eliminazione tenant sono passate a require_admin: la voce di
        # nav "Gestione Tenant" e' requires-admin e un gate solo lato UI sarebbe
        # cosmetico. Cambia SOLO la descrizione (la docstring che motiva il
        ("post", "/api/groups/rename"),
        ("post", "/api/groups/delete"),
        ("get", "/api/mac/locate"),
    )

    ALLOWED_ADDED_OPERATIONS = (
        ("delete", "/api/fortigate/{ip}/sessions"),
    )

    def test_migrated_operations_identical(self):
        for path, ops in self.golden["paths"].items():
            if not path.startswith(MIGRATED_PREFIXES):
                continue
            self.assertIn(path, self.current["paths"])
            cur_ops = self.current["paths"][path]
            allowed_added = {m for m, p in self.ALLOWED_ADDED_OPERATIONS if p == path}
            self.assertEqual(set(ops), set(cur_ops) - allowed_added, f"metodi diversi su {path}")
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
    # FgtLogQuerySchema ha guadagnato log_type/log_subtype/cli_category: i
    # parametri esistevano già in get_traffic_logs ma nessuno schema li
    # trasportava, quindi la categoria di log era irraggiungibile via HTTP.
    # Aggiunta puramente additiva (campi opzionali con i default storici):
    # nessun client esistente cambia comportamento.
    ALLOWED_CHANGED_SCHEMAS = ("FgtTokenSchema", "AgentDeviceSchema", "DeviceSchema",
                               "FgtLogQuerySchema")

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

    # NEW_PREFIXES filtra entrambi i lati del confronto, quindi copre anche
    # i percorsi RIMOSSI: /api/settings/fortigate-preview era il flag della
    # tab FortiGate in anteprima, sparito quando la tab è diventata normale.
    NEW_PREFIXES = ("/api/redundancy", "/api/agent/syslog", "/api/observability/protocol-distribution", "/api/sites/{site_id}/agent", "/api/settings/netsec-audit", "/api/settings/flow-siem-preview", "/api/settings/audit-checklist", "/api/settings/fortigate-preview", "/api/flow-siem", "/api/wlc/{ip}/diagnose-client", "/api/ws-token", "/api/wlc/{ip}/wlan-summary", "/api/netsec-audit", "/api/audit-checklist", "/api/incidents", "/api/settings/incidents", "/api/observability/events", "/api/ai/conversations", "/api/diagnose", "/api/agent/arp", "/api/endpoints",
                    "/api/fortigate/{ip}/firewall/policies-with-stats", "/api/fortigate/{ip}/system", "/api/fortigate/{ip}/vpn", "/api/fortigate/{ip}/sdwan",
                    "/api/fortigate/{ip}/firewall/address-groups", "/api/fortigate/{ip}/firewall/service-groups", "/api/fortigate/{ip}/firewall/vips", "/api/fortigate/{ip}/firewall/ip-pools", "/api/fortigate/{ip}/firewall/security-profiles",
                    "/api/settings/snmp-defaults",
                    # Monitor ping continuo: configurazione (sotto /api/settings)
                    # e stato letto dal tab Impostazioni.
                    "/api/settings/ping-monitor", "/api/ping-monitor", "/api/settings/ui-variant",
                    "/api/observability/prune-logs",
                    "/api/mac/port-control", "/api/wlc/{ip}/ap-summary", "/api/wlc/{ip}/client-summary", "/api/wlc/{ip}/client/{mac}", "/api/wlc/{ip}/rogue-aps", "/api/wlc/{ip}/status", "/api/wlc/{ip}/overview",
                    # La scansione non tenta piu' il login: l'autenticazione e'
                    # diventata un passo esplicito e opzionale, su un endpoint suo.
                    "/api/scan-verify", "/api/version")
    # Come NEW_PREFIXES, filtra entrambi i lati: copre anche FortigatePreviewSchema,
    # rimosso insieme al flag di preview /api/settings/fortigate-preview.
    NEW_SCHEMAS = ("GroupWrite", "MemberWrite", "AgentSyslogBatchSchema", "AgentSyslogItemSchema", "AgentConfigUpdateSchema", "AgentInventorySaveSchema", "AlertSuppressSchema", "VisioExportSchema", "FlowControlSchema", "AgentMacSchema", "AgentItemSchema", "AgentMacItemSchema", "NetSecAuditSchema", "ReportPdfSchema", "CreateEngagementRequest", "UpdateEngagementMetadataRequest", "UpdateItemAssessmentRequest", "AddEvidenceRequest", "TemplateItemRequest", "AiConversationSchema", "AiConversationUpdateSchema", "ClientDiagnosisSchema", "AgentArpSchema", "AgentArpCollection", "FortigatePreviewSchema",
                   # Bounce della porta di accesso trovata dalla diagnosi: unica
                   # scrittura della tab, rotta sotto /api/diagnose (già in NEW_PREFIXES).
                   "PortBounceSchema",
                    # Default SNMP di tenant: schema nuovo per le rotte sotto
                    # /api/settings/snmp-defaults (già in NEW_PREFIXES).
                    "SnmpDefaultSchema",
                    # Monitor ping continuo: schema della configurazione
                    # (enabled + interval_seconds) per POST
                    # /api/settings/ping-monitor (già in NEW_PREFIXES).
                    "PingMonitorSchema", "UiVariantSchema", "PortControlSchema", "ShunIpSchema", "PruneLogsSchema",
                    # Rilevamento del gateway via traceroute: schema del corpo
                    # di POST /api/diagnose/traceroute-gateway (rotta sotto
                    # /api/diagnose, gia' in NEW_PREFIXES).
                    "TracerouteGatewaySchema",
                    # Corpo di POST /api/scan-verify (rotta gia' in NEW_PREFIXES):
                    # IP selezionati + vendor + identita' con cui provare il login.
                    "ScanVerifyRequest")
    # v7: /anomalies ora restituisce INCIDENTI invece di singoli eventi
    # correlati. Parametri e forma della risposta restano quelli storici (li
    # consumano il tab Flussi e il tool MCP), è cambiata la descrizione.
    ALLOWED_CHANGED_OPERATIONS = (
        ("delete", "/api/fortigate/{ip}/sessions"),
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
        # Filtro telemetria: query param ``exclude_telemetry`` opzionale con
        # default False. Aggiunta additiva — omettendolo il comportamento è
        # quello storico — ma i parametri dell'operazione cambiano.
        # Copertura: test_observability_api.TestTopTalkers
        # .test_telemetry_filter_excludes_collector_ports.
        ("get", "/api/observability/top"),
        ("get", "/api/observability/flowgraph"),
        # Origine MAC: query param ``tenant`` opzionale, e la risposta ora ha
        # una voce per (MAC, tenant) invece che per MAC. Vedi
        # TestRouterParity.ALLOWED_CHANGED_OPERATIONS per il motivo.
        ("get", "/api/mac/locate"),
        # SIEM: query param ``tenant`` opzionale per lo scoping, sulle tre
        # rotte di lettura. Aggiunta additiva — omettendolo il comportamento
        # e' quello storico — ma i parametri dell'operazione cambiano.
        ("get", "/api/flow-siem/events"),
        ("get", "/api/flow-siem/histogram"),
        ("get", "/api/flow-siem/facets"),
    )

    ALLOWED_ADDED_OPERATIONS = (
        ("delete", "/api/fortigate/{ip}/sessions"),
    )

    # FgtLogQuerySchema: vedi TestRouterParity.ALLOWED_CHANGED_SCHEMAS.
    # SubnetScanRequest: la scansione e' diventata solo scoperta (ping + porte
    # TCP configurabili): vendor, group, auto_add e use_default_creds sono
    # rimossi, il login vive in /api/scan-verify con un'identita' esplicita.
    # SiteSchema/SiteUpdateSchema: jump-host-sites Task 5 adds jump_host,
    # jump_port, jump_identity (all optional) so /api/sites can create and
    # update bastion-mode sites; no existing field removed or retyped.
    # SwitchProvisionSSHSchema/FortiGateProvisionSSHSchema: jump-host-sites adds
    # ssh_site (optional, defaults to ""), the site id of a day-0 target that is
    # not in the inventory yet, so the push can be tunnelled through a bastion;
    # no existing field removed or retyped.
    ALLOWED_CHANGED_SCHEMAS = ("AgentDeviceSchema", "DeviceSchema", "FgtLogQuerySchema", "IdentitySchema",
                               "SubnetScanRequest", "AiGenerateConfigSchema",
                               "SiteSchema", "SiteUpdateSchema",
                               "SwitchProvisionSSHSchema", "FortiGateProvisionSSHSchema")

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
            allowed_added = {m for m, p in self.ALLOWED_ADDED_OPERATIONS if p == path}
            self.assertEqual(set(ops), set(cur_ops) - allowed_added, f"metodi diversi su {path}")
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
