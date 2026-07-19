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

GOLDEN = os.path.join(os.path.dirname(__file__), "tests_data", "openapi_golden.json")

# Prefissi degli endpoint già migrati nei router modulari.
MIGRATED_PREFIXES = ("/api/fortigate", "/api/wlc", "/api/auth", "/api/users", "/api/local-devices", "/api/export", "/api/add-device", "/api/delete-device", "/api/rename-device", "/api/import-csv", "/api/promote-device", "/api/reassign-device", "/api/groups", "/api/vendors", "/api/models", "/api/device-categories", "/api/device-classification", "/api/settings", "/api/topology", "/api/network-map", "/api/portchannels", "/api/map/export", "/api/run-triage", "/api/triage", "/api/ping", "/api/send-command", "/api/bulk-command", "/api/ws-token", "/api/ws-terminal", "/api/download-backup", "/api/search", "/api/mac", "/api/config-analyzer")


def _normalize(op: dict) -> dict:
    out = dict(op)
    out.pop("tags", None)  # i router aggiungono tag: differenza voluta
    return out


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
    ALLOWED_NEW_PREFIXES = ("/api/observability", "/api/settings/app", "/api/settings/fortigate-preview", "/api/arp", "/api/ai", "/api/provisioner", "/api/mcp", "/api/sites", "/api/command-jobs", "/api/agent", "/api/fortigate/{ip}/firewall", "/api/identities", "/api/config-analyzer/convert")

    def test_no_unexpected_new_paths(self):
        new = [p for p in self.current["paths"]
               if p not in self.golden["paths"]
               and not p.startswith(self.ALLOWED_NEW_PREFIXES)]
        self.assertEqual(new, [], f"endpoint aggiunti fuori dai domini attesi: {new}")

    def test_migrated_operations_identical(self):
        for path, ops in self.golden["paths"].items():
            if not path.startswith(MIGRATED_PREFIXES):
                continue
            self.assertIn(path, self.current["paths"])
            cur_ops = self.current["paths"][path]
            self.assertEqual(set(ops), set(cur_ops), f"metodi diversi su {path}")
            for method, op in ops.items():
                self.assertEqual(
                    json.dumps(_normalize(op), sort_keys=True),
                    json.dumps(_normalize(cur_ops[method]), sort_keys=True),
                    f"contratto cambiato: {method.upper()} {path}",
                )

    def test_migrated_schemas_identical(self):
        golden_schemas = self.golden.get("components", {}).get("schemas", {})
        cur_schemas = self.current.get("components", {}).get("schemas", {})
        for name, schema in golden_schemas.items():
            if not name.startswith(("Fgt",)):
                continue
            self.assertIn(name, cur_schemas, f"schema {name} sparito")
            self.assertEqual(
                json.dumps(schema, sort_keys=True),
                json.dumps(cur_schemas[name], sort_keys=True),
                f"schema {name} cambiato",
            )


PRE_DESTRUCTURE = os.path.join(os.path.dirname(__file__), "tests_data",
                               "openapi_pre_destructure.json")


class TestFullParity(unittest.TestCase):
    """Gate del destructuring (fase 6.6): OGNI percorso, metodo, parametro e
    schema deve restare identico allo snapshot catturato prima dell'estrazione.
    Unica differenza ammessa: i ``tags`` aggiunti dai router."""

    @classmethod
    def setUpClass(cls):
        with open(PRE_DESTRUCTURE, encoding="utf-8") as f:
            cls.snap = json.load(f)
        cls.current = app_server.app.openapi()

    def test_path_set_identical(self):
        self.assertEqual(sorted(self.snap["paths"]), sorted(self.current["paths"]),
                         "l'insieme dei percorsi è cambiato")

    def test_every_operation_identical(self):
        for path, ops in self.snap["paths"].items():
            cur_ops = self.current["paths"][path]
            self.assertEqual(set(ops), set(cur_ops), f"metodi diversi su {path}")
            for method, op in ops.items():
                self.assertEqual(
                    json.dumps(_normalize(op), sort_keys=True),
                    json.dumps(_normalize(cur_ops[method]), sort_keys=True),
                    f"contratto cambiato: {method.upper()} {path}",
                )

    def test_every_schema_identical(self):
        snap_schemas = self.snap.get("components", {}).get("schemas", {})
        cur_schemas = self.current.get("components", {}).get("schemas", {})
        self.assertEqual(sorted(snap_schemas), sorted(cur_schemas),
                         "l'insieme degli schemi componenti è cambiato")
        for name, schema in snap_schemas.items():
            self.assertEqual(
                json.dumps(schema, sort_keys=True),
                json.dumps(cur_schemas[name], sort_keys=True),
                f"schema {name} cambiato",
            )


if __name__ == "__main__":
    unittest.main()
