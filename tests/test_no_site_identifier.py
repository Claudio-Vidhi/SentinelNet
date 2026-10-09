# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
""""site" meant *probe* and is gone: one name per concept (spec
2026-10-09-site-to-probe-rename-design.md). A new site_... is a red test.

A line that must keep the spelling (the CSV alias for old exports, the test
asserting old headers are refused, the migration's old names) carries the
marker below; adding one is a reviewable diff, the same rule as
check_no_private_data.

PENDING lists files not renamed yet. It only shrinks: a listed file that no
longer offends fails too, so the list cannot go stale."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "check-site-name: ok"
SCANNED = re.compile(r"\.(py|js|mjs|html|ts|sql|ps1|sh|spec|service)$")
TOKEN = re.compile(r"[A-Za-z0-9_-]*[Ss][Ii][Tt][Ee][A-Za-z0-9_-]*")
QUOTED = re.compile(r"""['"]Sites?['"]|/sites\b""")
# Words that merely contain the letters; each was reviewed.
WORDS = ("site-to-site", "prerequisite", "opposite", "offsite", "onsite",
         "composite", "website", "requisite", "parasite", "visited", "on-site")

PENDING = frozenset({
    "ai/ai_assistant.py",
    "ai/mcp_server.py",
    "app_server.py",
    "collectors/arp_collector.py",
    "collectors/mac_collector.py",
    "collectors/mac_history.py",
    "core/core_engine.py",
    "core/device_credentials.py",
    "core/net_ssh.py",
    "observability/ingesters/linux_poller.py",
    "observability/ingesters/windows_poller.py",
    "observability/storage/schema.sql",
    "routers/agent.py",
    "routers/ai.py",
    "routers/audit_checklist.py",
    "routers/auth.py",
    "routers/commands.py",
    "routers/deps.py",
    "routers/inventory.py",
    "routers/manual_config.py",
    "routers/provisioner.py",
    "routers/route_classes.py",
    "routers/scan.py",
    "routers/settings.py",
    "routers/sites.py",
    "routers/triage.py",
    "scripts/dev/windows_probe.py",
    "scripts/vm_agent_test_helper.py",
    "services/audit_checklist.py",
    "services/client_diagnosis.py",
    "services/device_history.py",
    "services/inventory_manager.py",
    "services/ping_monitor.py",
    "services/route_table.py",
    "services/site_agent.py",
    "services/site_manager.py",
    "services/switch_provisioner.py",
    "services/triage_scheduler.py",
    "static/js/client-map.js",
    "static/js/core.js",
    "static/js/device-history.js",
    "static/js/devices.js",
    "static/js/diagnosi.js",
    "static/js/endpoint-inventory.js",
    "static/js/home.js",
    "static/js/i18n.js",
    "static/js/manual-config.js",
    "static/js/provisioning.js",
    "static/js/settings.js",
    "static/js/site-agent.js",
    "static/js/topology.js",
    "templates/dashboard.html",
    "tests/__init__.py",
    "tests/conftest.py",
    "tests/js/test_assignable_tabs.mjs",
    "tests/js/test_layered_groups.mjs",
    "tests/js/test_layered_levels.mjs",
    "tests/js/test_map_layout.mjs",
    "tests/js/test_site_enrollment.mjs",
    "tests/test_admin_tenant_scope.py",
    "tests/test_agent_syslog_toggle.py",
    "tests/test_ai_assistant.py",
    "tests/test_auth_cookie.py",
    "tests/test_bugfix_batch.py",
    "tests/test_category_tenant_scope.py",
    "tests/test_classification_assist.py",
    "tests/test_classify_device_type.py",
    "tests/test_client_diagnosis.py",
    "tests/test_cloud_backup_api.py",
    "tests/test_cloud_backup_payload.py",
    "tests/test_cloud_backup_restore_script.py",
    "tests/test_cloud_backup_state.py",
    "tests/test_cloud_backup_sync.py",
    "tests/test_cloud_backup_transport.py",
    "tests/test_cloud_backup_verify.py",
    "tests/test_config_analyzer_panos.py",
    "tests/test_config_analyzer_scoping.py",
    "tests/test_data_isolation.py",
    "tests/test_device_history.py",
    "tests/test_device_host_keys.py",
    "tests/test_device_meta_store.py",
    "tests/test_device_site_gui.py",
    "tests/test_export_customizable.py",
    "tests/test_firewall_traffic.py",
    "tests/test_flow_siem.py",
    "tests/test_hosts_csv_concurrency.py",
    "tests/test_import_csv_parsing.py",
    "tests/test_inventory_cache.py",
    "tests/test_jump_site.py",
    "tests/test_lazy_tab_scripts.py",
    "tests/test_manual_config_api.py",
    "tests/test_manual_device_guards.py",
    "tests/test_manual_device_skips.py",
    "tests/test_manual_transport.py",
    "tests/test_map_layered.py",
    "tests/test_no_private_data.py",
    "tests/test_path_trace.py",
    "tests/test_rbac_scope.py",
    "tests/test_remote_site.py",
    "tests/test_route_table.py",
    "tests/test_router_parity.py",
    "tests/test_scan_verify.py",
    "tests/test_secret_file_permissions.py",
    "tests/test_settings_restart.py",
    "tests/test_site_editing.py",
    "tests/test_site_verified.py",
    "tests/test_site_wizard_api.py",
    "tests/test_site_wizard_ui.py",
    "tests/test_sites.py",
    "tests/test_ssh_legacy_algorithms.py",
    "tests/test_tab_enforcement.py",
    "tests/test_triage_credential_errors.py",
    "tests/test_triage_scheduler.py",
    "tests/test_ui_revamp.py",
    "tests/test_wlc_triage_timeout.py",
    "types/globals.d.ts",
})


def _bad(token: str) -> bool:
    t = token.lower()
    for w in WORDS:
        t = t.replace(w, "")
    return "site" in t and t not in ("site", "sites")


def offending(text: str):
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if MARK in line:
            continue
        bad = [t for t in TOKEN.findall(line) if _bad(t)] + QUOTED.findall(line)
        if bad:
            hits.append((n, bad))
    return hits


def _tracked():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout.splitlines()
    return [p for p in out if not p.startswith("docs/")]


class TestNoSiteIdentifier(unittest.TestCase):
    def _offenders(self):
        found = {}
        for rel in _tracked():
            if rel == "tests/test_no_site_identifier.py":
                continue
            if _bad(Path(rel).name):
                found[rel] = [(0, ["<file name>"])]
                continue
            if not SCANNED.search(rel):
                continue
            hits = offending((ROOT / rel).read_text(encoding="utf-8", errors="replace"))
            if hits:
                found[rel] = hits
        return found

    def test_no_new_offenders(self):
        new = {p: h[:3] for p, h in self._offenders().items() if p not in PENDING}
        self.assertEqual(new, {}, "rename to probe, or mark the line with " + MARK)

    def test_pending_only_shrinks(self):
        stale = sorted(PENDING - set(self._offenders()))
        self.assertEqual(stale, [], "remove these from PENDING: they are clean")


if __name__ == "__main__":
    unittest.main()
