# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The Blueprint tab must be wired, translated and lazily loaded."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
IDS = ("bpOrgSelect", "bpRevInfo", "bpObsInfo", "btnBpCheck", "btnBpObserve", "btnBpPreset", "btnBpHistory",
       "bpSteps", "bpStepsList", "bpDraftBar", "bpDraftInfo", "btnBpDraftReview", "btnBpDraftApply",
       "btnBpDraftDiscard", "bpLocationsBody", "bpLinksBody", "btnBpAddLocation", "btnBpAddLink",
       "bpDiagram", "bpFindings", "btnBpAcceptSelected",
       "bpLocationModal", "bpLocName", "bpLocRole", "bpLocSubnets", "bpLocProbe", "bpLocGateway",
       "bpLocError", "btnBpLocSave", "bpLinkModal", "bpLinkA", "bpLinkB", "bpLinkKind", "bpLinkNote",
       "bpLinkError", "btnBpLinkSave", "bpPresetModal", "bpPresetKind", "bpPresetN", "bpPresetError",
       "btnBpPresetCreate", "bpDraftModal", "bpDraftOps", "bpApplyNote", "bpDraftError", "bpConflict",
       "bpConflictDiff", "btnBpAlign", "btnBpDraftApplyConfirm", "bpHistoryModal", "bpRevisionsBody",
       "bpDiffA", "bpDiffB", "btnBpDiff", "bpDiffOut")


class TheTabIsWired(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
        self.core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")
        self.js = (ROOT / "static/js/blueprint.js").read_text(encoding="utf-8")
        self.i18n = (ROOT / "static/js/i18n.js").read_text(encoding="utf-8")

    def test_nav_button_and_panel(self):
        self.assertRegex(self.html, r'class="nav-item requires-admin" data-tab="tab-blueprint"')
        self.assertIn('id="tab-blueprint"', self.html)

    def test_lazy_loaded_with_vis_and_dispatched(self):
        self.assertIn("'tab-blueprint': ['/static/vendor/vis/vis-network.min.js', '/static/js/blueprint.js']", self.core)
        self.assertIn("else if (tabId === 'tab-blueprint') loadBlueprintTab();", self.core)
        self.assertIn("window.loadBlueprintTab = loadBlueprintTab;", self.js)

    def test_admin_tab(self):
        settings = (ROOT / "static/js/settings.js").read_text(encoding="utf-8")
        self.assertRegex(settings, r"ADMIN_GROUP_TABS = \[[^\]]*'tab-blueprint'")

    def test_every_control_exists(self):
        for element_id in IDS:
            self.assertIn(f'id="{element_id}"', self.html, element_id)

    def test_finding_keys_in_both_languages(self):
        it, en = self.i18n.split("\n    en: {", 1)
        for key in ("bpf_subnet_overlap", "bpf_location_no_subnets", "bpf_location_isolated",
                    "bpf_location_no_gateway", "bpf_gateway_not_in_location", "bpf_device_outside_subnets",
                    "bpf_device_outside_subnets_owner", "bpf_arp_uncovered", "bpf_subnet_unused",
                    "bpf_link_no_route", "bpf_link_no_route_backup", "bpf_link_no_route_default",
                    "bpf_link_no_route_unknown", "bpf_route_without_link", "bpf_vpn_link_down_missing",
                    "bpf_vpn_link_down_down", "bpf_vpn_link_down_unknown", "bpf_tunnel_without_link"):
            with self.subTest(key=key):
                self.assertRegex(it, rf"\n\s+{key}:")
                self.assertRegex(en, rf"\n\s+{key}:")

    def test_bar_buttons_wait_for_an_organization(self):
        # Their handlers read bpState, which is null until an organization loads.
        for button in ("btnBpCheck", "btnBpObserve", "btnBpPreset", "btnBpHistory", "btnBpAssistant",
                       "btnBpInstructions"):
            self.assertIn(f'id="{button}" disabled', self.html, button)
        self.assertIn("document.querySelectorAll('.bp-bar button').forEach((b) => { b.disabled = false; });", self.js)

    def test_review_shows_every_field_of_a_new_location(self):
        # Security review 2026-10-12, A-M1: subnets and gateway were hidden.
        start = self.js.index("case 'create_location': return tr('bpOpCreate'")
        body = self.js[start:self.js.index("case 'update_location'", start)]
        for needle in ("op.subnets", "op.gateway", "op.probe"):
            self.assertIn(needle, body)

    def test_no_inline_handlers_in_the_new_markup(self):
        start = self.html.index('id="tab-blueprint"')
        self.assertNotRegex(self.html[start:self.html.index("<!-- End #tab-blueprint -->")], r"\bon[a-z]+=")


ASSIST_IDS = ("btnBpAssistant", "btnBpInstructions", "bpAssistantModal", "bpAssistText", "btnBpAssistDescribe",
              "bpAssistUseAi", "btnBpAssistDerive", "bpAssistError", "bpAssistNotes",
              "bpInstructionsModal", "bpInstrText", "bpInstrError", "btnBpInstrSave")


class TheAssistantIsWired(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
        self.js = (ROOT / "static/js/blueprint.js").read_text(encoding="utf-8")
        self.i18n = (ROOT / "static/js/i18n.js").read_text(encoding="utf-8")

    def test_every_control_exists_and_the_buttons_are_bound(self):
        for element_id in ASSIST_IDS:
            self.assertIn(f'id="{element_id}"', self.html, element_id)
        for button in ("btnBpAssistant", "btnBpInstructions", "btnBpAssistDescribe", "btnBpAssistDerive",
                       "btnBpInstrSave"):
            self.assertIn(f"$('{button}').addEventListener", self.js, button)

    def test_routes_ai_flag_and_source_tag(self):
        for needle in ("'/assistant/describe'", "'/assistant/derive'", "'/instructions'",
                       "$('bpAssistUseAi').disabled = !bpState.ai_available", "tr('bpOpFromAssistant')"):
            self.assertIn(needle, self.js, needle)

    def test_keys_in_both_languages(self):
        it, en = self.i18n.split("\n    en: {", 1)
        for key in ("btnBpAssistant", "btnBpInstructions", "bpAssistModalTitle", "bpAssistHint",
                    "bpAssistDescribeTitle", "lblBpAssistText", "bpAssistTextPh", "btnBpAssistDescribe",
                    "bpAssistDeriveTitle", "bpAssistDeriveHint", "lblBpAssistUseAi", "btnBpAssistDerive",
                    "bpInstrModalTitle", "bpInstrHint", "lblBpInstrText", "bpInstrSaved", "bpOpFromAssistant"):
            with self.subTest(key=key):
                self.assertRegex(it, rf"\n\s+{key}:")
                self.assertRegex(en, rf"\n\s+{key}:")

    def test_no_inline_handlers_in_the_new_modals(self):
        start = self.html.index('id="bpAssistantModal"')
        end = self.html.index("<!-- Which location of an organization")
        self.assertNotRegex(self.html[start:end], r"\bon[a-z]+=")
