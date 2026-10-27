# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Schema view readability controls: focus, port labels, wrapped rows, grouped uplinks."""

import os
import re
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONTROLS = ("toggleSchemaFocus", "schemaPortLabels", "toggleSchemaWrap",
            "toggleSchemaGroupUplinks", "schemaPresetRecommended", "schemaPresetOverview",
            "schemaApMode")


class TestSchemaReadability(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = open(os.path.join(_REPO_ROOT, "static", "js", "topology.js"),
                       encoding="utf-8").read()
        cls.html = open(os.path.join(_REPO_ROOT, "templates", "dashboard.html"),
                        encoding="utf-8").read()

    def _block(self, marker):
        start = self.src.index(marker)
        return self.src[start:self.src.index("\n    }", start)]

    def _wrap(self):
        start = self.html.index('id="schemaReadWrap"')
        return self.html[start:self.html.index("<!-- /schemaReadWrap -->", start)]

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_harness(self):
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_schema_readability.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)

    def test_controls_wired(self):
        # An id bound in JS but missing from the template leaves a dead control.
        self.assertTrue("getElementById('schemaReadWrap')" in self.src)
        wrap = self._wrap()
        for cid in CONTROLS:
            self.assertIn(f'id="{cid}"', wrap, cid)
            self.assertTrue(f"getElementById('{cid}')" in self.src, cid)
        self.assertNotIn("onclick=", wrap)

    def test_focus_cleared_on_render(self):
        # A stale focus on a node that is gone would dim the whole new map.
        start = self.src.index("minimalOverlayData = { bundles, groupsInfo, nodes, ladder }")
        self.assertIn("schemaFocusId = null", self.src[start - 600:start + 300])

    def test_overlay_uses_the_helpers(self):
        overlay = self._block("function drawMinimalOverlay(")
        self.assertIn("schemaDimmed(", overlay)
        self.assertIn("schemaUplinkGroups(", overlay)
        label = overlay[overlay.index("const drawPortLabel"):]
        label = label[:label.index("};")]
        self.assertIn("schemaPortLabelVisible(", label)
        # The export always gets every port name and no dimming.
        self.assertIn("visioConnectorSink", label)

    def test_wrap_in_tidy(self):
        tidy = self._block("function packSchemaRows(")
        self.assertIn("zigzagRow(", tidy)
        self.assertIn("SCHEMA_WRAP_MIN", tidy)

    def test_ap_modes_wired(self):
        # Collapsed group reuses the hierarchy's grouping; column is laid out by the tidy.
        start = self.src.index('const hoverInfo = document.getElementById("toggleMinimalHover")')
        branch = self.src[start:self.src.index("return;", start)]
        self.assertIn("groupLayeredLeaves(", branch)
        self.assertIn("schemaColumnsNow(", self._block("function packSchemaRows("))
        self.assertIn("schemaLeafColumns(", self._block("function drawMinimalOverlay("))
        # A group box opens on click in the Schema view too.
        sel = self.src[self.src.index("networkInstance.on('selectNode'"):]
        sel = sel[:sel.index("});")]
        self.assertNotIn("getMapView() === 'layered' && id.startsWith(GROUP_PREFIX)", sel)

    def test_group_mode_starts_collapsed(self):
        # Choosing "Collapsed group" closes the groups left open (state shared with the hierarchy).
        start = self.src.index("} else if (el.id === 'schemaApMode') {")
        block = self.src[start:self.src.index("redrawInteractiveMap();", start)]
        self.assertIn("delete layeredExpanded[", block)

    def test_compact_leaves_wired(self):
        # Small AP boxes: built compact, and no port label printed inside them.
        build = self._block("function buildMinimalGraph(")
        self.assertIn("schemaCompactLeaves(", build)
        overlay = self._block("function drawMinimalOverlay(")
        self.assertIn("compactIds.has(b.to)", overlay)
        self.assertIn("compactIds.has(b.from)", overlay)

    def test_prefs_read_in_try_catch(self):
        # Storage can throw (private window, blocked site data).
        for key in ("schemaFocus", "schemaPortLabels", "schemaWrap", "schemaGroupUplinks", "schemaApMode"):
            self.assertTrue(f"schemaPref('{key}'" in self.src, key)
        pref = self._block("function schemaPref(")
        self.assertRegex(pref, re.compile(r"try\s*\{.*localStorage\.getItem", re.S))


if __name__ == "__main__":
    unittest.main()
