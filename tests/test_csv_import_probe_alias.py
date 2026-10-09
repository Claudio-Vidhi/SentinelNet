# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""An export made before the rename (column 'Site') reimports onto Probe."""
import unittest

from services import inventory_manager


class TestProbeAlias(unittest.TestCase):
    def test_old_and_new_headers_map_to_probe(self):
        for header in ("Site", "site", "Probe", "sonda"):  # check-site-name: ok
            with self.subTest(header=header):
                self.assertEqual(inventory_manager._canonical_header(header), "Probe")

    def test_sede_is_not_a_probe(self):
        # Reserved for the Location column of sub-project 1.
        self.assertIsNone(inventory_manager._canonical_header("sede"))
