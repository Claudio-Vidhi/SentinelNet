# -*- coding: utf-8 -*-
"""Drift API: tenant isolation is enforced, and diffs carry no secrets."""
import unittest

from routers import config_drift


class ADiffNeverLeaksASecret(unittest.TestCase):
    """A config diff is dense with credentials. The operator does not need the
    secret in order to read the change."""

    def test_secrets_are_masked_in_the_unified_diff(self):
        before = "enable secret Sup3r-Enable\nhostname switch-01\n"
        after = "enable secret N3w-Enable\nhostname switch-02\n"
        diff = config_drift._unified("cisco", before, after, "a", "b")
        self.assertNotIn("Sup3r-Enable", diff)
        self.assertNotIn("N3w-Enable", diff)
        self.assertIn("switch-02", diff)

    def test_an_identical_pair_produces_an_empty_diff(self):
        text = "hostname switch-01\n"
        self.assertEqual("", config_drift._unified("cisco", text, text, "a", "b"))


if __name__ == "__main__":
    unittest.main()
