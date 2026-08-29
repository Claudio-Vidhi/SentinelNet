# -*- coding: utf-8 -*-
"""Cancello di accessibilita' sul template (plan item 14).

Il report e' a zero: da qui in avanti un controllo senza nome accessibile, o
la semantica tablist rimossa, fanno fallire il gate invece di scivolare in
produzione. La trappola del focus e la semantica dialog stanno in
tests/test_ui_modal.py: sono applicate a runtime dal gestore modali.
"""

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestDashboardAccessibility(unittest.TestCase):

    def test_report_is_clean(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_a11y.py"), "--strict"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_nav_items_and_panels_stay_paired(self):
        html = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
        import re
        controls = set(re.findall(r'role="tab" aria-controls="([^"]+)"', html))
        self.assertTrue(controls, "nessuna voce di nav con aria-controls")
        missing = [c for c in sorted(controls) if f'id="{c}"' not in html]
        self.assertEqual(missing, [], "aria-controls punta a pannelli inesistenti")


if __name__ == "__main__":
    unittest.main()
