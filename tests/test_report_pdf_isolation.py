# -*- coding: utf-8 -*-
"""The PDF print renders client-supplied HTML in a real browser, on the server.

Without --host-resolver-rules the browser fetches whatever subresource the HTML
names and paints the answer into the PDF we hand back: an authenticated SSRF
reading internal services from the appliance's network position. Measured, not
assumed -- with a real Chrome, an <img src="http://127.0.0.1:PORT/x"> reached a
local listener without the flag and was refused with it, literal IP included.

No role gate here on purpose: a viewer can already run the audit and export the
same report as DOCX, so gating only the PDF would buy nothing and split one
feature across two permission levels.
"""

import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_pdfiso_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR


from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from routers import analyzer  # noqa: E402



class TestPrintArgv(unittest.TestCase):
    """Runs without a browser installed: the argv is the whole contract."""

    def setUp(self):
        # Absolute: Path.as_uri() refuses a relative path, and "/tmp/x" is
        # relative on Windows.
        base = os.path.abspath(_TMP_DATA_DIR)
        self.src = os.path.join(base, "r.html")
        self.out = os.path.join(base, "r.pdf")
        self.profile = os.path.join(base, "profile")
        self.argv = analyzer._print_argv("/usr/bin/chromium", self.src,
                                         self.out, self.profile)

    def test_name_resolution_is_refused(self):
        self.assertIn("--host-resolver-rules=MAP * ~NOTFOUND", self.argv)

    def test_the_page_is_still_the_local_file(self):
        self.assertTrue(self.argv[-1].startswith("file://"))
        self.assertIn(f"--print-to-pdf={self.out}", self.argv)

    def test_the_profile_is_disposable(self):
        # A shared profile would carry cookies into the rendered page.
        self.assertIn(f"--user-data-dir={self.profile}", self.argv)


if __name__ == "__main__":
    unittest.main()
