# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
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

    def test_the_pdf_carries_bookmarks(self):
        # Built from the headings; the CVE report's device sections are h3 for
        # exactly this reason.
        self.assertIn("--generate-pdf-document-outline", self.argv)

    def test_the_profile_is_disposable(self):
        # A shared profile would carry cookies into the rendered page.
        self.assertIn(f"--user-data-dir={self.profile}", self.argv)

    def test_scripts_stay_on_by_default(self):
        # The compliance report paginates with a script: only the device
        # summary prints with scripts off.
        self.assertFalse(any(a.startswith("--blink-settings") for a in self.argv))
        argv = analyzer._print_argv("/usr/bin/chromium", self.src, self.out,
                                    self.profile, no_script=True)
        self.assertIn("--blink-settings=scriptEnabled=false", argv)
        self.assertTrue(argv[-1].startswith("file://"))


class TestSummaryHtml(unittest.TestCase):
    """The device summary wrapper: a CSP the client cannot precede, no script,
    no refresh."""

    CSP = ('<!doctype html><meta http-equiv="Content-Security-Policy" '
           'content="default-src \'none\'; style-src \'unsafe-inline\'; '
           'img-src data:; font-src data:; base-uri \'none\'; form-action \'none\'">')

    def test_csp_comes_first_and_client_doctype_is_dropped(self):
        out = analyzer._summary_html('<!DOCTYPE html>\n<html><body>x</body></html>')
        self.assertTrue(out.startswith(self.CSP))
        self.assertEqual(out[len(self.CSP):].lstrip(), '<html><body>x</body></html>')
        self.assertEqual(out.lower().count('<!doctype'), 1)

    def test_refresh_meta_is_refused(self):
        from fastapi import HTTPException
        for bad in ('<meta http-equiv="refresh" content="0;url=http://192.0.2.1/">',
                    "<META HTTP-EQUIV = 'Refresh' content=0>",
                    '<meta http-equiv=refresh content=0>',
                    # The parser decodes the entity; a value regex would not.
                    '<meta http-equiv="&#114;efresh" content="0;url=file:///etc/x">'):
            with self.assertRaises(HTTPException) as cm:
                analyzer._summary_html(bad)
            self.assertEqual(cm.exception.status_code, 400)

    def test_plain_meta_is_accepted(self):
        out = analyzer._summary_html('<meta charset="utf-8"><p>x</p>')
        self.assertTrue(out.endswith('<meta charset="utf-8"><p>x</p>'))

    def test_script_is_refused(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            analyzer._summary_html('<html><SCRIPT>1</SCRIPT></html>')
        self.assertEqual(cm.exception.status_code, 400)


class TestReportHtml(unittest.TestCase):
    """The audit report wrapper: client HTML carries no script, the server
    appends the one trusted pagination script under a per-request nonce."""

    JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "static", "js", "report-paginate.js")

    def _nonce(self, out):
        import re
        m = re.search(r"script-src 'nonce-([\w-]+)'", out)
        self.assertIsNotNone(m, out[:300])
        return m.group(1)

    def test_csp_first_with_nonce_and_client_doctype_dropped(self):
        out = analyzer._report_html('<!DOCTYPE html>\n<html><body>x</body></html>')
        self.assertTrue(out.startswith('<!doctype html><meta http-equiv="Content-Security-Policy" '
                                       'content="default-src \'none\'; style-src \'unsafe-inline\'; '
                                       'img-src data:; font-src data:; script-src \'nonce-'))
        self.assertIn("base-uri 'none'; form-action 'none'\">", out)
        # The pagination file itself mentions a doctype (its HTML export).
        self.assertTrue(out.split("'none'\">", 1)[1].lstrip()
                        .startswith('<html><body>x</body></html><script nonce='))

    def test_injected_script_is_the_trusted_file_under_the_nonce(self):
        out = analyzer._report_html('<p>x</p>')
        nonce = self._nonce(out)
        with open(self.JS, encoding="utf-8") as fh:
            js = fh.read()
        self.assertTrue(out.endswith(f'<script nonce="{nonce}">{js}</script>'))
        self.assertEqual(out.count('<script'), 1)

    def test_nonce_is_fresh_per_call(self):
        self.assertNotEqual(self._nonce(analyzer._report_html('<p>x</p>')),
                            self._nonce(analyzer._report_html('<p>x</p>')))

    def test_script_and_refresh_are_refused(self):
        from fastapi import HTTPException
        for bad in ('<script>location="file:///x"</script>',
                    '<SCRIPT src=x></SCRIPT>',
                    '<meta http-equiv="refresh" content="0;url=file:///etc/x">',
                    '<meta http-equiv="&#114;efresh" content="0;url=file:///etc/x">'):
            with self.assertRaises(HTTPException) as cm:
                analyzer._report_html(bad)
            self.assertEqual(cm.exception.status_code, 400)


class TestReportClientScripts(unittest.TestCase):
    """The pagination script lives in one constant file; the client sends no
    script of its own."""

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _read(self, rel):
        with open(os.path.join(self.ROOT, *rel.split("/")), encoding="utf-8") as fh:
            return fh.read()

    def test_paginate_file_has_no_interpolation(self):
        js = self._read("static/js/report-paginate.js")
        self.assertIn("function paginateReport", js)
        self.assertNotIn("${", js)
        self.assertNotIn("</script", js.lower())

    def test_audit_report_has_no_inline_pagination_template(self):
        src = self._read("static/js/netsec-audit.js")
        self.assertNotIn("function paginateReport", src)
        self.assertNotIn("<base href", src)
        self.assertIn("/static/js/report-paginate.js", src)

    def test_pdf_send_path_strips_scripts_and_base(self):
        src = self._read("static/js/netsec-audit.js")
        body = src[src.index("async function downloadModalPdf"):]
        body = body[:body.index("/api/netsec-audit/report/pdf") + 200]
        self.assertIn("querySelectorAll('script, base')", body)
        self.assertIn("clone.outerHTML", body)
        self.assertNotIn("doc.documentElement.outerHTML", body)


if __name__ == "__main__":
    unittest.main()
