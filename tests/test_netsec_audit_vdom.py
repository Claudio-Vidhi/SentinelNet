# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Benchmark rules on a multi-VDOM FortiOS backup: per-VDOM run, one folded
outcome per rule. Synthetic config only (RFC 5737 / private, invented names)."""

import os
import unittest

from services import netsec_audit
from services.netsec_audit.parser import parse_with_lines
from services.netsec_audit.rules import check_any_any_policy
from services.netsec_audit.vdom_scopes import split_vdoms

MULTI = """\
#config-version=FGT100F-7.4.5-FW-build2702:opmode=0:vdom=1:user=admin
config vdom
edit root
next
edit vd-b
next
end
config global
config system global
    set hostname "switch-01"
    set admintimeout 480
end
config system interface
    edit "wan1"
        set vdom "root"
        set role wan
        set allowaccess ping https telnet
    next
    edit "port5"
        set vdom "vd-b"
        set role wan
    next
end
end
config vdom
edit root
config firewall policy
    edit 1
        set name "any-any"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set logtraffic disable
    next
end
next
edit vd-b
config firewall policy
    edit 1
        set name "narrow"
        set srcintf "port6"
        set dstintf "port5"
        set action accept
        set srcaddr "Host_A"
        set dstaddr "Host_B"
        set service "HTTPS"
        set logtraffic all
    next
end
next
end
"""
LINES = MULTI.splitlines()


def _rules(text=MULTI):
    res = netsec_audit.run_netsec_audit(config_text=text, benchmark="cis", lang="en")
    return res, {r["id"]: r for r in res["rules"]}


class TestMultiVdomAudit(unittest.TestCase):
    def setUp(self):
        self.res, self.by_id = _rules()

    def _assert_real_line(self, ev):
        self.assertEqual(LINES[ev["line"] - 1].strip(), ev["text"])

    def test_scopes_and_vdom_list(self):
        self.assertEqual([vd for vd, _c in split_vdoms(parse_with_lines(MULTI))], ["root", "vd-b"])
        self.assertEqual(self.res["vdoms"], ["root", "vd-b"])

    def test_fail_in_one_vdom_is_fail(self):
        rule = self.by_id["AUD-CIS-02"]  # any-to-any: only root's policy 1
        self.assertEqual(rule["status"], "FAIL")
        self.assertTrue(rule["detail"].startswith("[root] "))
        self.assertEqual(len(rule["evidence"]), 1)
        ev = rule["evidence"][0]
        self.assertEqual(ev["context"], "vdom root / firewall policy / 1")
        # The real file line, inside the second (content) root block.
        root_at = LINES.index("edit root", LINES.index("edit root") + 1) + 1
        vdb_at = LINES.index("edit vd-b", root_at) + 1
        self.assertTrue(root_at < ev["line"] < vdb_at)
        self.assertEqual(LINES[ev["line"] - 1].strip(), "set action accept")
        self._assert_real_line(ev)

    def test_same_policy_id_in_both_vdoms_not_collapsed(self):
        ctxs = [e["context"] for e in self.by_id["AUD-CIS-26"]["evidence"]]
        self.assertEqual(ctxs, ["vdom root / firewall policy / 1",
                                "vdom vd-b / firewall policy / 1"])
        self.assertIn("[root]", self.by_id["AUD-CIS-26"]["detail"])
        self.assertIn("[vd-b]", self.by_id["AUD-CIS-26"]["detail"])

    def test_global_rule_once(self):
        rule = self.by_id["AUD-CIS-04"]  # admintimeout in config global
        self.assertEqual(rule["status"], "FAIL")
        self.assertEqual(len(rule["evidence"]), 1)
        ev = rule["evidence"][0]
        self.assertEqual(ev["context"], "system global")
        self.assertEqual(ev["text"], "set admintimeout 480")
        self._assert_real_line(ev)
        self.assertFalse(rule["detail"].startswith("["))

    def test_unknown_before_now_assessed(self):
        # The flat parse sees no top-level firewall policy at all.
        self.assertEqual(check_any_any_policy(parse_with_lines(MULTI)).status, "UNKNOWN")
        self.assertEqual(self.by_id["AUD-CIS-02"]["status"], "FAIL")

    def test_scoring_shape_unchanged(self):
        s = self.res["summary"]
        self.assertEqual(s["total"], s["passed"] + s["failed"] + s["warned"] + s["unknown"])
        self.assertIsNotNone(self.res["score"])


class TestSingleVdomUnchanged(unittest.TestCase):
    def test_fixture_has_no_scopes(self):
        p = os.path.join(os.path.dirname(__file__), "fixtures", "fortigate_violations.conf")
        with open(p, encoding="utf-8") as fh:
            text = fh.read()
        self.assertEqual(split_vdoms(parse_with_lines(text)), [])
        self.assertNotIn("vdoms", netsec_audit.run_netsec_audit(config_text=text))


def _docx_lines(result):
    import io
    from docx import Document
    from services.netsec_audit.docx_export import generate_audit_docx
    doc = Document(io.BytesIO(generate_audit_docx({**result, "device_name": "switch-01"})))
    return [p.text for t in doc.tables for row in t.rows for c in row.cells for p in c.paragraphs]


class TestDocxPolicyLabel(unittest.TestCase):
    def test_vdom_prefixed_policy_label(self):
        lines = _docx_lines(_rules()[0])
        self.assertIn("VDOM root · Policy ID #1: set action accept",
                      [ln.split("] ", 1)[-1] for ln in lines])
        self.assertTrue(any("VDOM vd-b · Policy ID #1" in ln for ln in lines))

    def test_single_vdom_label_unchanged(self):
        p = os.path.join(os.path.dirname(__file__), "fixtures", "fortigate_violations.conf")
        with open(p, encoding="utf-8") as fh:
            res = netsec_audit.run_netsec_audit(config_text=fh.read())
        lines = [ln for ln in _docx_lines(res) if "Policy ID #" in ln]
        self.assertTrue(lines)
        self.assertFalse(any("VDOM" in ln for ln in lines))


if __name__ == "__main__":
    unittest.main()
