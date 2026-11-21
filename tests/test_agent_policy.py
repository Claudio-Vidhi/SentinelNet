# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""ADR-0009: the probe agent, not central, decides what it does to devices."""

import json
import os
import tempfile
import unittest
from unittest import mock

from core import device_credentials
from core.device_credentials import CredentialResolveError
from services import agent_policy, probe_agent


def _agent():
    a = probe_agent.Agent.__new__(probe_agent.Agent)
    a.cfg = {"probe_id": "p1"}
    a.syslog_collector = None
    return a


class PolicyFileTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="agent_policy_")
        self.addCleanup(agent_policy.install, None)

    def test_bootstrap_pins_existing_addresses_and_grants_no_change(self):
        pol = agent_policy.load_or_bootstrap(self.dir, ["192.0.2.10", "192.0.2.11", ""])
        agent_policy.install(pol)
        self.assertEqual(pol["state"], "bootstrap")
        self.assertTrue(agent_policy.allows_address("192.0.2.10"))
        self.assertFalse(agent_policy.allows_address("192.0.2.12"))
        self.assertFalse(agent_policy.allows_change("192.0.2.10"))
        with open(os.path.join(self.dir, agent_policy.POLICY_FILE), encoding="utf-8") as fh:
            self.assertTrue(json.load(fh)["bootstrap"])

    def test_reviewed_file_is_read_as_written(self):
        with open(os.path.join(self.dir, agent_policy.POLICY_FILE), "w", encoding="utf-8") as fh:
            json.dump({"allowed_subnets": ["198.51.100.0/24"], "change": ["198.51.100.1/32"]}, fh)
        agent_policy.install(agent_policy.load_or_bootstrap(self.dir, []))
        self.assertTrue(agent_policy.allows_address("198.51.100.77"))
        self.assertTrue(agent_policy.allows_change("198.51.100.1"))
        self.assertFalse(agent_policy.allows_change("198.51.100.2"))
        self.assertEqual(agent_policy.summary(),
                         {"state": "reviewed", "allowed_subnets": 1, "change": 1})

    def test_a_broken_file_stops_the_agent(self):
        with open(os.path.join(self.dir, agent_policy.POLICY_FILE), "w", encoding="utf-8") as fh:
            json.dump({"allowed_subnets": ["not-a-subnet"]}, fh)
        with self.assertRaises(ValueError):
            agent_policy.load_or_bootstrap(self.dir, [])

    def test_central_has_no_policy_and_keeps_its_behaviour(self):
        agent_policy.install(None)
        self.assertTrue(agent_policy.allows_address("203.0.113.5"))
        self.assertFalse(agent_policy.allows_change("203.0.113.5"))


class CredentialBindingTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(prefix="agent_policy_")
        with open(os.path.join(d, agent_policy.POLICY_FILE), "w", encoding="utf-8") as fh:
            json.dump({"allowed_subnets": ["192.0.2.0/24"], "change": []}, fh)
        agent_policy.install(agent_policy.load_or_bootstrap(d, []))
        self.addCleanup(agent_policy.install, None)

    def test_no_credential_for_an_address_outside_the_policy(self):
        # Site default credentials exist; the address decides, not the record.
        with mock.patch.object(device_credentials, "_fallback_credentials",
                               return_value=("admin", "secret", "")):
            dev = {"IP": "192.0.2.5", "Profile": "default"}
            self.assertEqual(device_credentials.get_device_credentials(dev)[1], "secret")
            with self.assertRaises(CredentialResolveError):
                device_credentials.get_device_credentials({"IP": "203.0.113.9", "Profile": "default"})


class JobAndConfigTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(agent_policy.install, None)

    def _run(self, job, devices):
        agent = _agent()
        with mock.patch.object(probe_agent.core_engine, "send_custom_command",
                               return_value={"status": "success", "output": "ok"}) as send, \
             mock.patch.object(agent, "_get") as get, mock.patch.object(agent, "_post") as post:
            get.return_value = mock.MagicMock(json=lambda: {"jobs": [job]})
            agent.run_jobs(devices)
        return send, post.call_args[0][1]

    def test_bypass_without_a_local_grant_is_refused_and_logged(self):
        job = {"id": "j9", "device_ip": "192.0.2.5", "command": "reload", "kind": "cli",
               "blacklist_bypass": 1, "requested_by": "op"}
        send, out = self._run(job, [{"IP": "192.0.2.5", "Vendor": "cisco"}])
        self.assertFalse(send.called)
        self.assertEqual(out["status"], "error")
        self.assertIn("change", out["result"])
        from core import data_config
        with open(data_config.get_path("agent_jobs.jsonl"), encoding="utf-8") as fh:
            last = json.loads(fh.read().splitlines()[-1])
        self.assertEqual((last["id"], last["bypass"], last["status"], last["requested_by"]),
                         ("j9", True, "error", "op"))

    def test_config_rpc_refuses_keys_outside_the_allowlist(self):
        agent = _agent()
        for bad in ('{"central_url": "https://203.0.113.66"}', '{"token": "x"}',
                    '{"interval": "60"}', '{"interval": true}', '{"syslog_enabled": 1}', '[1]'):
            out = agent._execute_agent_rpc(f"_agent_config {bad}")
            self.assertEqual(out["status"], "error", bad)
        self.assertNotIn("central_url", agent.cfg)
        out = agent._execute_agent_rpc('_agent_config {"interval": 120}')
        self.assertEqual(out["status"], "done")
        self.assertEqual(agent.cfg["interval"], 120)


if __name__ == "__main__":
    unittest.main()
