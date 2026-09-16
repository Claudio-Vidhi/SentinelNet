# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Server-side tab enforcement: 'visible tabs' is a hint from the client
today, this makes it a gate the server also checks (admin-permissions
Task 1)."""
import json
import os
import shutil
import subprocess
import unittest

import pytest
from fastapi import HTTPException

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def um(tmp_path, monkeypatch):
    from security import user_manager
    monkeypatch.setattr(user_manager, "USERS_JSON", str(tmp_path / "users.json"))
    return user_manager


def test_effective_tabs(um):
    um.create_user("root", "password-1234", role="super_admin")
    um.create_user("free", "password-1234", role="operator")
    um.create_user("lim", "password-1234", role="admin")
    um.set_allowed_tabs("root", ["tab-devices"])
    um.set_allowed_tabs("lim", ["tab-mac", "tab-map", "tab-provisioning"])
    assert um.effective_tabs("root") is None
    assert um.effective_tabs("free") is None
    assert um.effective_tabs("lim") == {
        "tab-endpoint", "tab-map", "tab-map-interactive",
        "tab-provisioning", "tab-provisioner"}


def test_require_tab(um):
    from routers import deps
    um.create_user("lim", "password-1234", role="admin")
    um.set_allowed_tabs("lim", ["tab-devices"])
    dep = deps.require_tab("tab-devices", "tab-import")
    assert dep.tabs == frozenset({"tab-devices", "tab-import"})
    user = {"sub": "lim", "role": "admin"}
    assert dep(current_user=user) is user
    with pytest.raises(HTTPException) as e:
        deps.require_tab("tab-settings")(current_user=user)
    assert e.value.status_code == 403
    assert e.value.detail == "Funzionalita' non abilitata per questo utente."


class TestTabAliasParityWithCoreJS(unittest.TestCase):
    """user_manager.TAB_ALIASES and core.js's normalizeAllowedTabs() must
    agree: a legacy tab id saved for a user has to resolve the same way for
    the server gate and for the nav bar. The node harness runs the real JS
    function against the real Python dict."""

    def test_aliases_match(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node non disponibile")
        from security import user_manager
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_tab_alias_parity.mjs")
        proc = subprocess.run(
            [node, harness, json.dumps(user_manager.TAB_ALIASES)],
            capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)
