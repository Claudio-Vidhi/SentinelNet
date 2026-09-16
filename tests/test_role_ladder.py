# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The role ladder: who may manage whom, the super_admin quorum and the
one-shot promotion of pre-existing admins."""
import json

import pytest


@pytest.fixture
def um(tmp_path, monkeypatch):
    """user_manager bound to a throwaway users.json (never the real one)."""
    from security import user_manager
    monkeypatch.setattr(user_manager, "USERS_JSON", str(tmp_path / "users.json"))
    return user_manager


def test_is_admin(um):
    assert um.is_admin("super_admin") and um.is_admin("admin")
    assert not um.is_admin("operator") and not um.is_admin("viewer")
    assert not um.is_admin(None)


@pytest.mark.parametrize("actor,target,ok", [
    ("super_admin", "super_admin", True),
    ("super_admin", "admin", True),
    ("admin", "super_admin", False),
    ("admin", "admin", False),
    ("admin", "operator", True),
    ("admin", "viewer", True),
    ("operator", "viewer", True),   # rank-wise; routes still require admin first
    ("viewer", "viewer", False),
])
def test_can_manage(um, actor, target, ok):
    assert um.can_manage(actor, target) is ok


@pytest.mark.parametrize("actor,new_role,ok", [
    ("super_admin", "super_admin", True),
    ("super_admin", "admin", True),
    ("admin", "super_admin", False),
    ("admin", "admin", False),
    ("admin", "operator", True),
    ("admin", "viewer", True),
    ("super_admin", "root", False),
])
def test_can_assign(um, actor, new_role, ok):
    assert um.can_assign(actor, new_role) is ok


def test_quorum_counts_active_super_admins_only(um):
    um.create_user("root-a", "password-1234", role="super_admin")
    um.create_user("adm-b", "password-1234", role="admin")
    assert um.count_active_super_admins() == 1
    assert um.is_last_active_super_admin("root-a")
    assert not um.is_last_active_super_admin("adm-b")
    um.create_user("root-c", "password-1234", role="super_admin")
    assert not um.is_last_active_super_admin("root-a")
    um.set_disabled("root-c", True)
    assert um.is_last_active_super_admin("root-a")
    assert not um.is_last_active_super_admin("root-c")


def test_legacy_account_without_role_is_super_admin(um, tmp_path):
    (tmp_path / "users.json").write_text(
        json.dumps({"legacy": {"hashed_password": "$2b$12$notarealhash"}}),
        encoding="utf-8")
    assert um.get_role("legacy") == "super_admin"
    assert um.list_users()[0]["role"] == "super_admin"
    assert um.first_admin_username() == "legacy"


def test_first_admin_prefers_super_admin(um):
    um.create_user("aaa-admin", "password-1234", role="admin")
    assert um.first_admin_username() == "aaa-admin"   # CLI run before migration
    um.create_user("zzz-root", "password-1234", role="super_admin")
    assert um.first_admin_username() == "zzz-root"


def test_migration_promotes_admins_once(um):
    um.create_user("adm-1", "password-1234", role="admin")
    um.create_user("op-1", "password-1234", role="operator")
    assert um.migrate_admins_to_super_admin() == ["adm-1"]
    assert um.get_role("adm-1") == "super_admin"
    assert um.get_role("op-1") == "operator"
    # An admin created after the migration is never promoted, because an
    # active super_admin now exists.
    um.create_user("adm-2", "password-1234", role="admin")
    assert um.migrate_admins_to_super_admin() == []
    assert um.get_role("adm-2") == "admin"


def test_migration_on_empty_store_is_noop(um):
    assert um.migrate_admins_to_super_admin() == []


def test_migration_recovers_store_without_active_super_admin(um):
    um.create_user("root-disabled", "password-1234", role="super_admin")
    um.set_disabled("root-disabled", True)
    um.create_user("adm-1", "password-1234", role="admin")
    assert um.migrate_admins_to_super_admin() == ["adm-1"]
    assert um.get_role("adm-1") == "super_admin"


def test_migration_ignores_app_settings(um, monkeypatch):
    from core import app_settings

    def boom():
        raise AssertionError("migration must not touch app_settings")

    monkeypatch.setattr(app_settings, "get_app_settings", boom)
    um.create_user("adm-1", "password-1234", role="admin")
    assert um.migrate_admins_to_super_admin() == ["adm-1"]
