# -*- coding: utf-8 -*-
"""Break-glass CLI admin password reset (app_server --reset-admin).

The recovery path must work when every admin is locked out, so the tests cover
the disabled account too: leaving `disabled` set would hand back a password
that still cannot log in.
"""
import importlib
import json
import socket
import sys

import pytest


@pytest.fixture
def um(tmp_path, monkeypatch):
    """user_manager bound to a throwaway users.json (never the real one)."""
    from security import user_manager
    monkeypatch.setattr(user_manager, "USERS_JSON", str(tmp_path / "users.json"))
    return user_manager


def test_reset_enables_account_and_forces_change(um):
    um.create_user("admin-01", "old-password", role="admin")
    assert um.set_disabled("admin-01", True)

    assert um.reset_password_break_glass("admin-01", "new-password") is True

    assert um.verify_user("admin-01", "new-password") is True
    assert um.verify_user("admin-01", "old-password") is False
    assert um.is_disabled("admin-01") is False
    assert um.must_change_password("admin-01") is True


def test_reset_unknown_user_is_refused(um):
    um.create_user("admin-01", "old-password", role="admin")
    assert um.reset_password_break_glass("nobody", "new-password") is False
    # The existing account must be untouched by the failed attempt.
    assert um.verify_user("admin-01", "old-password") is True


def test_first_admin_ignores_non_admins(um):
    assert um.first_admin_username() is None
    um.create_user("zulu-viewer", "some-password", role="viewer")
    assert um.first_admin_username() is None
    um.create_user("mike-admin", "some-password", role="admin")
    um.create_user("alpha-operator", "some-password", role="operator")
    assert um.first_admin_username() == "mike-admin"


def test_legacy_account_without_role_counts_as_admin(um, tmp_path):
    # Single-user installs predating roles have no "role" key; get_role treats
    # them as admin, so break-glass must find them too.
    (tmp_path / "users.json").write_text(
        json.dumps({"legacy": {"hashed_password": "$2b$12$notarealhash"}}),
        encoding="utf-8",
    )
    assert um.first_admin_username() == "legacy"


def test_cli_rejects_password_below_policy(um, monkeypatch, capsys):
    um.create_user("admin-01", "old-password", role="admin")
    app_server = importlib.import_module("app_server")

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: "short")

    assert app_server.reset_admin_cli("admin-01") == 1
    assert "almeno" in capsys.readouterr().err
    assert um.verify_user("admin-01", "old-password") is True


def test_cli_rejects_mismatched_confirmation(um, monkeypatch):
    um.create_user("admin-01", "old-password", role="admin")
    app_server = importlib.import_module("app_server")

    typed = iter(["new-password", "different-password"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: next(typed))

    assert app_server.reset_admin_cli("admin-01") == 1
    assert um.verify_user("admin-01", "old-password") is True


def test_cli_defaults_to_first_admin(um, monkeypatch):
    um.create_user("admin-01", "old-password", role="admin")
    app_server = importlib.import_module("app_server")

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: "new-password")

    assert app_server.reset_admin_cli(None) == 0
    assert um.verify_user("admin-01", "new-password") is True


def test_port_in_use_detects_a_listener():
    app_server = importlib.import_module("app_server")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        assert app_server._port_in_use("127.0.0.1", port) is True

    # Socket closed: the port is free again.
    assert app_server._port_in_use("127.0.0.1", port) is False


def test_a_busy_port_is_a_failure_for_the_service_not_a_clean_exit(monkeypatch):
    """Sotto il servizio Windows la porta occupata deve far USCIRE MALE.

    Uscire con 0 e' un'uscita pulita, e WinSW la legge come "il servizio ha
    finito": stato Arrestato, nessun tentativo successivo, nessuna spiegazione.
    Succedeva ogni volta che girava anche un'istanza avviata dal collegamento,
    e durante un aggiornamento mentre la vecchia stava ancora chiudendo. Con
    un codice != 0 interviene onfailure e riprova.
    """
    import app_server

    monkeypatch.setenv("SENTINELNET_WINDOWS_SERVICE", "1")
    monkeypatch.setenv("SENTINELNET_NO_BROWSER", "true")
    monkeypatch.setattr(app_server, "_port_in_use", lambda h, p: True)
    monkeypatch.setattr(app_server, "resolve_bind_host", lambda: "127.0.0.1")
    monkeypatch.setattr(app_server, "effective_port", lambda: 8000)
    monkeypatch.setattr(app_server.data_config, "resolve_tls_config",
                        lambda: (None, None))
    monkeypatch.setattr(sys, "argv", ["SentinelNet.exe"])
    # Se ci arrivasse, il test fallirebbe con un errore piu' oscuro: meglio
    # dire subito che non deve nemmeno provarci.
    monkeypatch.setattr(app_server.uvicorn, "run",
                        lambda *a, **k: pytest.fail("non deve avviare uvicorn"))

    with pytest.raises(SystemExit) as exc:
        app_server.main()
    assert exc.value.code != 0, "0 = uscita pulita = servizio Arrestato"


def test_without_the_service_a_busy_port_still_hands_over(monkeypatch):
    """Fuori dal servizio la scorciatoia resta: doppio clic sul collegamento
    apre l'interfaccia di quella gia' in esecuzione, senza uscire male."""
    import app_server

    monkeypatch.delenv("SENTINELNET_WINDOWS_SERVICE", raising=False)
    monkeypatch.setenv("SENTINELNET_NO_BROWSER", "true")
    monkeypatch.setattr(app_server, "_port_in_use", lambda h, p: True)
    monkeypatch.setattr(app_server, "resolve_bind_host", lambda: "127.0.0.1")
    monkeypatch.setattr(app_server, "effective_port", lambda: 8000)
    monkeypatch.setattr(app_server.data_config, "resolve_tls_config",
                        lambda: (None, None))
    monkeypatch.setattr(sys, "argv", ["SentinelNet.exe"])
    monkeypatch.setattr(app_server.uvicorn, "run",
                        lambda *a, **k: pytest.fail("non deve avviare uvicorn"))

    assert app_server.main() is None
