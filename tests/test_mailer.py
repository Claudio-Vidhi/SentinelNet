# -*- coding: utf-8 -*-
"""SMTP delivery (services/mailer).

The point of these tests is the fail-closed behaviour: a server that does not
advertise STARTTLS, or a mode that would authenticate in the clear, must abort
before the password reaches the socket.
"""
import smtplib

import pytest

from services import mailer


class FakeSMTP:
    """Minimal stand-in for smtplib.SMTP recording what the mailer did."""

    instances = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port = host, port
        self.extensions = {"starttls"}
        self.started_tls = False
        self.logged_in = None
        self.sent = []
        type(self).instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def ehlo(self):
        return 250, b"ok"

    def has_extn(self, name):
        return name.lower() in self.extensions

    def starttls(self, context=None):
        self.started_tls = True

    def login(self, username, password):
        self.logged_in = (username, password)

    def send_message(self, msg):
        self.sent.append(msg)


@pytest.fixture
def smtp_cfg(monkeypatch):
    """In-memory SMTP settings, so no test touches app_settings.json."""
    stored = {}

    def _set(**overrides):
        cfg = {
            "enabled": True,
            "host": "smtp.example.com",
            "port": 587,
            "username": "sentinelnet@example.com",
            "password_enc": "",
            "from_email": "sentinelnet@example.com",
            "tls_mode": "starttls",
        }
        cfg.update(overrides)
        stored.update(cfg)
        return cfg

    monkeypatch.setattr(mailer, "get_config", lambda: dict(stored))
    monkeypatch.setattr(mailer.crypto_vault, "decrypt_password",
                        lambda _enc: "smtp-secret")
    FakeSMTP.instances = []
    return _set


def test_starttls_is_used_and_credentials_follow_it(smtp_cfg, monkeypatch):
    smtp_cfg()
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    mailer.send_email("operator@example.com", "Oggetto", "Corpo")

    server = FakeSMTP.instances[0]
    assert server.started_tls is True
    assert server.logged_in == ("sentinelnet@example.com", "smtp-secret")
    assert len(server.sent) == 1
    assert server.sent[0]["To"] == "operator@example.com"


def test_missing_starttls_aborts_before_login(smtp_cfg, monkeypatch):
    """A stripped STARTTLS capability is a downgrade attempt, not a reason to
    send the password in the clear."""
    smtp_cfg()

    class NoStartTLS(FakeSMTP):
        instances = []

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.extensions = set()

    monkeypatch.setattr(smtplib, "SMTP", NoStartTLS)

    with pytest.raises(mailer.MailerError, match="STARTTLS"):
        mailer.send_email("operator@example.com", "Oggetto", "Corpo")

    server = NoStartTLS.instances[-1]
    assert server.logged_in is None
    assert server.sent == []


def test_auth_without_tls_is_refused(smtp_cfg, monkeypatch):
    smtp_cfg(tls_mode="none")
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    with pytest.raises(mailer.MailerError, match="TLS"):
        mailer.send_email("operator@example.com", "Oggetto", "Corpo")

    assert FakeSMTP.instances[-1].logged_in is None


def test_anonymous_relay_without_tls_is_allowed(smtp_cfg, monkeypatch):
    """No username means nothing to leak: an internal relay stays usable."""
    smtp_cfg(tls_mode="none", username="")
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    mailer.send_email("operator@example.com", "Oggetto", "Corpo")

    server = FakeSMTP.instances[-1]
    assert server.logged_in is None
    assert len(server.sent) == 1


def test_implicit_tls_uses_smtp_ssl(smtp_cfg, monkeypatch):
    smtp_cfg(tls_mode="ssl", port=465)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)

    mailer.send_email("operator@example.com", "Oggetto", "Corpo")

    server = FakeSMTP.instances[-1]
    assert (server.host, server.port) == ("smtp.example.com", 465)
    assert server.started_tls is False  # already encrypted end to end
    assert server.logged_in == ("sentinelnet@example.com", "smtp-secret")


def test_disabled_service_refuses_to_send(smtp_cfg, monkeypatch):
    smtp_cfg(enabled=False)
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    with pytest.raises(mailer.MailerError, match="disabilitato"):
        mailer.send_email("operator@example.com", "Oggetto", "Corpo")
    assert FakeSMTP.instances == []


def test_invalid_recipient_is_rejected(smtp_cfg, monkeypatch):
    smtp_cfg()
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    with pytest.raises(mailer.MailerError, match="destinatario"):
        mailer.send_email("not-an-address", "Oggetto", "Corpo")
    assert FakeSMTP.instances == []


def test_transport_failure_becomes_mailer_error(smtp_cfg, monkeypatch):
    smtp_cfg()

    class Refused(FakeSMTP):
        instances = []

        def __init__(self, *a, **kw):
            raise OSError("connection refused")

    monkeypatch.setattr(smtplib, "SMTP", Refused)

    with pytest.raises(mailer.MailerError, match="Invio email fallito"):
        mailer.send_email("operator@example.com", "Oggetto", "Corpo")


def test_get_config_falls_back_to_defaults(monkeypatch):
    monkeypatch.setattr("services.mailer.get_app_settings",
                        lambda: {"smtp": {"host": "smtp.example.com",
                                          "port": "not-a-number",
                                          "tls_mode": "bogus"}})
    cfg = mailer.get_config()
    assert cfg["port"] == mailer.DEFAULT_PORT
    assert cfg["tls_mode"] == "starttls"
    assert cfg["enabled"] is False
