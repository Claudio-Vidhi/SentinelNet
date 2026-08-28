# -*- coding: utf-8 -*-
"""SMTP delivery for password recovery, user invites and notifications.

Configuration lives in app_settings.json under "smtp"; the account password is
encrypted with crypto_vault like every other stored credential.

Transport security is a requirement, not a hint: when the configured mode is
starttls and the server does not advertise it, the connection is refused rather
than continued in the clear. Stripping the STARTTLS capability from an EHLO
reply is the cheapest way to harvest an SMTP password, and a mailer that
"tries TLS and carries on" hands it over.
"""
import smtplib
import ssl
from email.message import EmailMessage

from core.app_settings import get_app_settings, save_app_settings
from security import crypto_vault

DEFAULT_PORT = 587
TLS_MODES = ("starttls", "ssl", "none")
_TIMEOUT = 15


class MailerError(RuntimeError):
    """Configuration or delivery failure. The message is shown to the user."""


def get_config() -> dict:
    """Stored SMTP configuration with defaults applied."""
    cfg = get_app_settings().get("smtp") or {}
    try:
        port = int(cfg.get("port") or DEFAULT_PORT)
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    tls_mode = cfg.get("tls_mode")
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "host": (cfg.get("host") or "").strip(),
        "port": port,
        "username": (cfg.get("username") or "").strip(),
        "password_enc": cfg.get("password_enc") or "",
        "from_email": (cfg.get("from_email") or "").strip(),
        "tls_mode": tls_mode if tls_mode in TLS_MODES else "starttls",
    }


def save_config(cfg: dict) -> None:
    save_app_settings({"smtp": cfg})


def _authenticate(server, cfg: dict, password: str) -> None:
    """AUTH only over an encrypted channel: in the clear the password is
    readable by anyone on the path."""
    if not cfg["username"]:
        return
    if cfg["tls_mode"] == "none":
        raise MailerError("Autenticazione SMTP richiesta ma TLS disabilitato: "
                          "impostare STARTTLS oppure SSL.")
    server.login(cfg["username"], password)


def send_email(to: str, subject: str, body: str) -> None:
    """Delivers a plain-text message. Raises MailerError on any failure; the
    caller decides whether to surface it."""
    cfg = get_config()
    if not cfg["enabled"] or not cfg["host"]:
        raise MailerError("Servizio SMTP non configurato o disabilitato.")
    if not cfg["from_email"]:
        raise MailerError("Indirizzo mittente (from) non configurato.")
    if "@" not in to:
        raise MailerError(f"Indirizzo destinatario non valido: '{to}'.")

    msg = EmailMessage()
    msg["From"] = cfg["from_email"]
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    password = crypto_vault.decrypt_password(cfg["password_enc"])
    context = ssl.create_default_context()
    try:
        if cfg["tls_mode"] == "ssl":
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"],
                                  timeout=_TIMEOUT, context=context) as server:
                _authenticate(server, cfg, password)
                server.send_message(msg)
            return

        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=_TIMEOUT) as server:
            server.ehlo()
            if cfg["tls_mode"] == "starttls":
                if not server.has_extn("starttls"):
                    raise MailerError("Il server SMTP non offre STARTTLS: "
                                      "connessione rifiutata.")
                server.starttls(context=context)
                server.ehlo()
            _authenticate(server, cfg, password)
            server.send_message(msg)
    except MailerError:
        raise
    except (smtplib.SMTPException, OSError) as e:
        raise MailerError(f"Invio email fallito: {e}") from e


def send_test_email(to: str) -> None:
    """Delivery probe used by the settings panel to validate a configuration."""
    cfg = get_config()
    send_email(
        to,
        "SentinelNet - Test configurazione SMTP",
        "Messaggio di prova inviato da SentinelNet.\n\n"
        f"Server: {cfg['host']}:{cfg['port']} ({cfg['tls_mode']})\n"
        "Se lo stai leggendo, la configurazione SMTP e' corretta.\n",
    )
