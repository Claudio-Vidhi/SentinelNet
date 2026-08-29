# -*- coding: utf-8 -*-
"""Credenziali dispositivo: un token salvato che non si decifra deve fallire
in modo esplicito, mai scivolare sul fallback admin (WP2,
docs/app-review-fix-plan.md)."""

from unittest import mock

import pytest

from core import core_engine
from core import device_credentials


DEVICE = {"IP": "192.0.2.10", "Username": "operator1",
          "Password": "ciphertext-non-vuoto", "Enable Secret": ""}


def test_undecryptable_password_raises_instead_of_fallback():
    # decrypt_password ritorna "" su ogni fallimento (chiave cambiata/token
    # corrotto): la riga con credenziale salvata non deve ricadere sui default.
    with mock.patch.object(device_credentials, "decrypt_password", return_value=""):
        with pytest.raises(core_engine.CredentialDecryptError) as exc:
            core_engine.get_device_credentials(dict(DEVICE))
    assert "192.0.2.10" in str(exc.value)


def test_undecryptable_enable_secret_raises():
    device = dict(DEVICE, Password="", **{"Enable Secret": "ciphertext-segreto"})
    with mock.patch.object(device_credentials, "decrypt_password", return_value=""):
        with pytest.raises(core_engine.CredentialDecryptError):
            core_engine.get_device_credentials(device)


def test_successful_decrypt_returns_the_stored_password():
    def fake_decrypt(token):
        return "vera-password" if token else ""
    with mock.patch.object(device_credentials, "decrypt_password", side_effect=fake_decrypt):
        username, password, secret = core_engine.get_device_credentials(dict(DEVICE))
    assert username == "operator1"
    assert password == "vera-password"


def test_row_without_credentials_still_uses_fallback():
    device = {"IP": "192.0.2.11", "Username": "", "Password": "", "Enable Secret": ""}
    with mock.patch.object(device_credentials, "decrypt_password", return_value=""):
        username, password, secret = core_engine.get_device_credentials(device)
    assert (username, password, secret) == (
        core_engine.DEFAULT_USERNAME,
        core_engine.DEFAULT_PASSWORD,
        core_engine.DEFAULT_SECRET,
    )
