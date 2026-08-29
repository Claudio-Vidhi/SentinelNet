# -*- coding: utf-8 -*-
"""Device credentials: row decryption and the fallback chain (extracted from
core_engine.py — plan Phase 3 item 12; core_engine keeps re-exporting the
public names so call sites and test patch points are unchanged)."""

import os

from security.crypto_vault import decrypt_password

DEFAULT_USERNAME = os.getenv("SENTINELNET_ADMIN_USER", "admin")
DEFAULT_PASSWORD = os.getenv("SENTINELNET_ADMIN_PASS", "admin")
DEFAULT_SECRET   = os.getenv("SENTINELNET_ADMIN_SECRET", "admin")


class CredentialDecryptError(RuntimeError):
    """A device row stores ciphertext that no longer decrypts (key rotated,
    corrupt token). The connection must fail loudly instead of sliding into
    the default-credential fallback: silently dialling the whole fleet with
    the public default login is how a key rotation becomes an outage."""


def _fallback_credentials(device):
    """Credentials to use when the device row names none of its own.

    A site may declare a default identity for the devices behind it
    (site_manager: 'device_identity'). Without it the only fallback is the
    global admin account, which for a customer site behind a bastion means
    dialling that customer's devices with this installation's default
    login — the wrong credential, sent to the right device.
    """
    # hosts.csv rows carry 'Site'; the get_device_by_ip cache carries 'site'
    # (see services/inventory_manager.py). Both shapes reach this function.
    site_id = device.get('Site') or device.get('site') or ''
    if site_id:
        from services import site_manager
        from security import identity_manager
        site = site_manager.get_site(site_id)
        identity = (site or {}).get('device_identity')
        if identity:
            creds = identity_manager.get_identity_credentials(identity)
            if creds:
                return creds
    return DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_SECRET


def get_device_credentials(device):
    profile = device.get('Profile', 'custom').lower()
    if profile == 'default':
        return _fallback_credentials(device)
    if profile.startswith('identity:'):
        # Tenant identity (identity_manager): fallback to the site default if
        # the identity no longer exists (it should not: delete is blocked if in use).
        from security import identity_manager
        creds = identity_manager.get_identity_credentials(
            device.get('Profile', '')[len('identity:'):])
        if creds:
            return creds
        return _fallback_credentials(device)
    fb_user, fb_pass, fb_secret = _fallback_credentials(device)
    username = device.get('Username') or fb_user
    raw_password = device.get('Password')
    raw_secret = device.get('Enable Secret')
    password = decrypt_password(raw_password)
    secret = decrypt_password(raw_secret)
    dev_id = device.get('IP') or device.get('ip') or '?'
    if raw_password and not password:
        raise CredentialDecryptError(
            f"Credenziali del dispositivo {dev_id} non decifrabili "
            f"(chiave cambiata o token corrotto): connessione rifiutata "
            f"finche' non vengono reinserite.")
    if raw_secret and not secret:
        raise CredentialDecryptError(
            f"Enable secret del dispositivo {dev_id} non decifrabile "
            f"(chiave cambiata o token corrotto).")
    return username, password or fb_pass, secret or fb_secret
