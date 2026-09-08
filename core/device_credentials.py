# -*- coding: utf-8 -*-
"""Device credentials: row decryption and the fallback chain (extracted from
core_engine.py — plan Phase 3 item 12; core_engine keeps re-exporting the
public names so call sites and test patch points are unchanged)."""

import os

from security.crypto_vault import decrypt_password

# Empty by default ON PURPOSE. These used to default to "admin"/"admin", so a
# device row naming no credential of its own was dialled with a guessable
# login — against customer gear, in a loop, generating failed-auth lockouts
# that looked like network faults. They stay as an escape hatch for an
# installation that really does have one global account, but setting them is
# now a deliberate act, not the default.
DEFAULT_USERNAME = os.getenv("SENTINELNET_ADMIN_USER", "")
DEFAULT_PASSWORD = os.getenv("SENTINELNET_ADMIN_PASS", "")
DEFAULT_SECRET   = os.getenv("SENTINELNET_ADMIN_SECRET", "")


class CredentialDecryptError(RuntimeError):
    """A device row stores ciphertext that no longer decrypts (key rotated,
    corrupt token). The connection must fail loudly instead of sliding into
    the default-credential fallback: silently dialling the whole fleet with
    the public default login is how a key rotation becomes an outage."""


class CredentialResolveError(RuntimeError):
    """No credential can be resolved for the device: the row names none, its
    site declares no default identity, and no global account is configured.
    Failing here is the point — the alternative is inventing a login and
    sending it to the device."""


def _fallback_credentials(device):
    """Credentials to use when the device row names none of its own, or
    ``None`` when there are none to use.

    A site may declare a default identity for the devices behind it
    (site_manager: 'device_identity'). Without it the only fallback is the
    global admin account, which for a customer site behind a bastion means
    dialling that customer's devices with this installation's default
    login — the wrong credential, sent to the right device.

    Returning ``None`` rather than a made-up pair is what lets the caller
    fail loudly; see CredentialResolveError.
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
    if DEFAULT_USERNAME and DEFAULT_PASSWORD:
        return DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_SECRET
    return None


def _device_id(device):
    return device.get('IP') or device.get('ip') or '?'


def _require_fallback(device):
    creds = _fallback_credentials(device)
    if creds is None:
        raise CredentialResolveError(
            f"Nessuna credenziale per il dispositivo {_device_id(device)}: "
            f"il dispositivo non ha un'identita' assegnata e la sua sede non "
            f"dichiara un'identita' di default. Assegna un'identita' al "
            f"dispositivo prima di connetterti.")
    return creds


def get_device_credentials(device):
    profile = device.get('Profile', 'custom').lower()
    if profile == 'default':
        return _require_fallback(device)
    if profile.startswith('identity:'):
        # Tenant identity (identity_manager): fallback to the site default if
        # the identity no longer exists (it should not: delete is blocked if in use).
        from security import identity_manager
        creds = identity_manager.get_identity_credentials(
            device.get('Profile', '')[len('identity:'):])
        if creds:
            return creds
        return _require_fallback(device)
    fb_user, fb_pass, fb_secret = _fallback_credentials(device) or ('', '', '')
    username = device.get('Username') or fb_user
    raw_password = device.get('Password')
    raw_secret = device.get('Enable Secret')
    password = decrypt_password(raw_password)
    secret = decrypt_password(raw_secret)
    dev_id = _device_id(device)
    if raw_password and not password:
        raise CredentialDecryptError(
            f"Credenziali del dispositivo {dev_id} non decifrabili "
            f"(chiave cambiata o token corrotto): connessione rifiutata "
            f"finche' non vengono reinserite.")
    if raw_secret and not secret:
        raise CredentialDecryptError(
            f"Enable secret del dispositivo {dev_id} non decifrabile "
            f"(chiave cambiata o token corrotto).")
    password = password or fb_pass
    secret = secret or fb_secret
    # An empty enable secret is legitimate (plenty of devices need no enable);
    # an empty username or password is not — that is the case that used to
    # become admin/admin.
    if not username or not password:
        raise CredentialResolveError(
            f"Nessuna credenziale per il dispositivo {dev_id}: la riga di "
            f"inventario non contiene utente e password e la sua sede non "
            f"dichiara un'identita' di default. Assegna un'identita' al "
            f"dispositivo prima di connetterti.")
    return username, password, secret
