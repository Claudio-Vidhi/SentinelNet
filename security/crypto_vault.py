import os
import base64
import hashlib
from cryptography.fernet import Fernet
from core import data_config
from security import secure_key_store

KEY_FILE = data_config.get_path("secret.key")

def load_or_create_key():
    # 1. First tries to load the Master Key from the environment variable
    env_key = os.getenv("SENTINELNET_MASTER_KEY")
    if env_key:
        # Derives a deterministic valid 32-byte base64-encoded Fernet key via SHA-256 hashing
        hashed = hashlib.sha256(env_key.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(hashed)

    # 2. Fallback to a persistent local file, protected at rest with DPAPI on
    #    Windows (a file copied elsewhere is unusable). Legacy plaintext files
    #    are migrated in-place keeping the same key.
    return secure_key_store.load_or_create(KEY_FILE, Fernet.generate_key)

CIPHER_SUITE = Fernet(load_or_create_key())

import logging as _log

def encrypt_password(password: str) -> str:
    if not password: return ""
    return CIPHER_SUITE.encrypt(password.encode()).decode()

def decrypt_password(token: str) -> str:
    if not token:
        return ""
    try:
        return CIPHER_SUITE.decrypt(token.encode()).decode()
    except Exception as e:
        _log.warning(f"[crypto_vault] Decifrazione fallita: {e}. "
                     f"La chiave Fernet potrebbe essere cambiata.")
        return ""
