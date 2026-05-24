import os
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"

def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as k_file:
            k_file.write(key)
        return key
    with open(KEY_FILE, "rb") as k_file:
        return k_file.read()

CIPHER_SUITE = Fernet(load_or_create_key())

def encrypt_password(password: str) -> str:
    if not password: return ""
    return CIPHER_SUITE.encrypt(password.encode()).decode()

def decrypt_password(token: str) -> str:
    if not token: return ""
    try:
        return CIPHER_SUITE.decrypt(token.encode()).decode()
    except Exception:
        return "decryption_error"
