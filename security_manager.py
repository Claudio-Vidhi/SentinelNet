import os
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet
import jwt

KEY_FILE = "secret.key"
GITIGNORE_FILE = ".gitignore"

from crypto_vault import encrypt_password, decrypt_password, load_or_create_key

# Chiave JWT derivata in modo deterministico dalla chiave Fernet caricata da crypto_vault
_key = load_or_create_key()
JWT_SECRET_KEY = hashlib.sha256(_key).hexdigest()
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- CRYPTOGRAPHY ---

def encrypt_credentials(plain_text: str) -> str:
    """Cifra una stringa di credenziali delegando a crypto_vault."""
    return encrypt_password(plain_text)

def decrypt_credentials(cipher_text: str) -> str:
    """Decifra una stringa usando crypto_vault, con fallback per retrocompatibilità."""
    if not cipher_text:
        return ""
    decrypted = decrypt_password(cipher_text)
    if decrypted == "decryption_error":
        return cipher_text  # Fallback al testo originale (dati in chiaro)
    return decrypted

# --- JWT AUTHENTICATION ---

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """Genera un token JWT di accesso."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str) -> dict:
    """Valida un token JWT. Ritorna il payload se valido, altrimenti None."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None
