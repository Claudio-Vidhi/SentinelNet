import json
import os
import hashlib
import secrets

USERS_JSON = "users.json"

def hash_password(password: str, salt: str = None) -> tuple:
    """Genera un hash sicuro SHA-256 usando un salt casuale."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return hashed, salt

def get_users():
    if not os.path.exists(USERS_JSON):
        return {}
    with open(USERS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

def has_any_user() -> bool:
    """Restituisce True se esiste almeno un utente registrato nel sistema."""
    return len(get_users()) > 0

def create_user(username: str, password: str) -> bool:
    users = get_users()
    if username in users:
        return False  # Utente già esistente
    
    hashed_password, salt = hash_password(password)
    users[username] = {
        "hashed_password": hashed_password,
        "salt": salt
    }
    
    with open(USERS_JSON, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)
    return True

def verify_user(username: str, password: str) -> bool:
    users = get_users()
    if username not in users:
        return False
    
    user_data = users[username]
    hashed_attempt, _ = hash_password(password, user_data["salt"])
    return hashed_attempt == user_data["hashed_password"] 
