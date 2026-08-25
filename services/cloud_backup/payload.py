# -*- coding: utf-8 -*-
"""Optional client-side encryption of what is uploaded.

Off by default. When on, the offsite copy is unreadable without this install's
Fernet key store -- which is why the UI pairs the toggle with the instruction
to back that key up separately, offline.
"""

from security.crypto_vault import CIPHER_SUITE

SUFFIX = ".enc"


def encrypt_bytes(data: bytes) -> bytes:
    return CIPHER_SUITE.encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    return CIPHER_SUITE.decrypt(token)


def remote_name(rel_path: str, encrypted: bool) -> str:
    return rel_path + SUFFIX if encrypted else rel_path
