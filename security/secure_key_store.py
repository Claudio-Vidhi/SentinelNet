"""Archiviazione a riposo delle chiavi segrete locali (secret.key, jwt_secret.key).

Su Windows le chiavi vengono cifrate con DPAPI (CryptProtectData, ambito utente):
il file su disco diventa inutilizzabile se copiato su un'altra macchina o letto da
un altro account Windows, perché la decifratura è vincolata alle credenziali di
login dell'utente corrente. In questo modo la cifratura delle password apparati
(secret.key) e la firma dei token JWT (jwt_secret.key) non sono più esposte da un
semplice accesso in lettura ai file accanto all'eseguibile.

Su piattaforme non-Windows (es. container Linux) si mantiene il comportamento
classico su file in chiaro: in quei contesti si raccomandano le variabili
d'ambiente SENTINELNET_MASTER_KEY / SENTINELNET_JWT_SECRET, che hanno comunque
la precedenza e non toccano il disco.
"""
import os
import sys
import ctypes

from core import data_config

_IS_WINDOWS = sys.platform == "win32"

# Prefisso che marca i file scritti come blob DPAPI: distingue le chiavi protette
# da quelle legacy in chiaro e ne permette la migrazione senza corromperle.
_MAGIC = b"DPAPIv1:"

if _IS_WINDOWS:
    from ctypes import wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.restype = wintypes.HLOCAL
    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]

    # CRYPTPROTECT_UI_FORBIDDEN: nessun prompt interattivo (compatibile con servizi).
    _CRYPTPROTECT_UI_FORBIDDEN = 0x01

    def _to_blob(data: bytes) -> "_DATA_BLOB":
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    def _from_blob(blob: "_DATA_BLOB") -> bytes:
        raw = ctypes.string_at(blob.pbData, int(blob.cbData))
        _kernel32.LocalFree(blob.pbData)
        return raw

    def _protect(data: bytes) -> bytes:
        in_blob = _to_blob(data)
        out_blob = _DATA_BLOB()
        if not _crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None,
                                         None, _CRYPTPROTECT_UI_FORBIDDEN,
                                         ctypes.byref(out_blob)):
            raise OSError("CryptProtectData ha restituito un errore.")
        return _from_blob(out_blob)

    def _unprotect(blob: bytes) -> bytes:
        in_blob = _to_blob(blob)
        out_blob = _DATA_BLOB()
        if not _crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None,
                                           None, _CRYPTPROTECT_UI_FORBIDDEN,
                                           ctypes.byref(out_blob)):
            raise OSError("CryptUnprotectData ha restituito un errore.")
        return _from_blob(out_blob)


def dpapi_available() -> bool:
    return _IS_WINDOWS


def _atomic_write(path: str, data: bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    # ACL restrittive: solo l'utente corrente può leggere la chiave (DF-1).
    data_config.restrict_permissions(path)


def _store(path: str, key: bytes):
    """Scrive la chiave protetta con DPAPI su Windows, altrimenti in chiaro."""
    if _IS_WINDOWS:
        try:
            _atomic_write(path, _MAGIC + _protect(key))
            return
        except OSError:
            pass  # DPAPI non disponibile: ripiega su file in chiaro
    _atomic_write(path, key)


def load_or_create(path: str, generator) -> bytes:
    """Ritorna la chiave grezza (bytes).

    - Se il file non esiste, la genera con `generator()` e la salva protetta.
    - Se il file è un blob DPAPI, lo decifra. Un fallimento qui (es. profilo
      utente diverso) è deliberatamente fatale: meglio un errore esplicito che
      corrompere silenziosamente la chiave.
    - Se il file è legacy in chiaro, lo usa così com'è e — su Windows — lo mette
      in sicurezza riscrivendolo come blob DPAPI, mantenendo lo stesso valore.
    """
    if os.path.exists(path):
        with open(path, "rb") as f:
            raw = f.read()
        if raw.startswith(_MAGIC):
            return _unprotect(raw[len(_MAGIC):])
        if _IS_WINDOWS:
            try:
                _atomic_write(path, _MAGIC + _protect(raw))
            except OSError:
                pass
        return raw

    key = generator()
    if isinstance(key, str):
        key = key.encode("utf-8")
    _store(path, key)
    return key
