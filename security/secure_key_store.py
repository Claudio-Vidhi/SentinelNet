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
import logging

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
        buf = ctypes.create_string_buffer(data, len(data))
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
else:
    def _protect(data: bytes) -> bytes:
        raise NotImplementedError("DPAPI non disponibile su piattaforme non-Windows.")

    def _unprotect(blob: bytes) -> bytes:
        raise NotImplementedError("DPAPI non disponibile su piattaforme non-Windows.")


def _atomic_write(path: str, data: bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    # Restrict the temp file BEFORE it is renamed: it already holds the key,
    # and between the write and the replace it carried whatever permissions
    # the directory handed out. On POSIX os.replace keeps the source's mode,
    # so this is also what the final file inherits.
    data_config.restrict_permissions(tmp)
    os.replace(tmp, path)
    # ACL restrittive: solo l'utente corrente può leggere la chiave (DF-1).
    data_config.restrict_permissions(path)


def _store(path: str, key: bytes):
    """Scrive la chiave protetta con DPAPI su Windows, altrimenti in chiaro."""
    if _IS_WINDOWS:
        try:
            _atomic_write(path, _MAGIC + _protect(key))
            return
        except OSError as e:
            # DPAPI non disponibile: ripiega su file in chiaro. È un
            # declassamento di sicurezza, non deve restare invisibile.
            logging.warning(
                "DPAPI non disponibile (%s): chiave salvata in chiaro in %s", e, path
            )
    _atomic_write(path, key)


def load_or_create(path: str, generator) -> bytes:
    """Ritorna la chiave grezza (bytes).

    - Se il file non esiste, la genera con `generator()` e la salva protetta.
    - Se il file è un blob DPAPI, lo decifra (su Windows) o usa un file .posix derivato (su Linux/Docker).
    - Se il file è legacy in chiaro, lo usa così com'è e — su Windows — lo mette
      in sicurezza riscrivendolo come blob DPAPI, mantenendo lo stesso valore.
    """
    if os.path.exists(path):
        with open(path, "rb") as f:
            raw = f.read()
        if raw.startswith(_MAGIC):
            if not _IS_WINDOWS:
                posix_path = path + ".posix"
                if os.path.exists(posix_path):
                    with open(posix_path, "rb") as pf:
                        return pf.read()
                logging.warning(
                    "Chiave %s è protetta con DPAPI Windows: generazione chiave compatibile in %s",
                    path, posix_path
                )
                posix_key = generator()
                if isinstance(posix_key, str):
                    posix_key = posix_key.encode("utf-8")
                _atomic_write(posix_path, posix_key)
                return posix_key
            return _unprotect(raw[len(_MAGIC):])
        if _IS_WINDOWS:
            try:
                _atomic_write(path, _MAGIC + _protect(raw))
            except OSError as e:
                logging.warning(
                    "Chiave legacy in chiaro non migrata a DPAPI (%s): %s", e, path
                )
        return raw

    key = generator()
    if isinstance(key, str):
        key = key.encode("utf-8")
    _store(path, key)
    return key
