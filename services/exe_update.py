# -*- coding: utf-8 -*-
"""Aggiornamento dell'installazione Windows: release GitHub -> installer.

Il pulsante "Aggiorna e riavvia" sapeva fare una cosa sola, `git pull`, e su
un'installazione da installer rispondeva soltanto che non c'era un repository.
Qui c'e' l'altra meta': si chiede a GitHub qual e' l'ultima release, si scarica
l'installer, se ne verifica l'impronta e lo si lancia in silenzio. L'installer
fa gia' il resto -- ferma il servizio, sostituisce il programma, NON tocca i
dati, riavvia.

Sicurezza, dato che qui si scarica ed esegue un binario:

- Il repository e' una COSTANTE. Niente che arrivi da una richiesta HTTP
  raggiunge un URL o una riga di comando: stessa regola di self_update.py, dove
  un parametro per il remote trasformerebbe la rotta in una shell remota.
- Solo HTTPS, e solo il dominio di GitHub.
- L'impronta SHA-256 la dichiara l'API di GitHub per ogni asset e viene
  verificata sul file scaricato PRIMA di eseguirlo. Un file che non corrisponde
  viene cancellato e non parte niente.
- Il nome dell'asset deve corrispondere allo schema atteso: non si esegue un
  allegato qualsiasi solo perche' e' nella release.

Resta un limite dichiarato: l'installer scrive in Program Files, che richiede
privilegi. Sotto il servizio Windows (LocalSystem) ci sono; avviata a mano da
un utente normale no, e un prompt UAC in sessione 0 non lo vedrebbe nessuno.
Per questo update() si rifiuta di procedere senza servizio invece di lanciare
un installer che fallirebbe in silenzio.
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile

import requests

from core.version import __version__

# Costante, mai un parametro. Vedi il docstring del modulo.
GITHUB_REPO = "Claudio-Vidhi/SentinelNet"
_LATEST_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

# L'asset che ci interessa, e nessun altro.
_ASSET_RE = re.compile(r"^SentinelNet-Setup-(\d+\.\d+\.\d+)\.exe$")
_DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")

_TIMEOUT = 20
_DOWNLOAD_TIMEOUT = 300
# Un installer sta abbondantemente sotto: oltre, qualcosa non torna e non vale
# la pena riempire il disco per scoprirlo.
_MAX_BYTES = 200 * 1024 * 1024


class ExeUpdateError(RuntimeError):
    """Rifiuto atteso: la rotta lo traduce in 409."""


def _version_tuple(v: str):
    return tuple(int(x) for x in v.split("."))


def is_newer(candidate: str, current: str) -> bool:
    try:
        return _version_tuple(candidate) > _version_tuple(current)
    except (ValueError, AttributeError):
        return False


def latest_release() -> dict:
    """L'ultima release pubblicata, o solleva.

    Torna {version, asset_name, url, digest, size}. Solleva se la release non
    porta un installer riconoscibile: senza asset non c'e' niente da fare, e
    dirlo e' meglio che tornare "aggiornato" quando non lo si e'.
    """
    try:
        r = requests.get(_LATEST_URL, timeout=_TIMEOUT,
                         headers={"Accept": "application/vnd.github+json",
                                  "User-Agent": "SentinelNet"})
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        raise ExeUpdateError(f"Impossibile contattare GitHub: {e}") from e
    except ValueError as e:
        raise ExeUpdateError(f"Risposta di GitHub non leggibile: {e}") from e

    for asset in data.get("assets") or []:
        match = _ASSET_RE.match(str(asset.get("name") or ""))
        if not match:
            continue
        url = str(asset.get("browser_download_url") or "")
        if not url.startswith("https://github.com/"):
            raise ExeUpdateError("URL dell'installer inatteso: non e' GitHub.")
        digest = _DIGEST_RE.match(str(asset.get("digest") or ""))
        return {
            "version": match.group(1),
            "asset_name": match.group(0),
            "url": url,
            # Puo' mancare su release vecchie: download_and_verify si rifiuta
            # di eseguire cio' che non puo' verificare.
            "digest": digest.group(1) if digest else "",
            "size": int(asset.get("size") or 0),
        }
    raise ExeUpdateError(
        f"La release {data.get('tag_name') or '?'} non contiene un installer "
        "SentinelNet-Setup-X.Y.Z.exe.")


def check() -> dict:
    """{'status': 'up-to-date'|'available', 'current': ..., 'latest': ...}."""
    rel = latest_release()
    available = is_newer(rel["version"], __version__)
    return {"status": "available" if available else "up-to-date",
            "current": __version__,
            "latest": rel["version"],
            "asset_name": rel["asset_name"],
            "size": rel["size"],
            "url": rel["url"]}


def _discard(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def download_and_verify(release: dict, dest_dir: str | None = None) -> str:
    """Scarica l'installer e ne verifica lo SHA-256. Torna il percorso.

    Senza impronta non si esegue niente: un binario scaricato e non verificato
    e' esattamente cio' che questa funzione esiste per evitare.
    """
    if not release.get("digest"):
        raise ExeUpdateError(
            "La release non dichiara un'impronta SHA-256 per l'installer: "
            "scaricalo a mano dalla pagina delle release.")

    dest_dir = dest_dir or tempfile.mkdtemp(prefix="sentinelnet-update-")
    path = os.path.join(dest_dir, release["asset_name"])
    sha = hashlib.sha256()
    written = 0
    try:
        with requests.get(release["url"], stream=True,
                          timeout=_DOWNLOAD_TIMEOUT,
                          headers={"User-Agent": "SentinelNet"}) as r:
            r.raise_for_status()
            with open(path, "wb") as fh:
                for chunk in r.iter_content(chunk_size=1024 * 256):
                    if not chunk:
                        continue
                    written += len(chunk)
                    if written > _MAX_BYTES:
                        raise ExeUpdateError(
                            "Installer piu' grande del previsto: interrotto.")
                    sha.update(chunk)
                    fh.write(chunk)
    except requests.RequestException as e:
        _discard(path)
        raise ExeUpdateError(f"Download fallito: {e}") from e
    except ExeUpdateError:
        _discard(path)
        raise

    if sha.hexdigest() != release["digest"]:
        _discard(path)
        raise ExeUpdateError(
            "L'impronta dell'installer scaricato non corrisponde a quella "
            "dichiarata da GitHub: file scartato, nessuna esecuzione.")
    return path


def spawn_installer(path: str, with_service: bool) -> None:
    """Lancia l'installer in silenzio e STACCATO, poi torna.

    Staccato perche' l'installer ferma il servizio, cioe' il processo che lo ha
    lanciato: da figlio morirebbe a meta' aggiornamento, lasciando il programma
    sostituito a meta' e il servizio giu'.

    /MERGETASKS mantiene selezionato il task del servizio: in modalita'
    silenziosa i task tornano ai valori predefiniti, e il predefinito e' senza
    servizio -- un aggiornamento lo lascerebbe deregistrato.
    """
    args = [path, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
    if with_service:
        args.append("/MERGETASKS=service")
    flags = (getattr(subprocess, "DETACHED_PROCESS", 0)
             | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    try:
        subprocess.Popen(args, close_fds=True, creationflags=flags)
    except OSError as e:
        raise ExeUpdateError(f"Avvio dell'installer fallito: {e}") from e


def update(supervisor_kind: str) -> dict:
    """Sequenza completa. ``supervisor_kind`` viene da self_update.supervisor().

    Senza servizio ci si ferma PRIMA di scaricare: l'installer chiederebbe
    privilegi che non ci sono, e un UAC in sessione 0 non lo vede nessuno.
    """
    if sys.platform != "win32":
        raise ExeUpdateError(
            "Aggiornamento dell'eseguibile disponibile solo su Windows.")
    if supervisor_kind != "windows-service":
        raise ExeUpdateError(
            "Aggiornamento automatico disponibile solo con il servizio "
            "Windows installato: l'installer scrive in Program Files e servono "
            "privilegi che questa istanza non ha. Scarica l'installer dalla "
            "pagina delle release e lancialo a mano, oppure reinstalla "
            "spuntando \"Esegui SentinelNet come servizio Windows\".")

    rel = latest_release()
    if not is_newer(rel["version"], __version__):
        return {"status": "up-to-date", "current": __version__,
                "latest": rel["version"]}

    path = download_and_verify(rel)
    spawn_installer(path, with_service=True)
    return {"status": "updating", "current": __version__,
            "latest": rel["version"], "installer": os.path.basename(path)}
