# -*- coding: utf-8 -*-
"""Restart and self-update of the central: which supervisor owns the process,
and the git pull -> dependencies -> restart sequence.

Lifted out of routers/settings.py, which was running the whole thing between
an auth dependency and a response dict. The HTTP layer keeps what is HTTP
(admin dependency, audit line, status code); everything below decides on its
own and says no by raising SelfUpdateError.

Every argv here is FIXED. Nothing from a request body reaches a command line:
a parameter for the remote, the branch or the unit name would turn the update
route into a remote shell on the machine that holds every site's credentials.
"""
import os
import subprocess
import sys


class SelfUpdateError(Exception):
    """Un rifiuto atteso: la rotta lo traduce in 409.

    Sempre 409 e mai 500 perche' ogni caso qui e' uno stato in cui la
    richiesta e' legittima ma la macchina non e' nelle condizioni di
    eseguirla -- nessun supervisore, nessun repository, git che fallisce."""


# Nome FISSO del servizio Windows. Non e' configurabile di proposito: e' il
# nome che finisce in una riga di comando, e un nome che arriva da fuori
# trasformerebbe questa rotta in una shell remota.
WINDOWS_SERVICE_NAME = "SentinelNet"

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def install_kind() -> str:
    """Come gira questa istanza: da repo git, da exe PyInstaller, o da una
    copia dei sorgenti senza repo. La terza non e' un dettaglio: chi ha
    scaricato uno zip non puo' aggiornare con git piu' di quanto possa un exe."""
    if getattr(sys, "frozen", False):
        return "exe"
    return "git" if os.path.isdir(os.path.join(_ROOT, ".git")) else "source"


def supervisor() -> str:
    """Chi rimettera' in piedi il processo dopo l'uscita: '' se nessuno.

    Su Linux: systemd esporta INVOCATION_ID a ogni unit che avvia, quindi la
    sua assenza significa che "riavvia" e' solo "termina".

    Su Windows non esiste una variabile equivalente -- un servizio non si
    distingue dall'esterno da un exe lanciato a mano -- quindi e' chi installa
    il servizio a dichiararlo con SENTINELNET_WINDOWS_SERVICE=1. Stessa
    logica del caso systemd: e' il supervisore a dire di esserci."""
    if os.environ.get("INVOCATION_ID"):
        return "systemd"
    if sys.platform == "win32" and os.environ.get("SENTINELNET_WINDOWS_SERVICE"):
        return "windows-service"
    # Un exe PyInstaller avviato a mano non ha nessuno che lo rialzi. Sotto un
    # servizio Windows invece e' normale che sia frozen, ed e' il ramo sopra
    # a coprirlo.
    return ""


def is_supervised() -> bool:
    """Compatibilita': le rotte ragionano su supervisor(), i test su questo."""
    return bool(supervisor())


def spawn_restart(kind: str) -> None:
    """Fa partire il riavvio delegandolo a un processo separato.

    Estratta perche' ha due chiamanti: il pulsante di riavvio e
    l'aggiornamento, che deve riavviare per applicare il codice appena
    scaricato. Due copie di questa logica divergerebbero, e la copia
    sbagliata sarebbe quella che spegne il pannello."""
    if kind == "windows-service":
        # Staccato, e senza aspettarlo: Restart-Service ferma QUESTO processo,
        # quindi un subprocess.run atteso non tornerebbe mai. Il prezzo e' che
        # l'esito non si conosce -- lo stesso prezzo di --no-block su Linux.
        try:
            subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Restart-Service", "-Name", WINDOWS_SERVICE_NAME],
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        except Exception as e:
            raise SelfUpdateError(f"Riavvio non disponibile: {e}")
    else:
        try:
            proc = subprocess.run(
                ["sudo", "-n", "systemctl", "start", "--no-block",
                 "sentinelnet-restart.service"],
                capture_output=True, text=True, timeout=15)
        except Exception as e:
            raise SelfUpdateError(f"Riavvio non disponibile: {e}")
        if proc.returncode != 0:
            raise SelfUpdateError(
                "sudo ha rifiutato il comando di riavvio: "
                f"{(proc.stderr or proc.stdout or '').strip()}")


def restart() -> str:
    """Riavvia delegando a un processo separato; torna il supervisore usato.

    L'app non si uccide MAI da sola: su Linux e' la unit oneshot
    sentinelnet-restart.service a riavviare sentinelnet.service, su Windows e'
    un powershell staccato a fare Restart-Service. Cosi' un riavvio fallito
    lascia in piedi il processo vecchio, invece di lasciare la macchina senza
    pannello."""
    kind = supervisor()
    if not kind:
        raise SelfUpdateError(
            "L'applicazione non e' gestita da un supervisore: un riavvio la "
            "spegnerebbe soltanto. Riavviala da systemd o dal gestore servizi "
            "di Windows.")
    spawn_restart(kind)
    return kind


def update() -> dict:
    """Aggiorna il centrale: git pull, dipendenze, riavvio. In quest'ordine.

    Torna ``{"status": "up-to-date" | "updating", ...}``; ogni rifiuto e' una
    SelfUpdateError. L'agente si aggiorna da solo dal 0.27.1; qui c'era ancora
    la sequenza a mano via SSH, cioe' la shell che questa tab esiste per
    evitare."""
    kind = install_kind()
    if kind != "git":
        raise SelfUpdateError(
            f"Installazione '{kind}': non c'e' un repository git da cui "
            "aggiornare. Sostituisci l'eseguibile, o reinstalla da sorgenti.")
    sup = supervisor()
    if not sup:
        # Scaricare il codice nuovo e non poterlo applicare lascia l'albero
        # avanti e il processo indietro: lo stato piu' confuso possibile.
        raise SelfUpdateError(
            "L'applicazione non e' gestita da un supervisore: "
            "l'aggiornamento non potrebbe essere applicato.")

    try:
        pull = subprocess.run(["git", "pull"], cwd=_ROOT, capture_output=True,
                              text=True, timeout=120)
    except Exception as e:
        raise SelfUpdateError(f"git non disponibile: {e}")
    output = (pull.stdout or "") + (pull.stderr or "")
    if pull.returncode != 0:
        raise SelfUpdateError(f"git pull fallito:\n{output.strip()[-2000:]}")
    if "Already up to date" in output:
        # Niente installazione e niente riavvio: interromperebbero le sessioni
        # aperte per applicare esattamente nulla.
        return {"status": "up-to-date", "output": output.strip()}

    # Le dipendenze PRIMA del riavvio, con l'interprete che sta girando: un
    # aggiornamento che ne aggiunge una, riavviato senza installarla, non
    # riparte piu' e lascia la rete senza pannello.
    dep = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r",
         os.path.join(_ROOT, "requirements.txt")],
        cwd=_ROOT, capture_output=True, text=True, timeout=900)
    if dep.returncode != 0:
        raise SelfUpdateError(
            "Dipendenze non installate, riavvio annullato (resta in "
            "esecuzione la versione precedente, che funziona):\n"
            f"{(dep.stderr or dep.stdout or '').strip()[-2000:]}")

    spawn_restart(sup)
    return {"status": "updating", "supervisor": sup, "output": output.strip()}
