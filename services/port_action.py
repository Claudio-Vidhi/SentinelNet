# -*- coding: utf-8 -*-
"""Azioni sulla porta di accesso trovata dalla diagnosi. Per ora: il bounce.

Perché una rotta dedicata e non ``send-command``: un bounce richiede la modalità
di configurazione, e ``conf t`` sta nella blacklist dei comandi distruttivi
(``routers/commands.py``). Farlo passare da lì significherebbe insegnare agli
operatori a scavalcare la blacklist per un'operazione di routine — il modo più
rapido per rendere innocua una protezione. Qui il comando lo costruisce questo
modulo a partire da un'interfaccia già risolta: l'utente non digita nulla che
raggiunga l'apparato, quindi non c'è niente da scavalcare.

Perché non tutti i vendor: la sintassi di shut/no-shut non è la stessa ovunque, e
indovinarla su uno switch in produzione è peggio che dire di no. I vendor che non
stanno in ``BOUNCE_COMMANDS`` ricevono un rifiuto esplicito, non un tentativo.
"""

from typing import Optional

# device_type netmiko -> (comandi_giu', comandi_su). Il nome dell'interfaccia
# viene inserito da _build; nient'altro finisce in queste stringhe.
BOUNCE_COMMANDS = {
    "cisco_ios":  (["interface {i}", "shutdown"], ["interface {i}", "no shutdown"]),
    "cisco_xe":   (["interface {i}", "shutdown"], ["interface {i}", "no shutdown"]),
    "cisco_s300": (["interface {i}", "shutdown"], ["interface {i}", "no shutdown"]),
    "hp_procurve": (["interface {i}", "disable"], ["interface {i}", "enable"]),
    "aruba_os":    (["interface {i}", "disable"], ["interface {i}", "enable"]),
}

# Un nome di interfaccia e basta: lettere, cifre, '/', '.', ':', '-'. Serve a
# impedire che un'interfaccia costruita altrove porti un a capo e con esso un
# secondo comando dentro la sessione di configurazione.
import re
_IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9/.:\-]{0,62}$")


class PortActionError(Exception):
    """Errore d'uso: il chiamante lo traduce in 4xx, non in 500."""


def _build(device_type: str, interface: str):
    if not _IFACE_RE.match(interface or ""):
        raise PortActionError(f"Nome di interfaccia non valido: {interface!r}")
    pair = BOUNCE_COMMANDS.get(device_type)
    if not pair:
        raise PortActionError(
            f"Bounce non supportato per '{device_type}': la sintassi di questo "
            "vendor non è verificata e indovinarla su un apparato in produzione "
            "non è accettabile.")
    down, up = pair
    return ([c.format(i=interface) for c in down],
            [c.format(i=interface) for c in up])


def _params(device: dict):
    """(device_type netmiko, parametri di connessione). Condiviso dalle due
    azioni: il bounce e lo spegnimento persistente parlano allo stesso
    apparato nello stesso modo, e una sola copia non puo' divergere."""
    from core import core_engine

    vendor = (device.get("Vendor") or "").lower()
    try:
        _, netmiko_type = core_engine.resolve_driver(vendor)
    except ValueError as e:
        raise PortActionError(str(e))
    cli_kind, port = core_engine.get_cli_transport(device)
    username, password, secret = core_engine.get_device_credentials(device)
    return netmiko_type, {
        "device_type": core_engine._cli_device_type(netmiko_type, cli_kind),
        "host": device["IP"], "port": port, "username": username,
        "password": password, "secret": secret,
        "timeout": 20, "auth_timeout": 15, "banner_timeout": 15}


def set_admin_state(device: dict, interface: str, up: bool) -> dict:
    """Spegne (o riaccende) UNA interfaccia e la lascia cosi'.

    Il bounce ripristina da solo; questo no: e' l'isolamento che deve reggere
    finche' qualcuno non lo toglie. Passa dagli stessi comandi per vendor del
    bounce — un 'shutdown' mandato a un ProCurve non spegne niente e fa
    credere all'operatore che il client sia isolato.
    """
    from netmiko import ConnectHandler

    netmiko_type, params = _params(device)
    down, up_cmds = _build(netmiko_type, interface)
    cmds = up_cmds if up else down

    with ConnectHandler(**params) as conn:
        try:
            conn.enable()
        except Exception:                      # noqa: BLE001 - non tutti hanno enable
            pass
        output = conn.send_config_set(cmds)
    return {"interface": interface, "commands": cmds, "output": output,
            "admin_up": up}


def bounce(device: dict, interface: str, wait_s: float = 2.0) -> dict:
    """Spegne e riaccende UNA interfaccia. Ritorna l'esito dei due passaggi.

    Il ``no shutdown`` non è dentro un ``finally``: se il ``shutdown`` non è
    andato a buon fine la porta non è giù, e mandare comunque il comando di
    risalita nasconderebbe l'errore invece di riportarlo. Se invece è il
    ``no shutdown`` a fallire, la porta resta GIÙ e questo va detto forte —
    è l'unico esito di questa funzione che lascia la rete peggio di come
    l'ha trovata.
    """
    import time
    from netmiko import ConnectHandler

    netmiko_type, params = _params(device)
    down, up = _build(netmiko_type, interface)

    out: dict = {"interface": interface, "commands": {"down": down, "up": up}}
    with ConnectHandler(**params) as conn:
        try:
            conn.enable()
        except Exception:                      # noqa: BLE001 - non tutti hanno enable
            pass
        out["down_output"] = conn.send_config_set(down)
        out["down_ok"] = True
        time.sleep(max(0.0, wait_s))
        try:
            out["up_output"] = conn.send_config_set(up)
            out["up_ok"] = True
        except Exception as e:                 # noqa: BLE001 - va riportato, non ingoiato
            out["up_ok"] = False
            out["error"] = (f"la porta è stata spenta ma NON riaccesa ({e}): "
                            f"riaccendila a mano con '{up[-1]}' su {interface}")
    return out
