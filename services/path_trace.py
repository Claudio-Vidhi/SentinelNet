# -*- coding: utf-8 -*-
"""Percorso di un indirizzo attraverso gli apparati, letto dalle loro tabelle.

La vista Rotte mostra le tabelle; questa risponde alla domanda successiva:
**per quali apparati passa il traffico verso un indirizzo, e perche' su
ciascuno ha vinto quella riga**. Nessun pacchetto viene inviato: e' la tabella
che viene interpretata, non la rete che viene sondata. Restano percio' fuori le
policy che scartano, le interfacce down e i next-hop irraggiungibili, e la
vista lo dichiara invece di lasciar credere il contrario.

Per concatenare due salti serve un dato che le rotte da sole non danno:
**l'indirizzo delle interfacce**. Sapere che una rotta punta a 192.0.2.9 non
dice niente finche' non si sa quale apparato possiede 192.0.2.9. Da qui
``addresses_for``, che quel dato lo prende dove gia' esiste invece di aprire
una raccolta nuova:

- FortiGate: ``monitor/system/interface``, che la tab FortiGate interroga gia';
- Cisco: le rotte *local* (``L 10.0.0.1/32``) che il parser di `show ip route`
  estrae gia' — sono per definizione l'indirizzo di un'interfaccia.
"""
import ipaddress
import logging

logger = logging.getLogger("sentinelnet.path_trace")

# Distanza amministrativa per tipo, quando l'apparato non la dichiara. Sono i
# valori standard: servono a ordinare due rotte con lo stesso prefisso, e un
# numero dichiarato qui e' preferibile a uno nascosto dentro un ramo.
DEFAULT_AD = {"connected": 0, "local": 0, "static": 1, "bgp": 20,
              "eigrp": 90, "ospf": 110, "isis": 115, "rip": 120}

MAX_HOPS = 16


def _net(value):
    """``10.0.0.0/16`` in una rete, o None se non e' interpretabile."""
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


def _addr(value):
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def addresses_for(device, rows) -> list:
    """Gli indirizzi delle interfacce di UN apparato: ``[{iface, ip, network}]``.

    ``rows`` sono le righe gia' raccolte per quell'apparato: per uno switch
    bastano quelle, perche' una rotta local E' l'indirizzo di un'interfaccia.
    Per un FortiGate si chiede l'elenco interfacce, e se non risponde si resta
    senza: un salto che si ferma e' meglio di un salto attribuito all'apparato
    sbagliato.
    """
    out = []
    if (device.get("Vendor") or "").lower() == "fortinet":
        out.extend(_fortigate_addresses(device))
    for r in rows or []:
        if r.get("type") != "local":
            continue
        net = _net(r.get("network"))
        if net is None or net.prefixlen != 32:
            continue
        out.append({"iface": r.get("interface") or "",
                    "ip": str(net.network_address), "network": str(net)})
    return out


def _fortigate_addresses(device) -> list:
    from services import fortigate_service
    try:
        answer = fortigate_service.get_interfaces(device)
    except fortigate_service.FortiGateError as e:
        # Non solleva: senza interfacce il percorso si ferma a questo apparato,
        # e la vista lo dice. Non e' un motivo per non mostrare gli altri.
        logger.debug("interfacce non lette da %s: %s", device.get("IP"), e)
        return []
    data = answer.get("data")
    # L'endpoint monitor risponde con un dizionario per nome interfaccia; il
    # ripiego SSH risponde con testo, e da quello qui non si estrae niente.
    entries = list(data.values()) if isinstance(data, dict) else data
    if not isinstance(entries, (list, tuple)):
        return []
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # Alcune build di FortiOS chiamano il campo ipv4_address: la stessa
        # doppia lettura che fa gia' fortigate_service. Senza, l'apparato torna
        # zero indirizzi in silenzio e ogni suo next-hop diventa "fuori
        # inventario".
        ip = _addr(entry.get("ip") or entry.get("ipv4_address"))
        if ip is None:
            continue
        try:
            mask = int(entry.get("mask"))  # type: ignore[arg-type]
            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except (TypeError, ValueError):
            net = ipaddress.ip_network(f"{ip}/32")
        out.append({"iface": entry.get("name") or "", "ip": str(ip),
                    "network": str(net)})
    return out


def _num(value):
    """Un numero, anche quando l'apparato lo manda come stringa. None se non
    c'e' o non e' interpretabile: scartare "110" come se fosse assente fa
    sembrare uguali due rotte che non lo sono, e nasce un ECMP inventato."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ad(row) -> int:
    d = _num(row.get("distance"))
    if d is not None:
        return d
    return DEFAULT_AD.get(row.get("type"), 255)


def candidates(rows, dst) -> list:
    """Le rotte che coprono l'indirizzo, dalla piu' specifica in giu'.

    L'ordine e' quello con cui decide un apparato: prefisso piu' lungo, poi
    distanza amministrativa, poi metrica. Le rotte local (il /32
    dell'interfaccia) non sono rotte di inoltro e restano fuori."""
    target = _addr(dst)
    if target is None:
        return []
    out = []
    for r in rows:
        if r.get("type") == "local":
            continue
        net = _net(r.get("network"))
        if net is None or target not in net:
            continue
        metric = _num(r.get("metric"))
        out.append({**r, "prefixlen": net.prefixlen, "ad": _ad(r),
                    "metric": metric if metric is not None else 0})
    out.sort(key=lambda r: (-r["prefixlen"], r["ad"], r["metric"]))
    return out


def decided_by(cand) -> str:
    """Quale criterio ha deciso, fra le candidate ordinate.

    E' l'informazione che spiega la scelta: "vince il /24, e la distanza
    amministrativa non viene nemmeno guardata" e' il punto in cui si sbaglia a
    ragionare piu' spesso."""
    if len(cand) < 2:
        return "unica"
    first, second = cand[0], cand[1]
    if first["prefixlen"] != second["prefixlen"]:
        return "prefisso"
    if first["ad"] != second["ad"]:
        return "distanza"
    if first["metric"] != second["metric"]:
        return "metrica"
    return "ecmp"


def owner_of(hop_ip, addresses, exclude=None):
    """L'apparato che possiede quel next-hop, per IP di gestione.

    Si esclude quello da cui si esce: il next-hop sta su una rete connessa
    anche a lui, e senza il filtro ogni salto tornerebbe indietro. Si accetta
    solo l'indirizzo esatto di un'interfaccia — attribuire un salto per
    vicinanza di sottorete significherebbe inventare la topologia."""
    target = _addr(hop_ip)
    if target is None:
        return None
    for device_ip, addrs in addresses.items():
        if device_ip == exclude:
            continue
        if any(_addr(a.get("ip")) == target for a in addrs):
            return device_ip
    return None


def _on_own_lan(hop_ip, addrs) -> bool:
    """Il next-hop sta su una rete connessa dell'apparato: e' un host non
    gestito sulla sua LAN, non un salto verso l'esterno. La differenza cambia
    la frase che la vista scrive."""
    target = _addr(hop_ip)
    if target is None:
        return False
    for a in addrs or []:
        net = _net(a.get("network"))
        if net is not None and target in net:
            return True
    return False


def _name(devices_by_ip, ip) -> str:
    return (devices_by_ip.get(ip) or {}).get("Hostname") or ip


def _same_choice(a, b) -> bool:
    return (a["prefixlen"], a["ad"], a["metric"]) == (b["prefixlen"], b["ad"], b["metric"])


def trace(dst, start_ip, rows_by_device, addresses, devices_by_ip) -> dict:
    """Il percorso verso ``dst`` a partire dall'apparato ``start_ip``.

    Torna ``{"hops": [...], "outcome": ...}``. Gli esiti sono distinti perche'
    rispondono a domande diverse: consegna, uscita dal perimetro noto, nessuna
    rotta, anello, biforcazione ECMP.
    """
    hops = []
    seen = set()
    current = start_ip
    for _ in range(MAX_HOPS):
        if current not in rows_by_device:
            # L'apparato non e' fra quelli interrogati: il percorso si ferma
            # perche' manca la sua tabella, non perche' finisce li'.
            return {"hops": hops, "outcome": "non interrogato", "device_ip": current}
        if current in seen:
            hops.append({"device_ip": current, "device": _name(devices_by_ip, current),
                         "outcome": "anello"})
            return {"hops": hops, "outcome": "anello"}
        seen.add(current)

        rows = rows_by_device[current]
        cand = candidates(rows, dst)
        hop = {"device_ip": current, "device": _name(devices_by_ip, current),
               "from_backup": any(r.get("from_backup") for r in rows),
               "candidates": cand}
        if not cand:
            hop["outcome"] = "nessuna rotta"
            hops.append(hop)
            return {"hops": hops, "outcome": "nessuna rotta"}

        best = cand[0]
        hop["best"] = best
        hop["decided_by"] = decided_by(cand)
        tied = [r for r in cand if _same_choice(r, best)]
        if len(tied) > 1:
            hop["outcome"] = "biforcazione"
            hop["tied"] = tied
            hops.append(hop)
            return {"hops": hops, "outcome": "biforcazione",
                    "branches": [{"route": r,
                                  "next_device_ip": owner_of(r.get("gateway"),
                                                             addresses, current)}
                                 for r in tied]}
        if best.get("type") in ("connected", "local"):
            hop["outcome"] = "consegna"
            hops.append(hop)
            return {"hops": hops, "outcome": "consegna"}

        nxt = owner_of(best.get("gateway"), addresses, current)
        hop["next_device_ip"] = nxt
        hops.append(hop)
        if nxt is None:
            return {"hops": hops, "outcome": "fuori inventario",
                    "exit_hop": best.get("gateway"),
                    "exit_local": _on_own_lan(best.get("gateway"),
                                              addresses.get(current))}
        current = nxt
    # Sedici salti senza mai rivedere un apparato: non e' un anello, e' un
    # percorso piu' lungo di quanto questa vista segua. Chiamarlo anello
    # manderebbe l'operatore a cercare un giro che non c'e'.
    return {"hops": hops, "outcome": "limite salti"}


# --- Prova sul campo ---------------------------------------------------------
#
# Tutto quello che sta sopra legge tabelle. Questo pezzo, e solo questo, manda
# davvero dei pacchetti: un traceroute lanciato DALL'APPARATO di partenza verso
# la destinazione. Serve a rispondere alla domanda che il calcolo non puo'
# toccare — "e nella realta' ci passa?" — ed e' percio' un'azione esplicita
# dell'utente, non qualcosa che parte con la vista.

import re

# Un traceroute che attraversa mezza rete puo' impiegare parecchio: il numero
# di salti e' limitato perche' la risposta deve tornare mentre l'utente guarda.
PROBE_MAX_HOPS = 8

_HOP_LINE = re.compile(r"^\s*(?P<n>\d{1,2})\s+(?P<rest>.*)$")
_IP = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")


def probe_command(device, dst: str) -> str:
    """Il comando di traceroute per quel vendor.

    ``dst`` e' gia' stato validato come indirizzo dal chiamante: qui non si
    concatena nient'altro che quello, perche' questa stringa finisce in una
    shell di rete."""
    if (device.get("Vendor") or "").lower() == "fortinet":
        return f"execute traceroute {dst}"
    return f"traceroute {dst} numeric timeout 2 probe 2 ttl 1 {PROBE_MAX_HOPS}"


def parse_traceroute(output: str) -> list:
    """I salti di un traceroute: ``[{n, ip}]``, con ip vuoto se non ha risposto.

    Le righe senza risposta (`* * *`) restano nella lista con ip vuoto: sono
    un'informazione, non un buco da nascondere — un salto che non risponde a
    ICMP e' normale, un salto che manca del tutto no."""
    hops = []
    for raw in (output or "").splitlines():
        m = _HOP_LINE.match(raw.rstrip())
        if not m:
            continue
        n = int(m.group("n"))
        if hops and n <= hops[-1]["n"]:
            # Non e' una riga di salto: e' un'altra tabella che ricomincia da 1
            # (o l'eco del comando). Meglio fermarsi che inventare salti.
            continue
        ip = _IP.search(m.group("rest"))
        hops.append({"n": n, "ip": ip.group("ip") if ip else ""})
    return hops


def probe(device, dst: str) -> dict:
    """Traceroute dall'apparato verso ``dst``. Non solleva."""
    command = probe_command(device, dst)
    vendor = (device.get("Vendor") or "").lower()
    try:
        if vendor == "fortinet":
            from services import fortigate_service
            output = str(fortigate_service.ssh_command(device, command))
        else:
            from core import core_engine
            answer = core_engine.send_custom_command(device, command,
                                                     bypass_blacklist=True)
            if answer.get("status") != "success":
                return {"command": command,
                        "error": answer.get("message") or "sessione non riuscita"}
            output = str(answer.get("output") or "")
    except Exception as e:   # noqa: BLE001 — un traceroute fallito e' un esito
        return {"command": command, "error": str(e)}
    return {"command": command, "output": output, "hops": parse_traceroute(output)}


def compare(trace_result: dict, probe_hops) -> dict:
    """Il percorso calcolato contro quello che il traceroute ha visto.

    Confronta i next-hop attesi con gli indirizzi che hanno risposto, in
    ordine. Un next-hop atteso che non compare non e' di per se' un guasto (un
    apparato puo' non rispondere a ICMP): e' il punto da cui guardare, ed e'
    cosi' che va presentato."""
    expected = [h["best"].get("gateway") for h in trace_result.get("hops", [])
                if h.get("best") and h["best"].get("gateway")]
    seen = [h.get("ip") for h in (probe_hops or []) if h.get("ip")]
    seen_set = set(seen)
    return {
        "expected": expected,
        "seen": seen,
        "matched": [ip for ip in expected if ip in seen_set],
        "missing": [ip for ip in expected if ip not in seen_set],
        "unexpected": [ip for ip in seen if ip not in set(expected)],
    }
