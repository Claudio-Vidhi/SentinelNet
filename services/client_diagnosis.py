# -*- coding: utf-8 -*-
"""Diagnosi end-to-end di UN client: L2 e L3 nello stesso referto.

Le due metà esistevano già ma non si erano mai incontrate nel codice:

    client_map()      →  a quale porta di quale switch è attaccato, in che VLAN
    flowpath.build()  →  che strada logica fa il traffico
    interface.state   →  come sta quella porta (link, contatori di errore)
    config backup     →  la sua VLAN passa sui trunk dello switch?
    FortiGate         →  quale policy governa il flusso, cosa dicono i log

Questo modulo non raccoglie nulla di nuovo: compone. Nessuna tabella nuova,
nessuna migrazione.

REGOLA EREDITATA DA ``flowpath.py``: ciò che non si sa viene DETTO. Ogni
sezione porta ``known`` oppure ``error``; il referto porta ``complete``. Una
diagnosi parziale e onesta vale più di una completa e inventata — qui più che
altrove, perché chi legge sta per andare a toccare la rete.
"""

import json
import logging
import re
import time
from typing import Any, Optional

logger = logging.getLogger("sentinelnet.diagnosis")

# Finestra su cui si contano i blocchi. Un'ora: abbastanza per vedere un
# problema in corso, abbastanza poco da non annegare nel rumore di ieri.
DENY_WINDOW_S = 3600
# Stesso tetto di flow_siem: src/dst non sono colonne, il filtro è in Python.
_MAX_SYSLOG_ROWS = 2000
# Due campioni bastano per una differenza di contatori; ne prendo qualcuno in
# più perché il poller può aver saltato un giro.
_IFACE_SAMPLES = 6
_IFACE_LOOKBACK_S = 7200

_MAC_RE = re.compile(r"[0-9a-fA-F]{2}([:\-.]?[0-9a-fA-F]{2}){5}")


def _section(result: dict, name: str, fn, *args, **kw) -> None:
    """Esegue una sezione isolandone l'errore.

    Stessa forma dell'helper locale in ``fortigate_service.diagnose_client``:
    una sorgente che non risponde produce una sezione in errore, non una
    diagnosi fallita. Chi sta diagnosticando un guasto ha bisogno di tutto
    quello che ancora funziona, non di un 500.
    """
    try:
        result["sections"][name] = fn(*args, **kw)
    except Exception as e:
        logger.debug("Sezione '%s' fallita: %s", name, e)
        result["sections"][name] = {"known": False, "error": str(e)}


# --- L2: dove sta il client, e come sta la sua porta -------------------------

def _pos_candidates(entries: list, l2rows: list, prefer_ip=None) -> list:
    """Le posizioni possibili del client, una per tenant, dalla più recente.

    Due sorgenti, due domande diverse. I binding ARP dicono che IP ha il client
    e chi lo fronteggia, ma esistono solo dove il gateway è interrogabile. Gli
    avvistamenti nelle MAC table dicono a quale porta è attaccato, e ci sono
    ovunque ci sia uno switch gestito.

    Prima si guardava SOLO l'ARP quando c'era, e la MAC table solo se l'ARP
    mancava del tutto. Così un portatile con un binding vecchio in una sede
    vinceva su un avvistamento di stamattina in un'altra: il referto descriveva
    dove il PC ERA STATO, non dove è.

    L'ordinamento è sul tempo della POSIZIONE (``port_last_seen``), non su
    quello del binding: la domanda è "dov'è attaccato adesso", e un ARP
    rinfrescato non sposta un cavo.

    ``prefer_ip``: chi ha cercato un INDIRIZZO ha chiesto di quell'indirizzo,
    non della macchina. Le posizioni che lo portano vanno prima, e solo fra
    quelle vale la recency — altrimenti cercare un IP risponderebbe su una
    sede dove quell'IP non esiste nemmeno.
    """
    out, seen = [], set()
    for e in entries:
        t = e.get("tenant")
        if t in seen:
            continue
        seen.add(t)
        out.append({
            "tenant": t, "site": e.get("site"),
            "mac": e.get("mac"), "ip": e.get("ip"),
            "client_type": e.get("client_type"),
            "switch_ip": e.get("switch_ip"), "switch_name": e.get("switch_name"),
            "switch_port": e.get("switch_port"), "port_vlan": e.get("port_vlan"),
            "gateway_ip": e.get("source_ip"), "gateway_name": e.get("source_name"),
            "gateway_type": e.get("source_type"),
            "binding_last_seen": e.get("last_seen"),
            "port_last_seen": e.get("port_last_seen"),
            "l2_only": False,
        })
    # Tenant che la MAC table conosce e l'ARP no: senza questi, una sede senza
    # visibilità L3 resterebbe invisibile anche quando è quella giusta.
    for r in l2rows:
        t = r.get("tenant")
        if t in seen:
            continue
        seen.add(t)
        out.append({
            "tenant": t, "site": r.get("site"),
            "mac": r.get("mac"), "ip": None, "client_type": None,
            "switch_ip": r.get("switch_ip"), "switch_name": r.get("switch_name"),
            "switch_port": r.get("interface"), "port_vlan": r.get("vlan"),
            "gateway_ip": None, "gateway_name": None, "gateway_type": None,
            "binding_last_seen": None, "port_last_seen": r.get("last_seen"),
            "l2_only": True,
        })
    out.sort(key=lambda c: (c.get("ip") == prefer_ip if prefer_ip else False,
                           c.get("port_last_seen") or c.get("binding_last_seen") or ""),
             reverse=True)
    return out


def _position(client: str, is_mac: bool, tenants) -> dict:
    """Posizione fisica del client: MAC, IP, switch, porta, VLAN, e il gateway
    che ne ha risposto l'ARP.

    Quando lo stesso client risulta in più tenant si sceglie la posizione più
    RECENTE e si espongono tutte le altre in ``tenants_available``: un
    portatile che gira fra sedi è il caso normale, non l'anomalia, e il
    referto deve partire da dov'è adesso lasciando raggiungibili le altre.
    """
    from collectors import mac_history
    kw = {"mac": client} if is_mac else {"ip": client}
    entries = mac_history.client_map(tenants=tenants, limit=50, **kw)
    if not is_mac:
        # ``search_arp`` filtra con LIKE 'ip%': cercando 192.0.2.1 tornano
        # anche 192.0.2.10 e 192.0.2.100. Per una diagnosi l'indirizzo deve
        # essere quello e basta.
        entries = [e for e in entries if e.get("ip") == client]

    # La MAC table si interroga per MAC: cercando per IP lo si ricava dal
    # binding, e se non c'è nemmeno quello non c'è niente da cui partire.
    mac = client if is_mac else (entries[0].get("mac") if entries else None)
    l2rows = mac_history.positions_for_mac(mac, tenants=tenants) if mac else []

    candidates = _pos_candidates(entries, l2rows, None if is_mac else client)
    if not candidates:
        if is_mac:
            return {"known": False,
                    "reason": "MAC mai visto: né un binding ARP né un "
                              "avvistamento nelle MAC table raccolte. Serve "
                              "una scansione MAC degli switch di accesso"}
        return {"known": False,
                "reason": "nessun binding ARP noto per questo IP: serve una "
                          "scansione ARP del gateway che ruota la VLAN di "
                          "questo client, oppure cerca per MAC — la posizione "
                          "fisica si ricava dalla sola MAC table"}

    best = candidates[0]
    out = {"known": True, **{k: v for k, v in best.items() if k != "l2_only"}}
    if best["l2_only"]:
        # Quello che si perde è dichiarato, non lasciato a zero: senza binding
        # non c'è IP e non c'è gateway, quindi le sezioni che dipendono dal
        # firewall diranno di non sapere — correttamente, perché nessuno sa
        # quale firewall fronteggi un client di cui non si conosce
        # l'indirizzo. Quello che resta — switch, porta, VLAN, salute del
        # collegamento, catena di trunk, cronologia, bounce della porta — è
        # esattamente ciò che serve a chi sta cercando un cavo.
        out["l2_only"] = True
        out["binding_reason"] = (
            "nessun binding ARP per questo MAC in questo tenant: IP e gateway "
            "restano ignoti, la posizione fisica arriva dalla MAC table. Le "
            "sezioni che dipendono dal firewall non hanno un indirizzo su cui "
            "lavorare")

    if not best.get("switch_port"):
        out["port_known"] = False
        out["port_reason"] = ("MAC mai visto su una porta di accesso: manca "
                              "una scansione MAC, o il client è dietro un "
                              "apparato non gestito")
    else:
        out["port_known"] = True

    # Ambiguo è un ALTRO MAC sullo stesso indirizzo: o il MAC è cambiato, o due
    # host se lo contendono. Non lo si risolve qui, ma tacerlo sarebbe peggio.
    #
    # Lo stesso MAC che ricompare NON è ambiguità: la chiave di ``arp_entries``
    # è (mac, ip, source_ip), quindi un host visto da due gateway — normale
    # dove più apparati fronteggiano la stessa VLAN — produce due righe dello
    # stesso binding. Elencarle mostrava lo stesso MAC due volte sotto il
    # titolo "altri binding", cioè un allarme per la configurazione normale.
    others, seen_macs = [], {best.get("mac")}
    for x in entries:
        if x.get("mac") in seen_macs:
            continue
        seen_macs.add(x.get("mac"))
        others.append({"mac": x.get("mac"), "ip": x.get("ip"),
                       "gateway_ip": x.get("source_ip"),
                       "last_seen": x.get("last_seen")})
        if len(others) >= 5:
            break
    if others:
        out["ambiguous"] = others

    if len(candidates) > 1:
        out["tenants_available"] = [{
            "tenant": c["tenant"], "site": c["site"], "ip": c["ip"],
            "mac": c["mac"], "switch_name": c["switch_name"] or c["switch_ip"],
            "switch_port": c["switch_port"], "last_seen": c["port_last_seen"],
            "l2_only": c["l2_only"],
        } for c in candidates]
    return out


def _interface_health(switch_ip: str, port: str) -> dict:
    """Stato e contatori di errore della porta di accesso, dagli eventi
    ``interface.state`` già raccolti dal poller SNMP.

    I contatori ci sono da sempre (ifInErrors/ifOutErrors) ma non li leggeva
    nessuno: normalize.py li marca volatili — giustamente, un contatore che
    sale non è un cambio di configurazione — e nessuna regola li guardava. Qui
    servono, perché "il sito si carica male" spesso è una porta che erra.
    """
    from core import db
    from core.core_engine import _normalize_iface

    conn = db.get_observability_connection()
    try:
        rows = [dict(r) for r in conn.execute(
            """SELECT ts, interface, attrs_json FROM events
               WHERE event_type = 'interface.state' AND device_ip = ?
                 AND ts >= ? ORDER BY ts DESC LIMIT 400""",
            (switch_ip, int(time.time()) - _IFACE_LOOKBACK_S)).fetchall()]
    finally:
        conn.close()

    # Il nome della porta arriva da due mondi: la MAC table lo scrive esteso
    # ('GigabitEthernet1/0/1'), SNMP usa ifName ('Gi1/0/1'). Il confronto passa
    # dal normalizzatore che il codice già usa per far combaciare config e
    # CDP, invece di aggiungerne un terzo.
    want = _normalize_iface(port)
    samples = [r for r in rows if _normalize_iface(r["interface"] or "") == want]
    if not samples:
        return {"known": False,
                "reason": f"nessuno snapshot SNMP recente per {switch_ip}:{port} "
                          "(SNMP non configurato su questo apparato?)"}

    parsed = []
    for r in samples[:_IFACE_SAMPLES]:
        try:
            parsed.append((r["ts"], json.loads(r["attrs_json"] or "{}")))
        except ValueError:
            continue
    if not parsed:
        return {"known": False, "reason": "snapshot illeggibile"}

    ts_new, newest = parsed[0]
    out: dict = {"known": True, "interface": samples[0]["interface"],
                 "observed_ts": ts_new,
                 "link": newest.get("link"),
                 "admin_status": newest.get("admin_status"),
                 # VLAN letta dall'apparato adesso, non quella della MAC table:
                 # è il confronto fra le due che smaschera una porta spostata
                 # di VLAN dopo l'ultima scansione.
                 "port_vlan": newest.get("port_vlan"),
                 "speed": newest.get("speed")}

    if len(parsed) > 1:
        ts_old, oldest = parsed[-1]
        deltas: dict[str, Optional[int]] = {}
        for key in ("in_errors", "out_errors"):
            new_v, old_v = newest.get(key), oldest.get(key)
            if isinstance(new_v, (int, float)) and isinstance(old_v, (int, float)):
                # Un contatore che scende significa riavvio dell'apparato o
                # wrap: la differenza non vorrebbe dire niente.
                deltas[key] = int(new_v - old_v) if new_v >= old_v else None
        out["error_delta"] = deltas
        out["error_window_s"] = ts_new - ts_old
        out["erroring"] = any(v for v in deltas.values() if v)
    else:
        # Un campione solo: il valore assoluto non dice se gli errori sono di
        # adesso o di sei mesi fa. Meglio dichiararlo che farlo passare per
        # una misura.
        out["error_delta"] = None
        out["error_note"] = ("un solo campione nella finestra: impossibile "
                             "dire se i contatori stanno salendo")
    return out


def _trunk_check(switch_ip: str, vlan, facing: Optional[str] = None) -> dict:
    """La VLAN del client passa sui trunk di QUESTO apparato?

    È il guasto classico di una topologia con trunk: la porta di accesso è
    giusta, la VLAN esiste, e il traffico non esce perché il trunk verso monte
    non la trasporta.

    ``facing``: se dato, si guarda SOLO l'interfaccia che punta al salto
    successivo invece di tutti i trunk. Un trunk che va da un'altra parte non
    sta sul percorso di questo client, e contarlo come mancante è il falso
    positivo più facile da produrre qui dentro. Lo usa ``_trunk_chain``, che
    la catena la conosce; chiamata senza, il comportamento è quello storico.
    """
    if not vlan:
        return {"known": False, "reason": "VLAN della porta sconosciuta"}
    from ai import config_analyzer
    from core.core_engine import _normalize_iface

    analysis = config_analyzer.analyze_device(switch_ip)
    if not analysis:
        return {"known": False,
                "reason": f"nessun backup di configurazione per {switch_ip}"}
    trunks = [i for i in analysis.get("interfaces", [])
              if i.get("mode") == "trunk"]
    if facing:
        want = _normalize_iface(facing)
        trunks = [i for i in trunks
                  if _normalize_iface(i.get("name") or "") == want]
        if not trunks:
            return {"known": False,
                    "reason": f"{facing} non risulta in modo trunk nella config "
                              f"di {switch_ip}"}
    if not trunks:
        return {"known": False,
                "reason": "nessuna interfaccia in modo trunk nella config"}

    vlan = str(vlan).strip()
    missing, carrying = [], []
    for i in trunks:
        allowed = i.get("trunk_allowed") or ""
        if not allowed:
            # 'switchport mode trunk' senza allowed-vlan = TUTTE le VLAN
            # passano (default IOS). Segnalarlo come mancante sarebbe il falso
            # positivo più facile da produrre in tutta questa funzione.
            carrying.append({"interface": i.get("name"), "allowed": "all (default)"})
            continue
        if vlan in config_analyzer._expand_vlan_list(allowed):
            carrying.append({"interface": i.get("name"), "allowed": allowed})
        else:
            missing.append({"interface": i.get("name"), "allowed": allowed})

    return {"known": True, "vlan": vlan,
            "carrying": carrying, "missing": missing,
            "ok": not missing,
            "scope": "solo i trunk di questo switch, non l'intero percorso"}


_TRUNK_CHAIN_MAX_HOPS = 8


def _hop_path(access_ip: str, gateway_ip: str, tenant: Optional[str]) -> list:
    """Catena di apparati dallo switch di accesso al gateway, con le porte.

    Cammina i link di ``generate_network_map()``, che il progetto ricava già dal
    CDP/LLDP dei backup ed espone in cache. Ritorna una lista di
    ``{"device", "egress"}``: l'apparato e l'interfaccia con cui guarda il salto
    dopo. L'ultimo elemento è il gateway, che non ha egress.

    BFS e non DFS perché serve il percorso più corto: in una rete magliata la
    prima strada trovata a caso può girare per mezza topologia e la catena di
    trunk da controllare diventa una diversa da quella che il traffico fa
    davvero. ``visited`` evita i cicli, ``_TRUNK_CHAIN_MAX_HOPS`` evita di
    camminare all'infinito una topologia malata.
    """
    from collections import deque
    from core import core_engine

    netmap = core_engine.generate_network_map(tenant or None)
    adj: dict = {}
    for link in netmap.get("links", []):
        src, tgt = link.get("source"), link.get("target")
        if not src or not tgt or src == tgt:
            continue
        adj.setdefault(src, []).append((tgt, link.get("local_port")))
        adj.setdefault(tgt, []).append((src, link.get("remote_port")))

    if access_ip not in adj:
        return []
    queue = deque([[(access_ip, None)]])
    visited = {access_ip}
    while queue:
        chain = queue.popleft()
        node = chain[-1][0]
        if node == gateway_ip:
            return [{"device": d, "egress": p} for d, p in chain]
        if len(chain) > _TRUNK_CHAIN_MAX_HOPS:
            continue
        for neighbour, egress in adj.get(node, []):
            if neighbour in visited:
                continue
            visited.add(neighbour)
            queue.append(chain[:-1] + [(node, egress), (neighbour, None)])
    return []


def _trunk_chain(access_switch_ip: str, gateway_ip: Optional[str], vlan,
                 tenant: Optional[str] = None) -> dict:
    """La VLAN del client passa su TUTTA la catena fino al gateway?

    Controllare il solo switch di accesso risponde a metà della domanda: la
    VLAN può essere ammessa sul suo uplink e cadere due salti più su, e il
    sintomo per chi sta al PC è identico.

    Un salto senza backup di configurazione è ``unknown``, non un salto
    promosso: la catena in quel caso non è ``ok`` e ``reason`` dice quale
    anello manca. È la stessa convenzione di ``_path`` — ``complete``
    significa "non ci sono buchi nel racconto", non "va tutto bene" — e qui
    conta il doppio, perché chi legge sta per andare a toccare la rete.

    Senza topologia utilizzabile (nessun backup con CDP/LLDP, gateway non
    raggiungibile nella mappa) si degrada al controllo del solo switch di
    accesso, dicendolo: metà risposta dichiarata batte nessuna risposta.
    """
    if not vlan:
        return {"known": False, "reason": "VLAN della porta sconosciuta"}

    chain = _hop_path(access_switch_ip, gateway_ip, tenant) if gateway_ip else []
    if not chain:
        single = _trunk_check(access_switch_ip, vlan)
        single["scope"] = (
            "solo i trunk dello switch di accesso: nessun gateway noto per "
            "questo client, quindi non c'è una catena da percorrere"
            if not gateway_ip else
            "solo i trunk dello switch di accesso: la topologia non collega "
            "quell'apparato al gateway (servono i backup con CDP/LLDP dei "
            "salti intermedi)")
        single["chain_known"] = False
        return single

    hops, missing, unknown = [], [], []
    # L'ultimo anello è il gateway: ci arriva il traffico, non lo attraversa in
    # trunk verso un salto successivo, quindi non ha un egress da controllare.
    for hop in chain[:-1]:
        device, egress = hop["device"], hop["egress"]
        res = _trunk_check(device, vlan, facing=egress)
        entry = {"device": device, "egress": egress}
        if not res.get("known"):
            entry.update({"verdict": "unknown", "reason": res.get("reason")})
            unknown.append(device)
        elif res.get("ok"):
            entry.update({"verdict": "carrying",
                          "allowed": (res.get("carrying") or [{}])[0].get("allowed")})
        else:
            entry.update({"verdict": "missing",
                          "allowed": (res.get("missing") or [{}])[0].get("allowed")})
            missing.append(device)
        hops.append(entry)

    out = {"known": True, "vlan": str(vlan).strip(), "chain_known": True,
           "hops": hops, "gateway": chain[-1]["device"],
           "missing": missing, "unknown": unknown,
           "ok": not missing and not unknown,
           "scope": f"catena completa: {len(hops)} salti fino al gateway"}
    if missing:
        out["reason"] = "VLAN non ammessa su: " + ", ".join(missing)
    elif unknown:
        out["reason"] = "salti senza configurazione nota: " + ", ".join(unknown)
    return out


def _path(src_ip: str, dst_ip: str, tenant: str,
          dst_tenant: Optional[str] = None) -> dict:
    """Percorso logico, tradotto nel vocabolario del referto.

    ``flowpath.build`` parla di ``complete``, tutte le altre sezioni di
    ``known``. Il ponte sta qui e non allentando il controllo a valle: un
    percorso con un salto ignoto NON e' un percorso noto, ed e' esattamente il
    caso in cui serve dire quale salto manca.
    """
    from observability import flowpath

    path = flowpath.build(src_ip, dst_ip, tenant, dst_tenant)
    unknown = [h.get("label") or h.get("kind") for h in path["hops"]
               if not h.get("known")]
    out = {"known": bool(path["complete"]), **path}
    if unknown:
        out["reason"] = "salti sconosciuti: " + "; ".join(unknown)
    return out


def _l2_health(position: dict) -> dict:
    """Salute del primo salto: la porta di accesso e i trunk dello switch."""
    if not position.get("known") or not position.get("switch_port"):
        return {"known": False,
                "reason": "posizione fisica sconosciuta: niente porta da esaminare"}
    switch_ip = position.get("switch_ip")
    if not switch_ip:
        return {"known": False, "reason": "switch di accesso sconosciuto"}

    out: dict = {"known": True, "switch_ip": switch_ip,
                 "switch_port": position.get("switch_port")}
    try:
        out["interface"] = _interface_health(switch_ip, position["switch_port"])
    except Exception as e:
        out["interface"] = {"known": False, "error": str(e)}

    # La VLAN arriva da due fonti con età diverse: la MAC table (l'ultima
    # scansione, manuale) e SNMP (l'ultimo poll, automatico). Se non
    # coincidono la porta è stata spostata di VLAN dopo la scansione — il caso
    # in cui il client "è ancora lì" ma non è più nella rete di prima. Si usa
    # la VLAN VIVA per il controllo sui trunk: controllare quella vecchia
    # risponderebbe alla domanda di ieri.
    live_vlan = (out["interface"].get("port_vlan")
                 if isinstance(out.get("interface"), dict) else None)
    table_vlan = position.get("port_vlan") or position.get("vlan")
    if live_vlan and table_vlan and str(live_vlan) != str(table_vlan):
        out["vlan_mismatch"] = {
            "live": str(live_vlan), "mac_table": str(table_vlan),
            "note": "la porta è stata spostata di VLAN dopo l'ultima scansione "
                    "MAC: rilancia una MAC scan per riallineare la Client Map"}
    vlan = live_vlan or table_vlan

    try:
        out["trunk"] = _trunk_chain(switch_ip, position.get("gateway_ip"), vlan,
                                    position.get("tenant"))
    except Exception as e:
        out["trunk"] = {"known": False, "error": str(e)}
    return out


# --- Di quale sede e' questo indirizzo, e chi lo fronteggia ------------------

def resolve_endpoint(ip: str, tenants=None) -> dict:
    """{tenant, site, gateway_ip, gateway_type} per un indirizzo qualsiasi.

    Due livelli, in quest'ordine:

    1. OSSERVATO — se un gateway gestito ha risposto all'ARP per quell'IP,
       ``arp_entries`` sa tenant, sede e chi ha risposto. E' un fatto misurato.
    2. DICHIARATO — altrimenti si guarda se l'indirizzo cade in una delle
       ``subnets`` che l'operatore ha scritto nella scheda della sede. Il
       campo esisteva da sempre ed era solo documentazione.

    NON contraddice ADR-0005. Quell'ADR vieta di INDOVINARE il tenant in
    ingestione per un record di flusso, perche' un dato attribuito male
    avvelena lo scoping di tutti. Qui siamo in lettura, su un fatto
    DICHIARATO dall'operatore, mostrato a una persona e marcato ``derived``
    — lo stesso contratto di ``vlan_real: false`` nel grafo dei flussi.
    """
    import ipaddress

    from collectors import mac_history

    for e in mac_history.search_arp(ip=ip, tenants=tenants, limit=20):
        # search_arp filtra con LIKE 'ip%': 192.0.2.1 pesca anche 192.0.2.10.
        if e.get("ip") != ip:
            continue
        return {"known": True, "derived": "observed-arp",
                "tenant": e.get("tenant"), "site": e.get("site"),
                "gateway_ip": e.get("source_ip"),
                "gateway_type": e.get("source_type")}

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"known": False, "reason": f"'{ip}' non e' un indirizzo IP"}

    from services import site_manager
    for site in site_manager.list_sites():
        for raw in site.get("subnets") or []:
            try:
                net = ipaddress.ip_network(str(raw).strip(), strict=False)
            except ValueError:
                # Il campo non e' mai stato validato: una riga scritta male
                # non deve far fallire la risoluzione delle altre.
                continue
            if addr in net:
                return {"known": True, "derived": "declared-subnet",
                        "tenant": None, "site": site.get("id"),
                        "subnet": str(net), "gateway_ip": None,
                        "gateway_type": None}

    return {"known": False,
            "reason": "indirizzo mai osservato e non compreso in nessuna "
                      "subnet dichiarata delle sedi"}


# --- L3: quale firewall, quale policy, quanti blocchi ------------------------

def _resolve_fortigate(position: dict) -> dict:
    """Quale FortiGate governa questo client.

    Prima scelta: l'apparato che ha risposto all'ARP — per costruzione è il
    gateway di quella VLAN, ed è già in ``client_map``. Se a rispondere è
    stata una SVI di switch il firewall sta più a monte e da qui non si vede:
    in quel caso, se di FortiGate configurati ce n'è uno solo, è lui; se sono
    tanti, si dice che non si sa invece di tirare a indovinare.
    """
    from services import fortigate_service, inventory_manager

    targets = {t["ip"]: t for t in fortigate_service.list_targets()}
    devices = {d.get("IP"): d for d in inventory_manager.get_all_devices()}

    gw = position.get("gateway_ip") if position.get("known") else None
    if gw and gw in targets and (devices.get(gw, {}).get("Vendor") or "").lower() == "fortinet":
        return {"known": True, "ip": gw, "device": devices[gw],
                "resolved_by": "gateway ARP del client"}

    fortinets = [ip for ip in targets
                 if (devices.get(ip, {}).get("Vendor") or "").lower() == "fortinet"]
    if len(fortinets) == 1:
        return {"known": True, "ip": fortinets[0], "device": devices[fortinets[0]],
                "resolved_by": "unico FortiGate configurato"}
    if not fortinets:
        return {"known": False,
                "reason": "nessun FortiGate con token API configurato"}
    return {"known": False,
            "reason": f"{len(fortinets)} FortiGate configurati e il gateway del "
                      f"client ({gw or 'sconosciuto'}) non è fra loro: "
                      "impossibile dire quale sia sul percorso",
            "candidates": fortinets}


def _is_agent_site(site_id: str) -> bool:
    """La sede è gestita da un agente (il centrale non raggiunge i suoi
    apparati in REST diretta)."""
    from services import site_manager
    site = site_manager.get_site(site_id or "central")
    return bool(site and site.get("mode") == "agent")


def _relay_policy_lookup(device: dict, site_id: str, src_ip: str, dest: str,
                         dest_port, protocol: str) -> dict:
    """Policy lookup su un FortiGate di una sede agent, tramite relay.

    Il centrale non raggiunge quell'apparato e ``policy-lookup`` non ha un
    equivalente CLI: senza relay la domanda più utile della diagnosi resta
    senza risposta proprio nelle sedi dove non si può andare a mano.

    L'agente esegue in polling (default 60s), quindi qui NON si aspetta: si
    accoda e si torna subito. Il risultato viene raccolto alla chiamata
    successiva — il bottone "Rilancia" del referto esiste per questo.
    """
    from services import site_manager

    path = "monitor/firewall/policy-lookup"
    params = {"srcip": src_ip, "protocol": (protocol or "TCP").lower(),
              "dest": dest, "destport": int(dest_port or 443), "ipv6": "false"}
    spec = json.dumps({"path": path, "params": params})

    done = site_manager.find_recent_rest_result(site_id, device["IP"], path)
    if done and done["status"] == "done":
        try:
            data = json.loads(done["result"])
        except (TypeError, ValueError):
            data = done["result"]
        return {"known": True, "source": "relay",
                "data": data.get("results", data) if isinstance(data, dict) else data}
    if done:
        return {"known": False, "source": "relay",
                "reason": f"l'agente ha risposto con un errore: {done['result']}"}

    if not site_manager.has_pending_rest_job(site_id, device["IP"], path):
        try:
            site_manager.enqueue_job(site_id, device["IP"], spec,
                                     requested_by="diagnosi client", kind="rest")
        except ValueError as e:
            return {"known": False, "reason": str(e)}
    return {"known": False, "source": "relay", "pending": True,
            "reason": f"sede '{site_id}' in modalita' agent: richiesta accodata, "
                      "l'agente la eseguira' al prossimo poll (max ~60s). "
                      "Rilancia la diagnosi fra poco."}


def _firewall(client: str, position: dict, dest, dest_port, protocol) -> dict:
    """Tutto ciò che il FortiGate sa del client: ARP, DHCP, sessioni, log e —
    se è stata data una destinazione — quale policy matcherebbe il flusso."""
    from services import fortigate_service

    fgt = _resolve_fortigate(position)
    if not fgt.get("known"):
        return fgt
    # L'IP è più preciso del MAC: se lo conosciamo già lo usiamo, così il
    # FortiGate non deve ri-risolverlo per conto suo.
    target = position.get("ip") if position.get("known") else client

    # Sede agent: il centrale non raggiunge l'apparato. Non si finge di
    # provarci (fallirebbe in timeout): si passa dal relay, che risponde alla
    # domanda che conta davvero — quale policy matcherebbe.
    site_id = (fgt["device"].get("Site") or "central")
    if _is_agent_site(site_id):
        out = {"known": False, "fortigate": fgt["ip"],
               "resolved_by": fgt["resolved_by"], "site": site_id,
               "reason": f"sede '{site_id}' in modalita' agent: il centrale non "
                         "raggiunge questo apparato in REST diretta"}
        if dest and target:
            out["policy_lookup"] = _relay_policy_lookup(
                fgt["device"], site_id, target, dest, dest_port, protocol)
        return out

    data = fortigate_service.diagnose_client(
        fgt["device"], target or client, dest=dest,
        dest_port=dest_port, protocol=protocol)
    return {"known": True, "fortigate": fgt["ip"],
            "resolved_by": fgt["resolved_by"], **data}


def _across_sites(position: dict, dest: str, dest_port, protocol,
                  tenants) -> dict:
    """Il pezzo che manca quando sorgente e destinazione stanno in due sedi.

    Un flusso fra due sedi attraversa DUE firewall, e basta che uno dei due lo
    neghi. Guardare solo quello del client risponde alla domanda sbagliata per
    meta' del percorso. In piu' si guarda cio' che sta in mezzo: il tunnel su
    o giu', e se il firewall del client abbia una rotta verso la destinazione
    (una policy che permette e una rotta che manca danno lo stesso sintomo e
    si riparano in due modi diversi).
    """
    from services import fortigate_service

    src = {"known": True, "tenant": position.get("tenant"),
           "site": position.get("site"),
           "gateway_ip": position.get("gateway_ip"),
           "gateway_type": position.get("gateway_type")} \
        if position.get("known") else {"known": False}
    dst = resolve_endpoint(dest, tenants)

    out: dict = {"known": True, "source": src, "destination": dst}
    if not (src.get("known") and dst.get("known")):
        out["same_site"] = None
        out["note"] = ("una delle due estremita' non e' collocabile: il "
                       "confronto fra sedi non e' possibile")
        return out

    same = (src.get("site") or "") == (dst.get("site") or "")
    out["same_site"] = same
    if same:
        out["note"] = "sorgente e destinazione nella stessa sede"
        return out

    # Firewall della destinazione: solo se e' un target noto e distinto da
    # quello della sorgente.
    targets = {t["ip"] for t in fortigate_service.list_targets()}
    from services import inventory_manager
    devices = {d.get("IP"): d for d in inventory_manager.get_all_devices()}
    dst_gw = dst.get("gateway_ip")

    if dst_gw and dst_gw in targets and dst_gw != src.get("gateway_ip"):
        device = devices.get(dst_gw)
        try:
            out["far_end_policy"] = {
                "fortigate": dst_gw,
                **fortigate_service.policy_lookup(
                    device, position.get("ip") or "", dest,
                    protocol=protocol, dest_port=dest_port or 443)}
        except Exception as e:
            out["far_end_policy"] = {"fortigate": dst_gw, "error": str(e)}
    else:
        out["far_end_policy"] = {
            "known": False,
            "reason": "il firewall che fronteggia la destinazione non e' fra i "
                      "target configurati: la sua policy non e' verificabile"}

    src_gw = src.get("gateway_ip")
    src_device = devices.get(src_gw) if src_gw else None
    if src_device and src_gw in targets:
        try:
            out["tunnels"] = fortigate_service.get_vpn_tunnels(src_device)
        except Exception as e:
            out["tunnels"] = {"error": str(e)}
        try:
            out["route"] = fortigate_service.get_route_for(src_device, dest)
        except Exception as e:
            out["route"] = {"error": str(e)}
    return out


def _denies(position: dict, client: str, dest, tenants) -> dict:
    """Quanti blocchi ha subito questo client nell'ultima ora, e per mano di
    quale policy.

    ``policy_id`` e ``subtype`` arrivano da ``fieldmap``: senza di loro si
    sapeva che qualcosa era stato bloccato, mai da quale regola né se il
    blocco fosse di policy o di UTM.
    """
    from core import db
    from observability import fieldmap

    ip = position.get("ip") if position.get("known") else client
    if not ip:
        return {"known": False, "reason": "IP del client sconosciuto"}

    since = int(time.time()) - DENY_WINDOW_S
    sql = ["SELECT ts, tenant, device_ip, action, message FROM syslog_events "
           "WHERE ts >= ?"]
    args: list[Any] = [since]
    if tenants is not None:
        if not tenants:
            return {"known": True, "total": 0, "by_policy": [], "samples": []}
        sql.append("AND tenant IN (%s)" % ",".join("?" * len(tenants)))
        args.extend(tenants)
    sql.append("ORDER BY ts DESC LIMIT ?")
    args.append(_MAX_SYSLOG_ROWS)

    conn = db.get_observability_connection()
    try:
        rows = [dict(r) for r in conn.execute(" ".join(sql), args).fetchall()]
    finally:
        conn.close()

    by_policy: dict = {}
    samples = []
    total = 0
    for r in rows:
        fields = fieldmap.extract(r["message"] or "")
        if fields["src_ip"] != ip:
            continue
        if dest and fields["dst_ip"] != dest:
            continue
        if not fieldmap.is_security_action(r["action"] or fields["action"]):
            continue
        total += 1
        key = (fields["policy_id"] or "?", fields["subtype"] or "?")
        by_policy[key] = by_policy.get(key, 0) + 1
        if len(samples) < 5:
            samples.append({"ts": r["ts"], "device_ip": r["device_ip"],
                            "dst_ip": fields["dst_ip"],
                            "dst_port": fields["dst_port"],
                            "action": r["action"] or fields["action"],
                            "policy_id": fields["policy_id"],
                            "subtype": fields["subtype"]})

    return {
        "known": True, "window_s": DENY_WINDOW_S, "total": total,
        "by_policy": [{"policy_id": p, "subtype": s, "count": c}
                      for (p, s), c in sorted(by_policy.items(),
                                              key=lambda kv: -kv[1])],
        "samples": samples,
        "scanned": len(rows),
        # Il tetto è quello di flow_siem: se lo si tocca, il conteggio è un
        # minimo, non un totale, e chi legge deve saperlo.
        "truncated": len(rows) >= _MAX_SYSLOG_ROWS,
    }


# --- Freschezza del dato -----------------------------------------------------

# Sotto questa età il dato si usa com'è. Quindici minuti: abbastanza per non
# riscansionare a ogni click, abbastanza poco che una porta cambiata stamattina
# non passi per buona.
DEFAULT_MAX_AGE_S = 900


def _age_s(ts: Optional[str]) -> Optional[float]:
    """Secondi da un timestamp ISO delle tabelle di storico, None se illeggibile."""
    if not ts:
        return None
    import datetime
    try:
        return max(0.0, time.time()
                   - datetime.datetime.fromisoformat(str(ts)).timestamp())
    except (ValueError, TypeError):
        return None


def get_max_age_s() -> int:
    """Soglia di freschezza, accanto a ``retention_days`` nelle stesse impostazioni."""
    from collectors import mac_history
    try:
        mac_history.init_db()
        with mac_history._lock, mac_history._connect() as c:
            row = c.execute("SELECT value FROM mac_settings WHERE key='max_age_s'").fetchone()
        return int(row["value"]) if row else DEFAULT_MAX_AGE_S
    except Exception:
        return DEFAULT_MAX_AGE_S


def _rescan_for(position: dict) -> dict:
    """Riscansiona i DUE apparati che compongono la posizione, non la flotta.

    Il gateway che ha risposto l'ARP dà il binding MAC↔IP, lo switch di accesso
    dà porta e VLAN: sono gli unici due che possono cambiare la risposta. Una
    scansione di flotta costerebbe una sessione SSH per apparato per rispondere
    alla stessa domanda.
    """
    from collectors import arp_collector, mac_collector
    from services import inventory_manager

    devices = {d["IP"]: d for d in inventory_manager.get_all_devices()}
    done, failed = [], {}
    for ip, collect_all in ((position.get("gateway_ip"), arp_collector.collect_all),
                            (position.get("switch_ip"), mac_collector.collect_all)):
        if not ip or ip not in devices:
            continue
        try:
            collect_all([devices[ip]])
            done.append(ip)
        except Exception as e:                      # noqa: BLE001 - best effort
            failed[ip] = str(e)
    return {"scanned": done, "failed": failed}


def _ensure_fresh(client: str, is_mac: bool, tenants, position: dict,
                  max_age_s: Optional[int] = None) -> tuple:
    """Posizione abbastanza fresca da fidarsene, riscansionando solo se serve.

    Ritorna ``(position, freshness)``. Se la riscansione fallisce NON si
    interrompe: si prosegue col dato vecchio dichiarandolo. Un referto che non
    esce è peggio di un referto che dice quanto è vecchio — e chi legge sta per
    andare a toccare la rete, quindi la differenza va scritta, non lasciata
    intuire dai timestamp.
    """
    limit = get_max_age_s() if max_age_s is None else max_age_s
    ages = {"binding_s": _age_s(position.get("binding_last_seen")),
            "port_s": _age_s(position.get("port_last_seen"))}
    if not position.get("known"):
        return position, {"refreshed": False, "stale": False, "max_age_s": limit,
                          "ages": ages, "reason": "posizione sconosciuta: "
                                                  "niente da riaggiornare"}
    stale = any(a is not None and a > limit for a in ages.values())
    if not stale:
        return position, {"refreshed": False, "stale": False, "max_age_s": limit,
                          "ages": ages, "reason": "dato entro la soglia"}

    scan = _rescan_for(position)
    if not scan["scanned"]:
        return position, {"refreshed": False, "stale": True, "max_age_s": limit,
                          "ages": ages, "failed": scan["failed"],
                          "reason": "riscansione non riuscita: il referto usa il "
                                    "dato vecchio"}
    fresh = _position(client, is_mac, tenants)
    if not fresh.get("known"):
        # La riscansione è andata ma il client non si è ripresentato: sparito
        # dalla rete, oppure spento. Il dato vecchio resta l'unica traccia.
        return position, {"refreshed": True, "stale": True, "max_age_s": limit,
                          "ages": ages, "scanned": scan["scanned"],
                          "failed": scan["failed"],
                          "reason": "dopo la riscansione il client non risulta "
                                    "più: posizione precedente, ora storica"}
    return fresh, {"refreshed": True, "stale": False, "max_age_s": limit,
                   "ages": {"binding_s": _age_s(fresh.get("binding_last_seen")),
                            "port_s": _age_s(fresh.get("port_last_seen"))},
                   "scanned": scan["scanned"], "failed": scan["failed"],
                   "reason": "dato oltre soglia: riscansionati gateway e switch"}


def verify_port(mac: str, switch_ip: str, interface: str, tenants=None,
                max_age_s: Optional[int] = None) -> dict:
    """La porta indicata è ANCORA quella di questo client, e il dato è recente?

    Cancello di ogni azione che tocca la porta. Le due condizioni sono
    separate perché falliscono per motivi diversi e si riparano in due modi
    diversi: una posizione che non combacia significa che il client si è
    spostato (rilancia la diagnosi), un dato vecchio significa che non lo
    sappiamo (rilancia la scansione). Confonderle manderebbe a fare la cosa
    sbagliata.

    Non è una formalità: la MAC table si scansiona a mano, e su un dato di tre
    settimane fa la porta di oggi può appartenere a un altro utente. Staccare
    quello sbagliato è un guasto causato dallo strumento che doveva ripararne
    uno.
    """
    from core.core_engine import _normalize_iface

    limit = get_max_age_s() if max_age_s is None else max_age_s
    pos = _position(mac, True, tenants)
    if not pos.get("known"):
        return {"ok": False, "reason": "posizione del client sconosciuta: "
                                       "nessun binding noto per questo MAC"}
    if (pos.get("switch_ip") or "") != switch_ip:
        return {"ok": False, "position": pos,
                "reason": f"il client non risulta su {switch_ip} ma su "
                          f"{pos.get('switch_ip')}: rilancia la diagnosi"}
    if _normalize_iface(pos.get("switch_port") or "") != _normalize_iface(interface):
        return {"ok": False, "position": pos,
                "reason": f"il client non risulta su {interface} ma su "
                          f"{pos.get('switch_port')}: rilancia la diagnosi"}
    age = _age_s(pos.get("port_last_seen"))
    if age is None:
        return {"ok": False, "position": pos,
                "reason": "età della posizione non determinabile: "
                          "rilancia una scansione MAC prima di agire"}
    if age > limit:
        return {"ok": False, "position": pos,
                "reason": f"posizione vecchia di {int(age)}s (soglia {limit}s): "
                          "rilancia una scansione MAC prima di agire"}
    return {"ok": True, "position": pos, "age_s": age}


def _history(position: dict, client: str, is_mac: bool) -> dict:
    """Dove è già stato questo client e che indirizzi ha avuto."""
    from collectors import mac_history

    mac = position.get("mac") if position.get("known") else (client if is_mac else None)
    if not mac:
        return {"known": False,
                "reason": "MAC sconosciuto: lo storico si interroga per MAC"}
    return mac_history.client_history(mac)


# --- Referto -----------------------------------------------------------------

def diagnose(client: str, dest: Optional[str] = None,
             dest_port: Optional[int] = 443, protocol: str = "TCP",
             tenants=None, max_age_s: Optional[int] = None) -> dict:
    """Referto completo su un client (IP o MAC), opzionalmente verso ``dest``.

    ``tenants``: lista dei tenant visibili al chiamante, oppure ``None`` per
    nessuna restrizione (amministratore). Lo scoping è deciso dal router, qui
    si applica soltanto.

    ``max_age_s``: soglia di freschezza in secondi; oltre quella, gateway e
    switch di accesso vengono riscansionati prima di rispondere. ``None`` usa
    l'impostazione salvata. ``0`` forza sempre la riscansione.

    Quando lo stesso indirizzo risulta in più tenant, la sezione ``position``
    porta ``tenants_available``: il chiamante sceglie e rilancia restringendo
    ``tenants``. Restringere è l'unica direzione ammessa — l'insieme che arriva
    qui è già quello che il router ha concesso all'utente.
    """
    is_mac = bool(_MAC_RE.fullmatch(client or ""))
    result: dict = {"client": client, "client_type": "mac" if is_mac else "ip",
                    "generated_ts": int(time.time()), "sections": {}}

    _section(result, "position", _position, client, is_mac, tenants)
    position = result["sections"]["position"]

    # Le scansioni ARP/MAC sono manuali: senza questo passaggio il referto
    # descrive una posizione che può essere di settimane fa, e chi legge se ne
    # accorge solo confrontando i timestamp. Sopra soglia si riscansionano i due
    # apparati che compongono la posizione, poi si riparte da quella nuova.
    try:
        position, freshness = _ensure_fresh(client, is_mac, tenants, position,
                                            max_age_s)
        result["sections"]["position"] = position
    except Exception as e:
        logger.debug("Controllo freschezza fallito: %s", e)
        freshness = {"refreshed": False, "error": str(e)}
    result["freshness"] = freshness

    result["resolved_ip"] = position.get("ip") if position.get("known") else None

    _section(result, "l2_health", _l2_health, position)
    _section(result, "history", _history, position, client, is_mac)

    src_ip = result["resolved_ip"]
    if src_ip and dest:
        # Il tenant della destinazione va risolto a parte: un server in
        # datacenter non sta nel tenant del client, e cercarlo con quello
        # della sorgente lo darebbe per ignoto sempre.
        dst_at = resolve_endpoint(dest, tenants)
        _section(result, "path", _path, src_ip, dest,
                 position.get("tenant") or "", dst_at.get("tenant"))
    else:
        result["sections"]["path"] = {
            "known": False,
            "reason": "serve un IP sorgente noto e una destinazione"}

    _section(result, "firewall", _firewall, client, position, dest,
             dest_port, protocol)
    if dest:
        _section(result, "across_sites", _across_sites, position, dest,
                 dest_port, protocol, tenants)
    _section(result, "denies", _denies, position, client, dest, tenants)

    # ``complete`` con lo stesso significato che ha in flowpath: non "tutto va
    # bene", ma "non ci sono buchi in ciò che ti sto raccontando".
    result["complete"] = all(s.get("known") for s in result["sections"].values())
    return result
