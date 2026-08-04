# Gateway L3 dedotto dalla configurazione — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Chiudere la catena dei trunk della Diagnosi Client quando l'ARP non
conosce il gateway, deducendo dai backup di configurazione quale apparato
instrada la VLAN del client.

**Architecture:** Un modulo nuovo `services/vlan_routing.py` con un solo punto
d'ingresso `route_owner(vlan, tenant, client_ip=None)`. Legge le SVI già
estratte da `config_analyzer` e le interfacce VLAN FortiOS (che il Task 1 rende
interrogabili), sceglie per contenimento di subnet, e dichiara parità o ignoto
invece di indovinare. `_trunk_chain` lo chiama solo quando manca il gateway ARP.

**Tech Stack:** Python 3.14, `unittest`, `uv`, FastAPI (non toccato: nessuna
rotta nuova), `pyrefly` per i tipi.

**Spec:** `docs/superpowers/specs/2026-08-04-vlan-routing-owner-design.md`

## Global Constraints

- **Lingua**: italiano per stringhe utente, log, errori, commenti e docstring;
  inglese per gli identificatori (`CONTRIBUTING.md` §1).
- **Dati veri MAI nel repo**: solo RFC 5737 (`192.0.2.x`, `198.51.100.x`) e nomi
  segnaposto (`switch-01`, `sede-a`). Vale per codice, test, commenti e messaggi
  di commit (`CLAUDE.md` §"Protect real data").
- **Nessuna rotta HTTP nuova** in questo piano: non si toccano le tre allowlist
  di `tests/test_router_parity.py`. Se un task sembra richiedere una rotta,
  fermarsi: è fuori ambito.
- **Cancelli, da eseguire e leggere davvero** prima di ogni commit:
  `uv run pyrefly check` (0 errori), `uv run python -m unittest discover -s tests`
  (tutti verdi), `graphify update .` dopo modifiche al codice.
- **I test non toccano mai `data/` reale**: `tests/__init__.py` impone una
  directory temporanea. Non aggirarlo, non impostare `SENTINELNET_DATA_DIR` verso
  il repo.
- **Commit**: conventional commit, corpo esplicativo. Usare `-F <file>` oppure
  tre `-m` separati (cmd.exe tronca i `-m` multilinea).

---

## File Structure

| File | Responsabilità | Azione |
|---|---|---|
| `fw_analyzers/fortios.py` | aggiungere `vlan_interfaces` all'envelope FortiOS | modifica |
| `ai/config_analyzer.py` | `analyze_device_cached()`, memo su `(ip, mtime)` | modifica |
| `services/vlan_routing.py` | `route_owner()`: derivazione, confini, parità | **nuovo** |
| `services/client_diagnosis.py` | `_trunk_chain` usa `route_owner` senza gateway ARP | modifica |
| `static/js/diagnosi.js` | riga "gateway dedotto" nella sezione trunk | modifica |
| `tests/test_config_analyzer_fortigate.py` | prova su `vlanid` | modifica |
| `tests/test_vlan_routing.py` | prove su `route_owner` | **nuovo** |
| `tests/test_client_diagnosis.py` | catena chiusa senza gateway ARP | modifica |

---

## Task 1: Interfacce VLAN FortiOS interrogabili

**Files:**
- Modify: `fw_analyzers/fortios.py:232-244` (ciclo `system interface`), `fw_analyzers/fortios.py:127` e `:317` (i due `return`)
- Test: `tests/test_config_analyzer_fortigate.py`

**Interfaces:**
- Consumes: niente.
- Produces: `fw_analyzers.fortios.analyze(text)["vlan_interfaces"]` → `list[dict]`
  con chiavi `name: str`, `vlan: str`, `ip: str` (CIDR, `""` se assente),
  `status: str`, `parent: str`. Consumato dal Task 3.

- [ ] **Step 1: Scrivere il test che fallisce**

In coda a `tests/test_config_analyzer_fortigate.py`:

```python
class TestFortiosVlanInterfaces(unittest.TestCase):
    """Le VLAN instradate dal firewall devono essere interrogabili, non solo
    mostrate: senza 'vlanid' la derivazione del gateway non vede mai un
    FortiGate, e direbbe 'nessuna interfaccia L3' di una VLAN che il firewall
    instrada."""

    CONF = """#config-version=FGT-7.0
config system interface
    edit "port1"
        set ip 192.0.2.254 255.255.255.0
        set status up
    next
    edit "vlan226"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
        set status up
        set interface "port1"
        set vlanid 226
    next
    edit "vlan227"
        set status down
        set interface "port1"
        set vlanid 227
    next
end
"""

    def test_vlan_interfaces_are_extracted(self):
        from fw_analyzers import fortios
        vifs = {v["vlan"]: v for v in fortios.analyze(self.CONF)["vlan_interfaces"]}
        self.assertEqual(sorted(vifs), ["226", "227"])
        self.assertEqual(vifs["226"]["ip"], "192.0.2.1/24")
        self.assertEqual(vifs["226"]["parent"], "port1")
        self.assertEqual(vifs["226"]["status"], "up")

    def test_interfaces_without_vlanid_are_not_vlan_interfaces(self):
        from fw_analyzers import fortios
        vifs = fortios.analyze(self.CONF)["vlan_interfaces"]
        self.assertNotIn("port1", [v["name"] for v in vifs])

    def test_a_broken_config_still_returns_the_key(self):
        # analyze() è tollerante per contratto: chi legge non deve difendersi
        # dall'assenza della chiave.
        from fw_analyzers import fortios
        self.assertEqual(fortios.analyze(None)["vlan_interfaces"], [])

    def test_the_display_section_keeps_its_columns(self):
        # Le colonne sono UI: questo lavoro non le cambia.
        from fw_analyzers import fortios
        sec = next(s for s in fortios.analyze(self.CONF)["sections"]
                   if s["id"] == "interfaces")
        self.assertEqual([c["key"] for c in sec["columns"]],
                         ["name", "ip", "zone", "vdom", "allowaccess", "status"])
```

- [ ] **Step 2: Eseguire il test e verificare che fallisca**

Run: `uv run python -m unittest tests.test_config_analyzer_fortigate.TestFortiosVlanInterfaces -v`
Expected: FAIL con `KeyError: 'vlan_interfaces'`.

- [ ] **Step 3: Implementare**

In `fw_analyzers/fortios.py`, sostituire il ciclo `system interface`:

```python
    rows = []
    vlan_ifaces = []
    for name, n in _children(root, 'system interface'):
        rows.append({
            "name": name,
            "ip": _forti_ip_cidr(n),
            "zone": zone_of_iface.get(name, ''),
            "vdom": _forti_set1(n, 'vdom'),
            "allowaccess": _multi(n["sets"].get('allowaccess', [])),
            "status": _forti_set1(n, 'status', 'up'),
        })
        # Sotto-interfaccia VLAN: e' l'equivalente FortiOS di una SVI, ed e'
        # cio' che rende deducibile un gateway che sta sul firewall.
        vlanid = _forti_set1(n, 'vlanid')
        if vlanid:
            vlan_ifaces.append({
                "name": name,
                "vlan": vlanid,
                "ip": _forti_ip_cidr(n),
                "status": _forti_set1(n, 'status', 'up'),
                "parent": _forti_set1(n, 'interface'),
            })
    sections.append(_section(
        "interfaces", ["name", "ip", "zone", "vdom", "allowaccess", "status"], rows))
```

Cambiare i due `return` (le colonne della sezione restano identiche):

```python
        return {"vendor": "fortios", "sections": [], "vlan_interfaces": []}
```

```python
    return {"vendor": "fortios", "sections": sections,
            "vlan_interfaces": vlan_ifaces}
```

- [ ] **Step 4: Eseguire i test e verificare che passino**

Run: `uv run python -m unittest tests.test_config_analyzer_fortigate -v`
Expected: PASS, comprese le prove preesistenti del file.

- [ ] **Step 5: Cancelli e commit**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
git add fw_analyzers/fortios.py tests/test_config_analyzer_fortigate.py
git commit -m "feat(fortios): expose VLAN sub-interfaces as queryable data" -m "The system-interface loop already read the address as CIDR but dropped vlanid, so a VLAN routed by the firewall was visible on screen and invisible to code. The display columns are unchanged." -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 2: Memo delle analisi di configurazione

**Files:**
- Modify: `ai/config_analyzer.py` (aggiungere dopo `analyze_device`, intorno a `:1372`)
- Test: `tests/test_config_analyzer_backup_age.py`

**Interfaces:**
- Consumes: `config_analyzer.analyze_device(ip)` esistente.
- Produces: `config_analyzer.analyze_device_cached(ip)` → stessa struttura di
  `analyze_device` oppure `None`. Consumato dal Task 3.

- [ ] **Step 1: Scrivere il test che fallisce**

In coda a `tests/test_config_analyzer_backup_age.py`:

```python
class TestAnalyzeDeviceCache(unittest.TestCase):
    """Ogni salto della catena dei trunk rilegge e ri-parsa un file. Il memo
    serve alla derivazione del gateway, che scansiona un tenant intero, e
    intanto ripaga il percorso che gia' esiste."""

    def setUp(self):
        config_analyzer.analyze_device_cached.cache_clear()

    def test_second_call_does_not_reparse(self):
        calls = []

        def _fake(ip):
            calls.append(ip)
            return {"ip": ip, "vlans": []}

        with patch.object(config_analyzer, "analyze_device", _fake), \
             patch.object(config_analyzer, "_backup_mtime", lambda ip: 111):
            config_analyzer.analyze_device_cached("192.0.2.20")
            config_analyzer.analyze_device_cached("192.0.2.20")
        self.assertEqual(len(calls), 1)

    def test_a_newer_backup_invalidates(self):
        calls = []

        def _fake(ip):
            calls.append(ip)
            return {"ip": ip, "vlans": []}

        mtime = {"v": 111}
        with patch.object(config_analyzer, "analyze_device", _fake), \
             patch.object(config_analyzer, "_backup_mtime", lambda ip: mtime["v"]):
            config_analyzer.analyze_device_cached("192.0.2.20")
            mtime["v"] = 222
            config_analyzer.analyze_device_cached("192.0.2.20")
        self.assertEqual(len(calls), 2)
```

Aggiungere in testa al file, se assente: `from unittest.mock import patch`.

- [ ] **Step 2: Eseguire il test e verificare che fallisca**

Run: `uv run python -m unittest tests.test_config_analyzer_backup_age.TestAnalyzeDeviceCache -v`
Expected: FAIL con `AttributeError: module 'ai.config_analyzer' has no attribute 'analyze_device_cached'`.

- [ ] **Step 3: Implementare**

In `ai/config_analyzer.py`, dopo `analyze_device`:

```python
def _backup_mtime(ip):
    """mtime del backup piu' fresco, o None. Chiave di invalidazione del memo."""
    path, _ = _find_freshest_backup(ip)
    if not path:
        return None
    try:
        return int(os.path.getmtime(path))
    except OSError:
        return None


@functools.lru_cache(maxsize=128)
def _analyze_device_at(ip, _mtime):
    # _mtime non si usa: sta nella firma perche' un backup nuovo produca una
    # chiave nuova. Il tetto LRU serve alla rotazione dei backup, che
    # altrimenti farebbe crescere le chiavi senza fine.
    return analyze_device(ip)


def analyze_device_cached(ip):
    """``analyze_device`` con memo su (ip, mtime del backup).

    Una singola diagnosi rilegge lo stesso backup a ogni salto della catena e
    a ogni candidato della derivazione del gateway: il parsing e' la parte
    cara, e il file non cambia mentre si risponde.
    """
    return _analyze_device_at(ip, _backup_mtime(ip))


analyze_device_cached.cache_clear = _analyze_device_at.cache_clear
```

Aggiungere `import functools` in testa al modulo se assente (verificare con
`grep -n "^import functools" ai/config_analyzer.py`).

**E far passare `analyze_all` dal memo**, altrimenti il memo non serve a niente:
la scansione per tenant del Task 3 usa `analyze_all`, che chiama
`analyze_device` diretto. In `analyze_all` sostituire:

```python
        try:
            res = analyze_device(ip)
        except Exception:
            res = None
```

con:

```python
        try:
            res = analyze_device_cached(ip)
        except Exception:
            res = None
```

- [ ] **Step 4: Eseguire i test e verificare che passino**

Run: `uv run python -m unittest tests.test_config_analyzer_backup_age -v`
Expected: PASS.

Poi, perché il cambio dentro `analyze_all` tocca tutti i suoi chiamanti:

Run: `uv run python -m unittest discover -s tests`
Expected: tutti verdi. Il memo non cambia il valore restituito, solo quante
volte si legge il file: un test che diventasse rosso qui starebbe segnalando che
qualcosa contava sulle riletture, e va capito prima di proseguire.

- [ ] **Step 5: Cancelli e commit**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
git add ai/config_analyzer.py tests/test_config_analyzer_backup_age.py
git commit -m "perf(config): memoise device analysis on the backup mtime" -m "A single diagnosis re-read and re-parsed the same backup at every hop of the trunk chain, and the tenant-wide scan the VLAN gateway derivation needs would have multiplied that. The key carries the backup mtime, so a fresh backup invalidates on its own, and an LRU ceiling keeps rotation from growing the keys forever. analyze_all goes through the memo too, otherwise the scan would not benefit from it at all." -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3: `route_owner()` — derivazione dalla configurazione

**Files:**
- Create: `services/vlan_routing.py`
- Test: `tests/test_vlan_routing.py`

**Interfaces:**
- Consumes: `config_analyzer.analyze_all(group_filter, allowed_groups)`,
  `fortios.analyze(...)["vlan_interfaces"]` (Task 1) tramite
  `result["firewall"]["vlan_interfaces"]`, `inventory_manager.get_all_devices()`.
- Produces: `services.vlan_routing.route_owner(vlan, tenant, client_ip=None)` →
  `dict` con `known: bool`, e in caso positivo `device_ip: str`,
  `svi_ip: Optional[str]`, `source: "config"`, `backup_age_s: Optional[int]`,
  `unreadable: list[str]`; in caso negativo `reason: str`, `unreadable: list[str]`
  ed eventualmente `candidates: list[str]`. Consumato dai Task 4 e 5.
  Anche `services.vlan_routing.tenant_key(value)` → `str`.

- [ ] **Step 1: Scrivere i test che falliscono**

Creare `tests/test_vlan_routing.py`:

```python
# -*- coding: utf-8 -*-
"""Chi instrada questa VLAN: la risposta si deduce dai backup, e quando non si
puo' dedurre lo si dice invece di indovinare.

Le due distinzioni che contano: un apparato illeggibile rende la risposta
IGNOTA, non "nessuna rotta"; e un tenant None (non si sa) non e' un tenant
vuoto (quello predefinito).
"""
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_vlanroute_"))

from services import vlan_routing  # noqa: E402


def _ios(ip, vlan, svi_ip, shutdown=False, tenant="sede-a", backup_ts=1000):
    return {"ip": ip, "tenant": tenant, "backup_ts": backup_ts,
            "vlans": [{"id": str(vlan), "svi": {"ip": svi_ip,
                                                "shutdown": shutdown}}],
            "firewall": None}


def _fgt(ip, vlan, iface_ip, status="up", tenant="sede-a", backup_ts=1000):
    return {"ip": ip, "tenant": tenant, "backup_ts": backup_ts, "vlans": [],
            "firewall": {"vendor": "fortios", "sections": [],
                         "vlan_interfaces": [{"name": f"vlan{vlan}",
                                              "vlan": str(vlan),
                                              "ip": iface_ip,
                                              "status": status,
                                              "parent": "port1"}]}}


class _Base(unittest.TestCase):
    def _run(self, analyses, devices, vlan="226", tenant="sede-a",
             client_ip=None):
        with patch("ai.config_analyzer.analyze_all",
                   return_value={"devices": analyses}), \
             patch("services.inventory_manager.get_all_devices",
                   return_value=devices):
            return vlan_routing.route_owner(vlan, tenant, client_ip)


class TestTenantIsABoundary(_Base):

    def test_none_tenant_refuses_and_never_scans(self):
        called = []
        with patch("ai.config_analyzer.analyze_all",
                   side_effect=lambda **kw: called.append(kw) or {"devices": []}):
            out = vlan_routing.route_owner("226", None)
        self.assertFalse(out["known"])
        self.assertEqual(called, [], "un tenant ignoto non deve far scansionare")

    def test_empty_tenant_is_the_default_one_not_unknown(self):
        # arp_collector scrive "" per un apparato senza Group, analyze_all
        # legge "Generale": e' la stessa rete, e deve funzionare.
        out = self._run([_ios("192.0.2.20", 226, "192.0.2.1/24",
                              tenant="Generale")],
                        [{"IP": "192.0.2.20", "Group": ""}],
                        tenant="", client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))
        self.assertEqual(out["device_ip"], "192.0.2.20")

    def test_tenant_key_folds_the_empty_forms_together(self):
        self.assertEqual(vlan_routing.tenant_key(""), "Generale")
        self.assertEqual(vlan_routing.tenant_key("  "), "Generale")
        self.assertEqual(vlan_routing.tenant_key("sede-a"), "sede-a")


class TestDerivation(_Base):

    def test_the_subnet_containing_the_client_wins(self):
        out = self._run(
            [_ios("192.0.2.20", 226, "192.0.2.1/24"),
             _ios("192.0.2.21", 226, "198.51.100.1/24")],
            [{"IP": "192.0.2.20", "Group": "sede-a"},
             {"IP": "192.0.2.21", "Group": "sede-a"}],
            client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))
        self.assertEqual(out["device_ip"], "192.0.2.20")
        self.assertEqual(out["svi_ip"], "192.0.2.1/24")
        self.assertEqual(out["source"], "config")

    def test_a_pair_on_the_same_subnet_is_a_declared_tie(self):
        out = self._run(
            [_ios("192.0.2.20", 226, "192.0.2.1/24"),
             _ios("192.0.2.21", 226, "192.0.2.2/24")],
            [{"IP": "192.0.2.20", "Group": "sede-a"},
             {"IP": "192.0.2.21", "Group": "sede-a"}],
            client_ip="192.0.2.50")
        self.assertFalse(out["known"])
        self.assertEqual(sorted(out["candidates"]), ["192.0.2.20", "192.0.2.21"])

    def test_a_shutdown_svi_does_not_route(self):
        out = self._run([_ios("192.0.2.20", 226, "192.0.2.1/24", shutdown=True)],
                        [{"IP": "192.0.2.20", "Group": "sede-a"}],
                        client_ip="192.0.2.50")
        self.assertFalse(out["known"])

    def test_a_fortigate_vlan_interface_is_a_candidate(self):
        out = self._run([_fgt("192.0.2.254", 226, "192.0.2.1/24")],
                        [{"IP": "192.0.2.254", "Group": "sede-a"}],
                        client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))
        self.assertEqual(out["device_ip"], "192.0.2.254")

    def test_a_down_fortigate_vlan_interface_does_not_route(self):
        out = self._run([_fgt("192.0.2.254", 226, "192.0.2.1/24", status="down")],
                        [{"IP": "192.0.2.254", "Group": "sede-a"}],
                        client_ip="192.0.2.50")
        self.assertFalse(out["known"])

    def test_the_backup_age_is_reported(self):
        import time
        ts = int(time.time()) - 3600
        out = self._run([_ios("192.0.2.20", 226, "192.0.2.1/24", backup_ts=ts)],
                        [{"IP": "192.0.2.20", "Group": "sede-a"}],
                        client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))
        self.assertGreaterEqual(out["backup_age_s"], 3600)


class TestUnknownIsNotAbsent(_Base):

    def test_a_device_without_a_backup_makes_the_answer_unknown(self):
        out = self._run([], [{"IP": "192.0.2.20", "Group": "sede-a"}])
        self.assertFalse(out["known"])
        self.assertEqual(out["unreadable"], ["192.0.2.20"])
        self.assertIn("192.0.2.20", out["reason"])

    def test_everything_readable_and_nothing_found_is_not_unknown(self):
        out = self._run([_ios("192.0.2.20", 999, "192.0.2.1/24")],
                        [{"IP": "192.0.2.20", "Group": "sede-a"}])
        self.assertFalse(out["known"])
        self.assertEqual(out["unreadable"], [])

    def test_unreadable_is_reported_even_when_the_answer_is_known(self):
        out = self._run([_ios("192.0.2.20", 226, "192.0.2.1/24")],
                        [{"IP": "192.0.2.20", "Group": "sede-a"},
                         {"IP": "192.0.2.99", "Group": "sede-a"}],
                        client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))
        self.assertEqual(out["unreadable"], ["192.0.2.99"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Eseguire i test e verificare che falliscano**

Run: `uv run python -m unittest tests.test_vlan_routing -v`
Expected: FAIL con `ModuleNotFoundError: No module named 'services.vlan_routing'`.

- [ ] **Step 3: Implementare**

Creare `services/vlan_routing.py`:

```python
# -*- coding: utf-8 -*-
"""Chi instrada una VLAN, dedotto dai backup di configurazione.

La catena dei trunk della diagnosi si percorre solo se si sa dove finisce, e il
capolinea e' il gateway. Quando l'ARP non ne conosce uno, la risposta e' comunque
scritta nei backup: una SVI su uno switch L3, oppure una sotto-interfaccia VLAN
su un FortiGate. Qui la si legge.

Due regole non negoziabili:

* **Il tenant e' un confine.** Cercare fuori dal tenant del client vuol dire
  poter restituire l'apparato di un altro cliente. ``None`` significa "non si
  sa" e fa rifiutare; ``""`` e' il tenant predefinito e si cerca.
* **Ignoto non e' assente.** Un apparato senza backup non e' un apparato senza
  rotta: se non si e' potuto guardare, lo si dice.
"""
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def tenant_key(value) -> str:
    """Chiave di confronto fra tenant.

    ``arp_collector`` scrive ``""`` per un apparato senza ``Group`` e
    ``analyze_all`` legge ``"Generale"``: sono la stessa rete e devono
    coincidere, altrimenti il caso piu' comune (installazione senza gruppi)
    smetterebbe di trovare il proprio gateway.
    """
    return (value or "").strip() or "Generale"


def _svi_candidates(analysis, vlan: str) -> Optional[str]:
    """Indirizzo L3 dell'apparato su quella VLAN, o None se non la instrada.

    Copre le due forme: la SVI IOS e la sotto-interfaccia VLAN FortiOS.
    Un'interfaccia spenta non instrada, quindi non e' un candidato.
    """
    for entry in analysis.get("vlans") or []:
        if str(entry.get("id")) != vlan:
            continue
        svi = entry.get("svi")
        if svi and not svi.get("shutdown"):
            return svi.get("ip") or ""

    firewall = analysis.get("firewall") or {}
    for vif in firewall.get("vlan_interfaces") or []:
        if str(vif.get("vlan")) != vlan:
            continue
        if (vif.get("status") or "up").lower() != "up":
            continue
        return vif.get("ip") or ""
    return None


def _contains(cidr: str, client_ip: str) -> bool:
    if not cidr or not client_ip:
        return False
    try:
        return ipaddress.ip_address(client_ip) in ipaddress.ip_network(
            cidr, strict=False)
    except ValueError:
        return False


def route_owner(vlan, tenant, client_ip: Optional[str] = None) -> dict:
    """Quale apparato instrada ``vlan`` nel tenant indicato.

    ``tenant`` a ``None`` significa che non lo si conosce: si rifiuta senza
    cercare, perche' una ricerca senza confine puo' restituire l'apparato di un
    altro cliente.
    """
    from ai import config_analyzer
    from services import inventory_manager

    if tenant is None:
        return {"known": False, "unreadable": [],
                "reason": "tenant del client sconosciuto: senza confine la "
                          "ricerca potrebbe restituire l'apparato di un'altra "
                          "rete"}

    vlan = str(vlan)
    key = tenant_key(tenant)

    # Entrambi i gate: allowed_groups regge anche se il controllo di falsy di
    # group_filter cambiasse, e da solo impedisce la scansione larga.
    analyses = config_analyzer.analyze_all(
        group_filter=key, allowed_groups=[key]).get("devices") or []

    in_tenant = [d.get("IP") for d in inventory_manager.get_all_devices()
                 if d.get("IP") and tenant_key(d.get("Group")) == key]
    analysed = {a.get("ip") for a in analyses}
    unreadable = sorted(ip for ip in in_tenant if ip not in analysed)

    candidates = []
    for analysis in analyses:
        svi_ip = _svi_candidates(analysis, vlan)
        if svi_ip is not None:
            candidates.append((analysis.get("ip"), svi_ip, analysis))

    if client_ip:
        narrowed = [c for c in candidates if _contains(c[1], client_ip)]
        if len(narrowed) == 1:
            candidates = narrowed

    if len(candidates) == 1:
        device_ip, svi_ip, analysis = candidates[0]
        return {"known": True, "device_ip": device_ip, "svi_ip": svi_ip or None,
                "source": "config", "backup_age_s": _age(analysis),
                "unreadable": unreadable}

    if len(candidates) > 1:
        return {"known": False, "unreadable": unreadable,
                "candidates": sorted(c[0] for c in candidates),
                "reason": f"{len(candidates)} apparati instradano la VLAN "
                          f"{vlan} e nessuno e' distinguibile dall'indirizzo "
                          "del client: quale sia il suo gateway non si puo' dire"}

    if unreadable:
        return {"known": False, "unreadable": unreadable,
                "reason": f"nessuna interfaccia L3 trovata per la VLAN {vlan}, "
                          f"ma {len(unreadable)} apparati del tenant sono senza "
                          f"backup ({', '.join(unreadable)}): la risposta e' "
                          "ignota, non 'nessuna rotta'"}

    return {"known": False, "unreadable": [],
            "reason": f"nessun apparato del tenant '{key}' ha un'interfaccia L3 "
                      f"per la VLAN {vlan}"}


def _age(analysis) -> Optional[int]:
    import time
    ts = analysis.get("backup_ts")
    return int(time.time()) - int(ts) if ts else None
```

- [ ] **Step 4: Eseguire i test e verificare che passino**

Run: `uv run python -m unittest tests.test_vlan_routing -v`
Expected: PASS, tutti.

- [ ] **Step 5: Cancelli e commit**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
git add services/vlan_routing.py tests/test_vlan_routing.py
git commit -m "feat(diagnosis): derive which device routes a VLAN from the backups" -m "The answer is in the configuration the program already collects: an SVI on an L3 switch, or a VLAN sub-interface on a FortiGate. The tenant bounds the search because an unbounded one could return another customer's device, and a device without a backup makes the answer unknown rather than 'no route'." -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 4: Assegnazione manuale come ripiego

**Files:**
- Modify: `services/vlan_routing.py`
- Test: `tests/test_vlan_routing.py`

**Interfaces:**
- Consumes: `route_owner` del Task 3, `core.data_config.get_path`.
- Produces: `route_owner` puo' ora tornare `source: "manual"` con
  `svi_ip: None` e `backup_age_s: None`. Nessuna firma nuova.

- [ ] **Step 1: Scrivere i test che falliscono**

In coda a `tests/test_vlan_routing.py`, prima di `if __name__`:

```python
class TestManualOverride(_Base):

    def _with_file(self, content, analyses, devices, **kw):
        import json
        path = os.path.join(tempfile.mkdtemp(prefix="vlanroute_ovr_"),
                            "vlan_routing.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content if isinstance(content, str) else json.dumps(content))
        with patch.object(vlan_routing, "VLAN_ROUTING_JSON", path):
            return self._run(analyses, devices, **kw)

    def test_the_override_answers_when_the_config_is_silent(self):
        out = self._with_file(
            {"tenants": {"sede-a": {"226": "192.0.2.254"}}},
            [], [{"IP": "192.0.2.254", "Group": "sede-a"}])
        self.assertTrue(out["known"], out.get("reason"))
        self.assertEqual(out["device_ip"], "192.0.2.254")
        self.assertEqual(out["source"], "manual")
        self.assertIsNone(out["svi_ip"])
        self.assertIsNone(out["backup_age_s"])

    def test_the_override_wins_over_an_unreadable_device_and_says_so(self):
        # Precedenza decisa nella spec: riempire il vuoto di un backup mancante
        # e' il motivo per cui l'override esiste. Non nasconde niente pero'.
        out = self._with_file(
            {"tenants": {"sede-a": {"226": "192.0.2.254"}}},
            [], [{"IP": "192.0.2.254", "Group": "sede-a"},
                 {"IP": "192.0.2.20", "Group": "sede-a"}])
        self.assertTrue(out["known"], out.get("reason"))
        self.assertEqual(out["source"], "manual")
        self.assertEqual(sorted(out["unreadable"]), ["192.0.2.20", "192.0.2.254"])

    def test_the_config_wins_over_the_override(self):
        out = self._with_file(
            {"tenants": {"sede-a": {"226": "192.0.2.254"}}},
            [_ios("192.0.2.20", 226, "192.0.2.1/24")],
            [{"IP": "192.0.2.20", "Group": "sede-a"}],
            client_ip="192.0.2.50")
        self.assertEqual(out["source"], "config")
        self.assertEqual(out["device_ip"], "192.0.2.20")

    def test_an_override_naming_an_unknown_device_is_not_used(self):
        out = self._with_file(
            {"tenants": {"sede-a": {"226": "192.0.2.77"}}},
            [], [{"IP": "192.0.2.20", "Group": "sede-a"}])
        self.assertFalse(out["known"])

    def test_a_broken_file_is_treated_as_absent(self):
        out = self._with_file("{ questo non e' JSON",
                              [_ios("192.0.2.20", 226, "192.0.2.1/24")],
                              [{"IP": "192.0.2.20", "Group": "sede-a"}],
                              client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))

    def test_the_override_is_read_from_the_client_tenant_only(self):
        out = self._with_file(
            {"tenants": {"sede-b": {"226": "192.0.2.254"}}},
            [], [{"IP": "192.0.2.254", "Group": "sede-a"}])
        self.assertFalse(out["known"])
```

- [ ] **Step 2: Eseguire i test e verificare che falliscano**

Run: `uv run python -m unittest tests.test_vlan_routing.TestManualOverride -v`
Expected: FAIL con `AttributeError: <module 'services.vlan_routing'> does not have the attribute 'VLAN_ROUTING_JSON'`.

- [ ] **Step 3: Implementare**

In `services/vlan_routing.py`, dopo gli import:

```python
from core import data_config

VLAN_ROUTING_JSON = data_config.get_path("vlan_routing.json")
```

E aggiungere la lettura:

```python
def _manual_owner(tenant_name: str, vlan: str) -> str:
    """Apparato dichiarato a mano per quella VLAN, o "".

    File scritto a mano: rotto o illeggibile vale come assente. Una riga
    sbagliata non deve far fallire una diagnosi che senza di lei funzionerebbe
    comunque - stessa tolleranza di ``snmp_defaults._load``.
    """
    import json
    import os
    if not os.path.exists(VLAN_ROUTING_JSON):
        return ""
    try:
        with open(VLAN_ROUTING_JSON, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return str(((data.get("tenants") or {}).get(tenant_name) or {}).get(
            str(vlan)) or "")
    except Exception as e:
        logger.warning("vlan_routing.json illeggibile, ignorato: %s", e)
        return ""
```

In `route_owner`, sostituire il blocco finale (dopo il ramo `len(candidates) > 1`)
con:

```python
    manual = _manual_owner(key, vlan)
    if manual and manual in in_tenant:
        return {"known": True, "device_ip": manual, "svi_ip": None,
                "source": "manual", "backup_age_s": None,
                "unreadable": unreadable}

    if unreadable:
        return {"known": False, "unreadable": unreadable,
                "reason": f"nessuna interfaccia L3 trovata per la VLAN {vlan}, "
                          f"ma {len(unreadable)} apparati del tenant sono senza "
                          f"backup ({', '.join(unreadable)}): la risposta e' "
                          "ignota, non 'nessuna rotta'"}

    return {"known": False, "unreadable": [],
            "reason": f"nessun apparato del tenant '{key}' ha un'interfaccia L3 "
                      f"per la VLAN {vlan}"}
```

Nota: `manual in in_tenant` e' il controllo che impedisce a una riga vecchia di
puntare a un apparato non piu' in inventario, e insieme la confina al tenant.

- [ ] **Step 4: Eseguire i test e verificare che passino**

Run: `uv run python -m unittest tests.test_vlan_routing -v`
Expected: PASS, tutti.

- [ ] **Step 5: Cancelli e commit**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
git add services/vlan_routing.py tests/test_vlan_routing.py
git commit -m "feat(diagnosis): let an operator declare the router of a VLAN" -m "Read-only fallback in data/vlan_routing.json, consulted only once the configuration has said nothing. It wins over an unreadable device, because filling that gap is the reason it exists, and the answer still carries the devices nobody could read. A broken file counts as absent." -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 5: Chiudere la catena nella diagnosi

**Files:**
- Modify: `services/client_diagnosis.py:395-396` (firma `_trunk_chain`), `:512-514` (chiamata), `static/js/diagnosi.js`
- Test: `tests/test_client_diagnosis.py`

**Interfaces:**
- Consumes: `vlan_routing.route_owner(vlan, tenant, client_ip)` (Task 3-4).
- Produces: la sezione `trunk` porta `gateway_source` (`"arp"` | `"config"` |
  `"manual"`), e con sorgente diversa da `"arp"` anche `gateway_device`,
  `gateway_vlan_ip`, `gateway_backup_age_s`.

- [ ] **Step 1: Scrivere il test che fallisce**

In `tests/test_client_diagnosis.py`, in coda alla classe
`TestFortigateResolution` (o in una classe nuova dopo di essa):

```python
class TestDerivedGateway(unittest.TestCase):
    """Senza gateway ARP la catena non si percorreva. Se la configurazione dice
    chi instrada la VLAN, il capolinea c'e' lo stesso."""

    def test_the_chain_uses_the_derived_gateway(self):
        derived = {"known": True, "device_ip": "192.0.2.20",
                   "svi_ip": "192.0.2.1/24", "source": "config",
                   "backup_age_s": 3600, "unreadable": []}
        with patch("services.vlan_routing.route_owner", return_value=derived), \
             patch("services.client_diagnosis._hop_path", return_value=[]), \
             patch("services.client_diagnosis._trunk_check",
                   return_value={"known": True, "ok": True, "carrying": []}):
            out = client_diagnosis._trunk_chain("192.0.2.30", None, "226",
                                                "sede-a", "192.0.2.50")
        self.assertEqual(out["gateway_source"], "config")
        self.assertEqual(out["gateway_device"], "192.0.2.20")
        self.assertEqual(out["gateway_vlan_ip"], "192.0.2.1/24")

    def test_an_arp_gateway_keeps_the_old_shape(self):
        with patch("services.client_diagnosis._hop_path", return_value=[]), \
             patch("services.client_diagnosis._trunk_check",
                   return_value={"known": True, "ok": True, "carrying": []}):
            out = client_diagnosis._trunk_chain("192.0.2.30", "192.0.2.1", "226",
                                                "sede-a", "192.0.2.50")
        self.assertEqual(out["gateway_source"], "arp")
        self.assertNotIn("gateway_device", out)

    def test_a_failed_derivation_reports_its_reason(self):
        derived = {"known": False, "unreadable": ["192.0.2.99"],
                   "reason": "la risposta e' ignota"}
        with patch("services.vlan_routing.route_owner", return_value=derived), \
             patch("services.client_diagnosis._trunk_check",
                   return_value={"known": True, "ok": True, "carrying": []}):
            out = client_diagnosis._trunk_chain("192.0.2.30", None, "226",
                                                "sede-a", "192.0.2.50")
        self.assertEqual(out["gateway_source"], "arp")
        self.assertIn("ignota", out["route_owner_reason"])
```

- [ ] **Step 2: Eseguire il test e verificare che fallisca**

Run: `uv run python -m unittest tests.test_client_diagnosis.TestDerivedGateway -v`
Expected: FAIL con `TypeError: _trunk_chain() takes from 3 to 4 positional arguments but 5 were given`.

- [ ] **Step 3: Implementare**

In `services/client_diagnosis.py`, cambiare la firma e l'inizio di
`_trunk_chain`:

```python
def _trunk_chain(access_switch_ip: str, gateway_ip: Optional[str], vlan,
                 tenant: Optional[str] = None,
                 client_ip: Optional[str] = None) -> dict:
```

Subito dopo il controllo `if not vlan:`, inserire:

```python
    # Senza gateway ARP il capolinea manca e la catena non si percorre. La
    # configurazione pero' sa chi instrada la VLAN: se lo dice, il capolinea
    # c'e' lo stesso, e la risposta dichiara da dove viene.
    gateway_source, derived = "arp", None
    if not gateway_ip:
        from services import vlan_routing
        derived = vlan_routing.route_owner(vlan, tenant, client_ip)
        if derived.get("known"):
            gateway_ip = derived["device_ip"]
            gateway_source = derived["source"]
```

Alla fine della funzione, prima di ogni `return`, i campi vanno aggiunti. Il
modo piu' semplice e' racchiudere il risultato: sostituire il corpo esistente
con una chiamata interna e decorare l'esito. Rinominare la funzione esistente in
`_trunk_chain_inner(access_switch_ip, gateway_ip, vlan, tenant)` (invariata,
senza il blocco appena aggiunto) e scrivere:

```python
def _trunk_chain(access_switch_ip: str, gateway_ip: Optional[str], vlan,
                 tenant: Optional[str] = None,
                 client_ip: Optional[str] = None) -> dict:
    """La VLAN del client passa su TUTTA la catena fino al gateway?

    Il capolinea e' il gateway ARP quando c'e'; quando manca lo si deduce dalla
    configurazione (``vlan_routing.route_owner``). La risposta dice sempre da
    quale delle due strade viene, perche' un gateway dedotto vale quanto il
    backup che lo dichiara.
    """
    gateway_source, derived = "arp", None
    if not gateway_ip and vlan:
        from services import vlan_routing
        derived = vlan_routing.route_owner(vlan, tenant, client_ip)
        if derived.get("known"):
            gateway_ip = derived["device_ip"]
            gateway_source = derived["source"]

    out = _trunk_chain_inner(access_switch_ip, gateway_ip, vlan, tenant)
    out["gateway_source"] = gateway_source
    if gateway_source != "arp" and derived:
        out["gateway_device"] = derived["device_ip"]
        out["gateway_vlan_ip"] = derived.get("svi_ip")
        out["gateway_backup_age_s"] = derived.get("backup_age_s")
    if derived and not derived.get("known"):
        out["route_owner_reason"] = derived.get("reason", "")
        if derived.get("candidates"):
            out["gateway_candidates"] = derived["candidates"]
    if derived and derived.get("unreadable"):
        out["unreadable_devices"] = derived["unreadable"]
    return out
```

Aggiornare il chiamante in `_l2_health` (intorno a `:512`):

```python
        out["trunk"] = _trunk_chain(switch_ip, position.get("gateway_ip"), vlan,
                                    position.get("tenant"),
                                    position.get("ip"))
```

- [ ] **Step 4: Eseguire i test e verificare che passino**

Run: `uv run python -m unittest tests.test_client_diagnosis -v`
Expected: PASS, comprese tutte le prove preesistenti sulla catena.

- [ ] **Step 5: Mostrarlo nel referto**

In `static/js/diagnosi.js`, nella resa della sezione trunk, aggiungere dopo la
riga dello `scope`:

```javascript
        if (t.gateway_source && t.gateway_source !== 'arp') {
            const age = t.gateway_backup_age_s
                ? ` — ${en ? 'backup' : 'backup di'} ${Math.floor(t.gateway_backup_age_s / 86400)}g`
                : '';
            const how = t.gateway_source === 'manual'
                ? (en ? 'declared by an operator' : 'dichiarato da un operatore')
                : (en ? 'derived from the configuration' : 'dedotto dalla configurazione');
            out += `<div style="font-size:12px; color:var(--text-muted); margin-top:6px;">
                <i class="fa-solid fa-route" style="margin-right:6px;"></i>${escapeHtml(en ? 'VLAN gateway' : 'Gateway della VLAN')}:
                ${escapeHtml(jsStr(t.gateway_device || ''))}${t.gateway_vlan_ip ? ' (' + escapeHtml(jsStr(t.gateway_vlan_ip)) + ')' : ''} — ${how}${age}</div>`;
        }
```

Verificare la sintassi: `node --check static/js/diagnosi.js`.

- [ ] **Step 6: Cancelli e commit**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
node --check static/js/diagnosi.js
graphify update .
git add services/client_diagnosis.py static/js/diagnosi.js tests/test_client_diagnosis.py
git commit -m "feat(diagnosis): walk the trunk chain to a gateway read from the config" -m "Without an ARP gateway the chain had no end and degraded to the access switch alone. When the configuration names the device routing the VLAN, the end exists after all, and the report says which of the two roads the answer came from, with the age of the backup behind it." -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Self-review del piano

**Copertura della spec**

| Requisito | Task |
|---|---|
| `route_owner` con la forma dichiarata | 3 (campi), 4 (`source: manual`) |
| tenant `None` rifiuta, `""` e' `"Generale"` | 3 |
| entrambi i gate `group_filter` + `allowed_groups` | 3 |
| ignoto ≠ assente, `unreadable` sempre valorizzato | 3 |
| precedenza override vs illeggibile | 4 |
| `vlanid` FortiOS | 1 |
| memo `(ip, mtime)` con tetto LRU | 2 |
| parità dichiarata, nessun tie-break HA | 3 |
| JSON rotto = assente | 4 |
| contratto `gateway_source` e campi assenti con `arp` | 5 |
| riga nel referto | 5 |

**Non coperto di proposito** (§Fuori ambito della spec): vista "chi instrada
cosa", rotta/UI per l'override, tie-break HSRP/VRRP, PAN-OS, IPv6, indirizzi
secondari.

**Nomi verificati coerenti fra task**: `analyze_device_cached` (T2 → T3),
`vlan_interfaces` (T1 → T3), `route_owner`/`tenant_key` (T3 → T4, T5),
`VLAN_ROUTING_JSON` (T4), `_trunk_chain_inner` (T5).

**Nota per chi esegue il Task 3**: il piano scrive `route_owner` senza il ramo
manuale, che arriva nel Task 4. È voluto: il Task 3 deve restare verde da solo.

**Test esistente toccato dal Task 5**, da leggere prima di scrivere codice:
`tests/test_client_diagnosis.py:339` (`test_the_trunk_chain_says_why_it_has_no_chain`)
chiama `_trunk_chain("192.0.2.20", None, "10", "sede-a")` — cioè proprio il ramo
senza gateway ARP che il Task 5 modifica. Dopo la modifica quella chiamata
entrerà in `route_owner`, che a sua volta chiama `analyze_all` e
`get_all_devices` non messi in patch dal test.

Il test **deve restare verde senza cambiarne le asserzioni**: con l'inventario
vuoto della suite `route_owner` non trova candidati, torna `known: False`, il
gateway resta `None` e il degrado è quello di prima. Se invece diventasse rosso,
non aggiustare l'asserzione: significa che il ramo `arp` ha cambiato forma, ed è
il contratto dichiarato nella spec («con `gateway_source: "arp"` gli altri campi
restano assenti»). Quel test sta nella classe `TestPositionWithoutArp`, non in
`TestTrunkChain`: verificarlo esplicitamente, prima e dopo il Task 5, con

```sh
uv run python -m unittest tests.test_client_diagnosis.TestPositionWithoutArp -v
uv run python -m unittest tests.test_client_diagnosis.TestTrunkChain -v
```
