# Endpoint Inventory + diagnosi multi-tenant — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Aggiungere la tab "Endpoint Inventory" (elenco client per tenant, filtrabile ed esportabile) e togliere alla diagnosi client la scelta automatica della sede quando un indirizzo esiste in più tenant.

**Architecture:** L'inventario è **derivato in lettura**, nessuna tabella nuova: `mac_sightings` (verità L2) è la sorgente, `arp_entries` si aggancia a sinistra per gli IP, `switch_if_macs` fornisce sia l'esclusione dell'infrastruttura sia l'elenco interfacce per l'occupazione porte. Le due query nuove vivono in `collectors/mac_history.py`, che possiede già DB, lock e i riclassificatori; il router è sottile; l'export è un `Blob` lato browser.

**Tech Stack:** Python 3.12 + FastAPI + SQLite (WAL), frontend vanilla JS senza build step, test `unittest` (nessun runner JS).

Spec di riferimento: [`docs/superpowers/specs/2026-08-03-endpoint-inventory-design.md`](../specs/2026-08-03-endpoint-inventory-design.md).
**La Parte C della spec è già fatta e committata** (`bdc8d5f`) — non rifarla.

## Global Constraints

- **Nessun dato reale nel repo.** Indirizzi RFC 5737 (`192.0.2.x`, `198.51.100.x`), nomi segnaposto (`switch-01`, `sede-a`), MAC di esempio (`aa:bb:cc:dd:ee:01`). Mai un hostname, IP, modello o seriale del laboratorio — nel codice, nei test, nei commenti, nei messaggi di commit. Vedi `CLAUDE.md` §"Protect real data".
- **Lingua:** codice, commenti, docstring e stringhe di test in italiano, come tutto il progetto.
- **Prima di ogni commit**, eseguiti davvero e con l'output letto:
  ```sh
  uv run pyrefly check                          # 0 errors
  uv run python -m unittest discover -s tests   # tutti verdi
  graphify update .                             # dopo modifiche al codice
  ```
  Mai dichiarare verde un controllo che non è stato eseguito.
- **Escaping frontend:** ogni valore che arriva dagli apparati passa da `escapeHtml(jsStr(x))`.
- **i18n:** le icone Font Awesome degli elementi tradotti stanno DENTRO la stringa i18n — `changeLanguage()` sostituisce `innerHTML` in blocco e un'icona fuori dalla stringa sparisce al cambio lingua. Ogni chiave va aggiunta a ENTRAMBI i dizionari di `static/js/i18n.js` (IT e EN).
- **Convenzione `known`:** `known: True` significa "ho potuto rispondere", non "va tutto bene". Una sezione vuota è `known: True` con `empty: True`.
- **Due allowlist di parità indipendenti** in `tests/test_router_parity.py`: `TestRouterParity` (riga ~58 e ~68) e `TestFullParity` (riga ~151). Una rotta nuova può passare la prima e fallire la seconda.
- **Nessun runner JS:** il frontend si verifica grep-style con `frontend_source()` da `tests/test_helpers_frontend.py`.

---

## File Structure

| File | Responsabilità | Stato |
|---|---|---|
| `services/client_diagnosis.py` | stop alla scelta automatica del tenant in `diagnose()` | modifica |
| `static/js/diagnosi.js` | schermata `ambiguous` al posto della striscia sotto il referto | modifica |
| `collectors/mac_history.py` | `endpoint_inventory()` e `port_occupancy()` — le due query nuove | modifica |
| `routers/endpoint_inventory.py` | due rotte GET, scoping per tenant, nient'altro | **nuovo** |
| `app_server.py` | registrazione del router | modifica |
| `static/js/endpoint-inventory.js` | KPI, filtri, tabella, export, occupazione porte | **nuovo** |
| `templates/dashboard.html` | sezione `tab-endpoints`, quarta sotto-tab, include dello script | modifica |
| `static/js/i18n.js` | chiavi IT + EN della tab | modifica |
| `tests/test_endpoint_inventory.py` | rollup, flag, occupazione porte, scoping, frontend grep | **nuovo** |
| `tests/test_client_diagnosis.py` | stato `ambiguous` | modifica |
| `tests/test_router_parity.py` | `/api/endpoints` in `ALLOWED_NEW_PREFIXES` | modifica |

Il nome del modulo è `endpoint_inventory.py` e non `endpoints.py`: quel nome è già di `observability/endpoints.py` (classificatore di indirizzi), e due moduli omonimi con scopi diversi si confondono alla prima lettura.

---

## Task 1: `diagnose()` non sceglie più la sede

**Files:**
- Modify: `services/client_diagnosis.py:1012-1013` (dentro `diagnose()`)
- Test: `tests/test_client_diagnosis.py`

**Interfaces:**
- Consumes: `_position(client, is_mac, tenants) -> dict`, che con più candidati popola già `position["tenants_available"]` (lista di dict con `tenant`, `site`, `ip`, `mac`, `switch_name`, `switch_port`, `last_seen`, `l2_only`).
- Produces: `diagnose()` può ora restituire `{"client", "client_type", "generated_ts", "status": "ambiguous", "tenants_available": [...]}` — **senza** `sections` e **senza** `complete`.

**Perché funziona senza un flag "il chiamante ha scelto":** quando il router passa `tenants=[scelto]`, `_position()` interroga solo quel tenant, i candidati sono uno solo e `tenants_available` non viene nemmeno popolato. Basta quindi contare i candidati. Un utente il cui profilo contiene una sola sede non vede mai la domanda.

- [ ] **Step 1: Scrivi il test che fallisce**

In coda a `tests/test_client_diagnosis.py`:

```python
class TestTenantAmbiguo(unittest.TestCase):
    """Con lo stesso indirizzo in piu' sedi non si diagnostica: si chiede.

    Scegliere la piu' recente e presentare un referto completo dichiara
    definitiva una scelta che nessuno ha confermato — e la sezione dopo e' un
    pulsante che tocca la rete.
    """

    def _due_sedi(self):
        return [
            dict(CLIENT, tenant="sede-a",
                 last_seen="2026-08-03T10:00:00", port_last_seen="2026-08-03T10:00:00"),
            dict(CLIENT, tenant="sede-b", ip="198.51.100.7",
                 last_seen="2026-08-01T09:00:00", port_last_seen="2026-08-01T09:00:00"),
        ]

    def _diagnose(self, entries, tenants=None):
        """client_map() filtra per tenant come fa quella vera: e' il
        meccanismo su cui poggia tutto il comportamento."""
        def fake(ip=None, mac=None, tenants=None, limit=500, source_ip=None):
            if tenants is None:
                return list(entries)
            return [e for e in entries if e["tenant"] in tenants]

        with patch("collectors.mac_history.client_map", side_effect=fake), \
             patch("collectors.mac_history.positions_for_mac", return_value=[]):
            return client_diagnosis.diagnose("aa:bb:cc:dd:ee:ff", tenants=tenants)

    def test_due_tenant_nessun_referto(self):
        out = self._diagnose(self._due_sedi())

        self.assertEqual(out["status"], "ambiguous")
        self.assertEqual(len(out["tenants_available"]), 2)
        self.assertNotIn("sections", out)
        self.assertNotIn("complete", out)

    def test_i_candidati_arrivano_dal_piu_recente(self):
        out = self._diagnose(self._due_sedi())

        self.assertEqual(out["tenants_available"][0]["tenant"], "sede-a")

    def test_con_il_tenant_indicato_il_referto_si_produce(self):
        out = self._diagnose(self._due_sedi(), tenants=["sede-b"])

        self.assertNotEqual(out.get("status"), "ambiguous")
        self.assertIn("sections", out)
        self.assertEqual(out["sections"]["position"]["tenant"], "sede-b")

    def test_un_solo_tenant_nessuna_domanda(self):
        """Il caso normale — la maggioranza — non cambia."""
        out = self._diagnose([dict(CLIENT, tenant="sede-a")])

        self.assertNotEqual(out.get("status"), "ambiguous")
        self.assertIn("sections", out)
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_client_diagnosis.TestTenantAmbiguo -v`
Expected: FAIL — `KeyError: 'status'` oppure `'ambiguous' != None`, perché oggi il referto si produce comunque.

- [ ] **Step 3: Implementa**

In `services/client_diagnosis.py`, dentro `diagnose()`, subito dopo le due righe:

```python
    _section(result, "position", _position, client, is_mac, tenants)
    position = result["sections"]["position"]
```

inserisci:

```python
    # Piu' tenant e nessuno indicato: NON si diagnostica. Un tenant e' una rete
    # a se', e "la piu' recente" e' una scelta che nessuno ha confermato: il
    # referto uscirebbe completo e definitivo su una sede scelta dal programma,
    # con sotto un pulsante che stacca una porta. Nessun apparato viene
    # interrogato — qui si e' ancora sul solo dato storico.
    #
    # Quando il chiamante indica il tenant, il router restringe ``tenants`` e
    # ``_position`` trova un candidato solo: questa via non scatta.
    available = position.get("tenants_available") or []
    if len(available) > 1:
        return {"client": client, "client_type": result["client_type"],
                "generated_ts": result["generated_ts"],
                "status": "ambiguous", "tenants_available": available}
```

- [ ] **Step 4: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_client_diagnosis -v`
Expected: PASS, inclusi i test preesistenti della diagnosi.

- [ ] **Step 5: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add services/client_diagnosis.py tests/test_client_diagnosis.py
git commit -m "feat(diagnosis): stop picking a tenant when an address exists in several

An address present in more than one site now returns status \"ambiguous\"
with the candidate list and no report at all. Picking the most recent one
and rendering a complete report presented a choice nobody confirmed as
settled, with a port-bounce button underneath it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 2: la schermata `ambiguous` al posto del referto

**Files:**
- Modify: `static/js/diagnosi.js:128-133` (inizio di `renderDiagnosi`), `:157` (rimozione della chiamata dal riquadro posizione), `:276-305` (`_diagTenantChoice`)
- Test: `tests/test_endpoint_inventory.py` **no** — i grep di questa parte vanno in `tests/test_client_diagnosis.py`

**Interfaces:**
- Consumes: la risposta di Task 1 — `{status: "ambiguous", tenants_available: [...]}`.
- Produces: `_diagTenantChoice(d)` ora restituisce un **pannello intero** e non una striscia; `renderDiagnosi(d, dest)` esce subito sullo stato `ambiguous`. `diagnosiPickTenant(tenant)` resta invariata.

- [ ] **Step 1: Scrivi il test che fallisce**

In coda a `tests/test_client_diagnosis.py`:

```python
class TestTenantAmbiguoFrontend(unittest.TestCase):
    """Verifica grep-style: non c'e' un runner JS."""

    @classmethod
    def setUpClass(cls):
        from tests.test_helpers_frontend import frontend_source
        cls.src = frontend_source()

    def test_lo_stato_ambiguous_esce_prima_del_referto(self):
        self.assertIn("if (d.status === 'ambiguous')", self.src)

    def test_la_scelta_non_e_piu_una_striscia_del_riquadro_posizione(self):
        """Chiamata una volta sola, dal ramo 'ambiguous'. Se restasse anche
        dentro il riquadro posizione, il referto tornerebbe a uscire con una
        sede gia' scelta e i chip sotto."""
        self.assertEqual(self.src.count("_diagTenantChoice("), 2)  # 1 def + 1 uso

    def test_nessun_tenant_e_preselezionato(self):
        """Con 'la piu' recente' gia' evidenziata, la domanda avrebbe una
        risposta suggerita — cioe' la scelta del programma con un altro nome."""
        self.assertNotIn("t.tenant === p.tenant", self.src)
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_client_diagnosis.TestTenantAmbiguoFrontend -v`
Expected: FAIL su tutti e tre.

- [ ] **Step 3: Uscita anticipata in `renderDiagnosi`**

In `static/js/diagnosi.js`, dopo `if (!host) return;` (riga 132):

```javascript
    // L'indirizzo esiste in piu' sedi e nessuna e' stata scelta: non c'e'
    // nessun referto da mostrare. Mostrarne uno "provvisorio" sarebbe la
    // stessa scelta silenziosa con un'etichetta sopra.
    if (d.status === 'ambiguous') {
        host.innerHTML = _diagTenantChoice(d);
        return;
    }
```

- [ ] **Step 4: Togli la striscia dal riquadro posizione**

Alla riga 157 di `static/js/diagnosi.js`, dentro la costruzione di `position`, rimuovi la riga:

```javascript
        _diagTenantChoice(p)
```

e la virgola che la precede, così l'ultimo argomento di `_diagCard` torna a essere quello prima di lei.

- [ ] **Step 5: `_diagTenantChoice` diventa un pannello**

Sostituisci il corpo di `_diagTenantChoice` (righe 276-305) con:

```javascript
// Lo stesso indirizzo puo' esistere in piu' tenant: 192.0.2.50 sta in ogni
// sede del mondo. Sceglierne uno in silenzio significa diagnosticare la rete
// sbagliata senza dirlo, quindi si elencano e si ASPETTA. Il tenant scelto
// RESTRINGE lo scoping lato server, non lo allarga.
function _diagTenantChoice(d) {
    const list = d.tenants_available || [];
    if (list.length < 2) return '';
    const en = currentLang === 'en';
    // Ordinati dal piu' recente, con la data: e' il dato su cui si decide —
    // un portatile e' dove e' stato visto per ULTIMO. Ma nessuno e'
    // preselezionato: la scelta e' di chi legge.
    const chips = list.map(t => {
        const where = [t.switch_name, t.switch_port].filter(Boolean).join(' ');
        return `<button onclick="diagnosiPickTenant('${escapeHtml(jsStr(t.tenant))}')"
            class="btn btn-secondary btn-small" style="width:auto; margin:0; text-align:left;"
            title="${escapeHtml(jsStr(`${t.ip || ''} ${where}`.trim()))}">
            <i class="fa-solid fa-sitemap" style="margin-right:6px;"></i>${escapeHtml(jsStr(t.tenant))}
            <span style="color:var(--text-muted); font-weight:400;">
                ${escapeHtml(jsStr(t.ip || (en ? 'no IP' : 'senza IP')))}${where ? ' · ' + escapeHtml(jsStr(where)) : ''}
                · ${escapeHtml(jsStr(String(t.last_seen || '').replace('T', ' ').slice(0, 16)))}
            </span>
        </button>`;
    }).join('');
    return `<div class="panel" style="padding:22px;">
        <div style="display:flex; gap:10px; align-items:flex-start; margin-bottom:14px;">
            <i class="fa-solid fa-triangle-exclamation" style="color:var(--warning); margin-top:2px;"></i>
            <div>
                <div style="font-size:14px; font-weight:700; margin-bottom:4px;">${escapeHtml(
                    en ? 'This address exists in more than one tenant'
                       : 'Questo indirizzo esiste in piu\\' tenant')}</div>
                <div style="font-size:12px; color:var(--text-muted);">${escapeHtml(
                    en ? 'No report was produced: each site is its own network, and diagnosing the wrong one would be wrong in silence. Pick the site.'
                       : 'Nessun referto e\\' stato prodotto: ogni sede e\\' una rete a se\\', e diagnosticare quella sbagliata lo sarebbe in silenzio. Scegli la sede.')}</div>
            </div>
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">${chips}</div>
    </div>`;
}
```

- [ ] **Step 6: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_client_diagnosis -v`
Expected: PASS.

- [ ] **Step 7: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add static/js/diagnosi.js tests/test_client_diagnosis.py
git commit -m "feat(diagnosis): render the tenant question instead of a pre-picked report

The chips moved out of the position card and became the whole screen, with
no site preselected. A highlighted 'most recent' would have been the
program's choice under another name.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3: `endpoint_inventory()` — il rollup e i flag

**Files:**
- Modify: `collectors/mac_history.py` (in coda, dopo `arp_stats()`)
- Test: `tests/test_endpoint_inventory.py` (nuovo)

**Interfaces:**
- Consumes: `reclassify_sightings(rows)` (riscrive `is_uplink`/`uplink_to`/`origin_type` in loco), `observability.endpoints.classify_mac(mac) -> dict|None` e `is_stable_identity(mac) -> bool`, `services.inventory_manager.get_category_assignments() -> {ip: {"category": str}}`.
- Produces:
  ```python
  endpoint_inventory(tenants=None, site=None, switch_ip=None, vlan=None,
                     q=None, stale_days=7, limit=2000) -> dict
  # {"results": [endpoint, ...], "total": int, "truncated": bool, "counts": {...}}
  # endpoint = {mac, tenant, oui_vendor, site, ips[], switch_ip, switch_name,
  #             interface, vlan, first_seen, last_seen, seen_count,
  #             access_port_count, client_type, flags[]}
  # counts   = {endpoints, switches, vlans, stale, new, no_ip, random}
  ```
  Più gli helper di modulo `_age_days(iso, now=None) -> float|None` e `_is_physical_iface(name) -> bool` (quest'ultimo usato da Task 4).

- [ ] **Step 1: Scrivi il test che fallisce**

Crea `tests/test_endpoint_inventory.py`:

```python
# -*- coding: utf-8 -*-
"""Inventario endpoint: una riga per (MAC, tenant), derivata e mai memorizzata.

Parte da mac_sightings — la verita' L2 — e aggancia l'ARP a sinistra. Il
contrario (partire dai binding, come client_map) perderebbe ogni endpoint di
una VLAN il cui gateway non e' interrogabile: proprio quelli che un inventario
deve elencare.
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_epinv_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from collectors import mac_history  # noqa: E402

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_RANDOM = "7a:bb:cc:dd:ee:02"      # bit U/L a 1 = amministrato localmente
MAC_VM = "00:50:56:dd:ee:03"          # OUI VMware
MAC_INFRA = "aa:bb:cc:dd:ee:99"


def _iso(days_ago=0):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(timespec="seconds")


class _Base(unittest.TestCase):
    """DB vero, svuotato a ogni test: la query e' il soggetto della prova."""

    def setUp(self):
        mac_history.init_db()
        with mac_history._lock, mac_history._connect() as c:
            for table in ("mac_sightings", "arp_entries", "switch_if_macs"):
                c.execute(f"DELETE FROM {table}")
        # La topologia non e' il soggetto di questi test: senza switch noti,
        # reclassify_sightings conserva l'is_uplink scritto in raccolta.
        self.topo = patch("collectors.mac_history.topology_uplinks",
                          return_value=({}, set()))
        self.topo.start()
        self.addCleanup(self.topo.stop)
        self.assign = patch("services.inventory_manager.get_category_assignments",
                            return_value={})
        self.assign.start()
        self.addCleanup(self.assign.stop)

    def _sighting(self, mac=MAC_A, tenant="sede-a", switch_ip="192.0.2.1",
                  interface="GigabitEthernet1/0/4", vlan="10", is_uplink=0,
                  first_days=10, last_days=0, site="central",
                  switch_name="switch-01", oui="Example Corp"):
        with mac_history._lock, mac_history._connect() as c:
            c.execute(
                """INSERT INTO mac_sightings
                   (mac, oui_vendor, vlan, switch_ip, switch_name, interface,
                    port_channel, is_uplink, uplink_to, tenant, site,
                    first_seen, last_seen, seen_count)
                   VALUES (?,?,?,?,?,?,'',?,'',?,?,?,?,1)""",
                (mac, oui, vlan, switch_ip, switch_name, interface, is_uplink,
                 tenant, site, _iso(first_days), _iso(last_days)))

    def _arp(self, mac=MAC_A, ip="192.0.2.10", tenant="sede-a",
             source_ip="192.0.2.254"):
        with mac_history._lock, mac_history._connect() as c:
            c.execute(
                """INSERT INTO arp_entries
                   (mac, ip, vlan, interface, source_ip, source_name,
                    source_type, tenant, site, first_seen, last_seen, seen_count)
                   VALUES (?,?,'','',?,'gw','firewall',?,'central',?,?,1)""",
                (mac, ip, source_ip, tenant, _iso(10), _iso(0)))

    def _infra_mac(self, mac=MAC_INFRA, switch_ip="192.0.2.1",
                   interface="Vlan10"):
        with mac_history._lock, mac_history._connect() as c:
            c.execute(
                """INSERT INTO switch_if_macs
                   (mac, switch_ip, switch_name, interface, last_seen)
                   VALUES (?,?,'switch-01',?,?)""",
                (mac, switch_ip, interface, _iso(0)))


class TestRollup(_Base):

    def test_una_riga_per_mac_e_tenant(self):
        """Un tenant e' una rete a se': lo stesso MAC in due sedi e'
        legittimamente due righe, non un duplicato da fondere."""
        self._sighting(tenant="sede-a", switch_ip="192.0.2.1")
        self._sighting(tenant="sede-b", switch_ip="198.51.100.1")

        out = mac_history.endpoint_inventory()

        self.assertEqual(out["total"], 2)
        self.assertEqual({r["tenant"] for r in out["results"]}, {"sede-a", "sede-b"})

    def test_i_mac_di_interfaccia_switch_sono_esclusi(self):
        """Infrastruttura, non endpoint. Contarli gonfia l'inventario di
        dispositivi che il cliente non possiede."""
        self._sighting(mac=MAC_A)
        self._sighting(mac=MAC_INFRA)
        self._infra_mac(MAC_INFRA)

        out = mac_history.endpoint_inventory()

        self.assertEqual([r["mac"] for r in out["results"]], [MAC_A])

    def test_gli_ip_arrivano_dall_arp_dello_stesso_tenant(self):
        self._sighting(tenant="sede-a")
        self._arp(ip="192.0.2.10", tenant="sede-a")
        self._arp(ip="192.0.2.11", tenant="sede-a")

        out = mac_history.endpoint_inventory()

        self.assertEqual(out["results"][0]["ips"], ["192.0.2.10", "192.0.2.11"])

    def test_la_posizione_e_l_ultima_di_accesso(self):
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/4",
                       last_days=5)
        self._sighting(switch_ip="192.0.2.2", interface="GigabitEthernet2/0/9",
                       last_days=0)

        out = mac_history.endpoint_inventory()

        self.assertEqual(out["results"][0]["switch_ip"], "192.0.2.2")

    def test_gli_uplink_non_sono_una_posizione(self):
        """La porta di un uplink dice dov'e' il cavo, non dov'e' il client."""
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/4",
                       last_days=5)
        self._sighting(switch_ip="192.0.2.9", interface="Port-channel1",
                       is_uplink=1, last_days=0)

        out = mac_history.endpoint_inventory()

        self.assertEqual(out["results"][0]["switch_ip"], "192.0.2.1")
        self.assertEqual(out["results"][0]["access_port_count"], 1)


class TestFlag(_Base):

    def _flags(self, **kw):
        return mac_history.endpoint_inventory(**kw)["results"][0]["flags"]

    def test_ambiguous_due_porte_di_accesso(self):
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/4")
        self._sighting(switch_ip="192.0.2.2", interface="GigabitEthernet2/0/9")
        self._arp()

        self.assertIn("AMBIGUOUS", self._flags())

    def test_no_ip_senza_binding_arp(self):
        """Chi non ha visibilita' L3 localizza comunque il client dalla MAC
        table: l'endpoint c'e', l'IP no, e va detto."""
        self._sighting()

        self.assertIn("NO-IP", self._flags())

    def test_multi_ip(self):
        self._sighting()
        self._arp(ip="192.0.2.10")
        self._arp(ip="192.0.2.11")

        self.assertIn("MULTI-IP", self._flags())

    def test_random_mac_amministrato_localmente(self):
        """Il binding vale per questa sessione e basta: correlare uno storico
        su di esso inventa continuita' dove non ce n'e'."""
        self._sighting(mac=MAC_RANDOM)

        self.assertIn("RANDOM", self._flags())

    def test_vm_oui_di_virtualizzazione(self):
        self._sighting(mac=MAC_VM)

        flags = self._flags()
        self.assertIn("VM", flags)
        self.assertNotIn("RANDOM", flags)

    def test_transit_only_visto_solo_su_uplink(self):
        """Endpoint reale dietro uno switch non gestito: resta in elenco."""
        self._sighting(interface="Port-channel1", is_uplink=1)

        out = mac_history.endpoint_inventory()
        self.assertEqual(out["total"], 1)
        self.assertIn("TRANSIT-ONLY", out["results"][0]["flags"])
        self.assertEqual(out["results"][0]["access_port_count"], 0)

    def test_stale_oltre_la_soglia(self):
        self._sighting(first_days=40, last_days=30)

        self.assertIn("STALE", self._flags(stale_days=7))

    def test_non_stale_dentro_la_soglia(self):
        self._sighting(first_days=40, last_days=2)

        self.assertNotIn("STALE", self._flags(stale_days=7))

    def test_new_primo_avvistamento_recente(self):
        self._sighting(first_days=1, last_days=0)

        self.assertIn("NEW", self._flags(stale_days=7))

    def test_non_new_se_visto_da_tempo(self):
        self._sighting(first_days=40, last_days=0)

        self.assertNotIn("NEW", self._flags(stale_days=7))


class TestFiltriEScoping(_Base):

    def test_lo_scoping_per_tenant_e_una_barriera(self):
        """Un utente della sede A non vede mai una riga della sede B."""
        self._sighting(tenant="sede-a")
        self._sighting(tenant="sede-b", switch_ip="198.51.100.1")

        out = mac_history.endpoint_inventory(tenants=["sede-a"])

        self.assertEqual(out["total"], 1)
        self.assertEqual(out["results"][0]["tenant"], "sede-a")

    def test_scope_vuoto_non_e_scope_assente(self):
        """[] significa 'nessun tenant visibile'. Trattarlo come None
        mostrerebbe tutto proprio a chi non puo' vedere niente."""
        self._sighting(tenant="sede-a")

        self.assertEqual(mac_history.endpoint_inventory(tenants=[])["total"], 0)

    def test_filtro_per_switch(self):
        self._sighting(switch_ip="192.0.2.1")
        self._sighting(mac=MAC_VM, switch_ip="192.0.2.2")

        out = mac_history.endpoint_inventory(switch_ip="192.0.2.2")

        self.assertEqual([r["mac"] for r in out["results"]], [MAC_VM])

    def test_ricerca_libera_su_mac_e_vendor(self):
        self._sighting(mac=MAC_A, oui="Example Corp")
        self._sighting(mac=MAC_VM, oui="Altro Vendor")

        self.assertEqual(mac_history.endpoint_inventory(q="ee:01")["total"], 1)
        self.assertEqual(mac_history.endpoint_inventory(q="Example")["total"], 1)

    def test_limite_dichiarato_non_silenzioso(self):
        """Una tabella HTML non regge decine di migliaia di righe: si taglia e
        lo si DICE, cosi' l'export puo' avvertire che esporta cio' che vede."""
        for i in range(5):
            self._sighting(mac=f"aa:bb:cc:dd:ee:1{i}")

        out = mac_history.endpoint_inventory(limit=2)

        self.assertEqual(len(out["results"]), 2)
        self.assertEqual(out["total"], 5)
        self.assertTrue(out["truncated"])

    def test_contatori(self):
        self._sighting(mac=MAC_A, switch_ip="192.0.2.1", vlan="10")
        self._sighting(mac=MAC_VM, switch_ip="192.0.2.2", vlan="20")
        self._arp(mac=MAC_A)

        counts = mac_history.endpoint_inventory()["counts"]

        self.assertEqual(counts["endpoints"], 2)
        self.assertEqual(counts["switches"], 2)
        self.assertEqual(counts["vlans"], 2)
        self.assertEqual(counts["no_ip"], 1)
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_endpoint_inventory -v`
Expected: FAIL — `AttributeError: module 'collectors.mac_history' has no attribute 'endpoint_inventory'`.

- [ ] **Step 3: Implementa**

In coda a `collectors/mac_history.py`, dopo `arp_stats()`:

```python
# --- Inventario endpoint (derivato, mai memorizzato) -------------------------

# Interfacce in cui non si infila un cavo: restano visibili, ma fuori dal
# conteggio delle porte libere.
_NON_PHYSICAL_IF = ("vlan", "loopback", "null", "port-channel", "tunnel", "bdi")


def _is_physical_iface(name: str) -> bool:
    return not (name or "").lower().startswith(_NON_PHYSICAL_IF)


def _age_days(iso: str, now=None):
    """Giorni trascorsi da un timestamp ISO, None se non interpretabile.

    I timestamp scritti da questo modulo portano il fuso; quelli che arrivano
    da un import piu' vecchio possono essere ingenui. Un valore illeggibile
    non e' "vecchio zero giorni": e' None, e chi lo legge non marca nulla.
    """
    if not iso:
        return None
    try:
        ts = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ((now or datetime.now(timezone.utc)) - ts).total_seconds() / 86400.0


def endpoint_inventory(tenants=None, site: Optional[str] = None,
                       switch_ip: Optional[str] = None, vlan: Optional[str] = None,
                       q: Optional[str] = None, stale_days: int = 7,
                       limit: int = 2000) -> dict:
    """Un endpoint per (MAC, tenant), dal dato gia' raccolto.

    Parte da ``mac_sightings`` — la verita' L2, ogni MAC mai visto — e aggancia
    ``arp_entries`` a sinistra per gli IP. Il contrario, cioe' partire dai
    binding come fa ``client_map()``, perderebbe ogni endpoint di una VLAN il
    cui gateway non e' interrogabile: proprio quelli che un inventario deve
    elencare.

    La chiave e' (MAC, tenant), la stessa di ``_access_positions_for()``: un
    tenant e' una rete a se', e lo stesso MAC in due sedi e' legittimamente due
    righe.

    Tutto e' DERIVATO e niente viene salvato, per la stessa ragione scritta in
    ``observability/endpoints.py``: il giorno in cui la classificazione impara
    qualcosa di nuovo, migliora anche cio' che e' stato raccolto ieri.
    """
    from observability import endpoints as ep_kb
    from services import inventory_manager

    init_db()
    tenant_list = list(tenants) if tenants is not None else None
    empty = {"results": [], "total": 0, "truncated": False,
             "counts": {"endpoints": 0, "switches": 0, "vlans": 0,
                        "stale": 0, "new": 0, "no_ip": 0, "random": 0}}
    # [] = "nessun tenant visibile", che non e' None = "nessuna restrizione".
    if tenant_list is not None and not tenant_list:
        return empty

    where, args = [], []
    if tenant_list is not None:
        where.append("tenant IN (%s)" % ",".join("?" * len(tenant_list)))
        args.extend(tenant_list)
    if site:
        where.append("site = ?")
        args.append(site)
    if switch_ip:
        where.append("switch_ip = ?")
        args.append(switch_ip)
    if vlan:
        where.append("vlan = ?")
        args.append(vlan)
    if q:
        where.append("(mac LIKE ? OR oui_vendor LIKE ? OR switch_name LIKE ? "
                     "OR interface LIKE ?)")
        args.extend(["%" + q + "%"] * 4)
    clause = (" WHERE " + " AND ".join(where)) if where else ""

    with _lock, _connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT mac, oui_vendor, vlan, switch_ip, switch_name, interface, "
            "port_channel, is_uplink, uplink_to, tenant, site, first_seen, "
            "last_seen, seen_count FROM mac_sightings" + clause, args).fetchall()]
        infra = {r["mac"] for r in c.execute(
            "SELECT DISTINCT mac FROM switch_if_macs").fetchall()}

    # Il valore grezzo non riconosce i Port-channel: fidarsene qui farebbe
    # passare per porta di accesso un'interfaccia aggregata verso un altro
    # switch, cioe' un punto di transito.
    reclassify_sightings(rows)
    rows = [r for r in rows if r["mac"] not in infra]
    if not rows:
        return empty

    macs = list(dict.fromkeys(r["mac"] for r in rows))
    arp: dict = {}
    CHUNK = 400                                   # < limite ~999 parametri SQLite
    with _lock, _connect() as c:
        for i in range(0, len(macs), CHUNK):
            batch = macs[i:i + CHUNK]
            sql = ("SELECT mac, ip, tenant FROM arp_entries WHERE mac IN (%s)"
                   % ",".join("?" * len(batch)))
            a = list(batch)
            if tenant_list is not None:
                sql += " AND tenant IN (%s)" % ",".join("?" * len(tenant_list))
                a.extend(tenant_list)
            for r in c.execute(sql, a).fetchall():
                arp.setdefault((r["mac"], r["tenant"] or ""), []).append(dict(r))

    assignments = inventory_manager.get_category_assignments()
    now = datetime.now(timezone.utc)
    groups: dict = {}
    for r in rows:
        groups.setdefault((r["mac"], r["tenant"] or ""), []).append(r)

    results = []
    for (mac, tenant), grp in groups.items():
        access = [s for s in grp if not s.get("is_uplink")]
        access.sort(key=lambda s: s.get("last_seen") or "", reverse=True)
        distinct = {(s["switch_ip"], (s.get("interface") or "").lower())
                    for s in access}
        best = access[0] if access else {}

        ips = sorted({b["ip"] for b in arp.get((mac, tenant), []) if b.get("ip")})
        first_seen = min(s["first_seen"] for s in grp)
        last_seen = max(s["last_seen"] for s in grp)
        info = ep_kb.classify_mac(mac) or {}

        flags = []
        if len(distinct) > 1:
            flags.append("AMBIGUOUS")
        if info.get("vendor_kind"):
            flags.append("VM")
        elif not ep_kb.is_stable_identity(mac):
            flags.append("RANDOM")
        if len(ips) > 1:
            flags.append("MULTI-IP")
        if not ips:
            flags.append("NO-IP")
        if not access:
            flags.append("TRANSIT-ONLY")
        age = _age_days(last_seen, now)
        born = _age_days(first_seen, now)
        if age is not None and age > stale_days:
            flags.append("STALE")
        if born is not None and born <= stale_days:
            flags.append("NEW")

        # Tipo del client: certo SOLO se assegnato a mano nella scheda
        # "Dispositivi e categorie". Mai ereditare il tipo del gateway.
        assigned = next((assignments[ip] for ip in ips if assignments.get(ip)), {})
        results.append({
            "mac": mac, "tenant": tenant,
            "oui_vendor": next((s["oui_vendor"] for s in grp if s.get("oui_vendor")), ""),
            "site": grp[0].get("site") or "",
            "ips": ips,
            "switch_ip": best.get("switch_ip", ""),
            "switch_name": best.get("switch_name", ""),
            "interface": best.get("interface", ""),
            "vlan": best.get("vlan", ""),
            "first_seen": first_seen, "last_seen": last_seen,
            "seen_count": sum(s.get("seen_count") or 0 for s in grp),
            "access_port_count": len(distinct),
            "client_type": assigned.get("category") or "client",
            "flags": flags,
        })

    results.sort(key=lambda e: e["last_seen"], reverse=True)
    total = len(results)
    counts = {
        "endpoints": total,
        "switches": len({e["switch_ip"] for e in results if e["switch_ip"]}),
        "vlans": len({e["vlan"] for e in results if e["vlan"]}),
        "stale": sum(1 for e in results if "STALE" in e["flags"]),
        "new": sum(1 for e in results if "NEW" in e["flags"]),
        "no_ip": sum(1 for e in results if "NO-IP" in e["flags"]),
        "random": sum(1 for e in results if "RANDOM" in e["flags"]),
    }
    cap = max(1, min(20000, limit))
    return {"results": results[:cap], "total": total,
            "truncated": total > cap, "counts": counts}
```

- [ ] **Step 4: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_endpoint_inventory -v`
Expected: PASS su tutte le classi `TestRollup`, `TestFlag`, `TestFiltriEScoping`.

- [ ] **Step 5: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add collectors/mac_history.py tests/test_endpoint_inventory.py
git commit -m "feat(mac): derive an endpoint inventory from the sightings already collected

One row per (MAC, tenant), built from mac_sightings with arp_entries joined
on the left, switch interface MACs excluded, and flags computed at read time
so a classification learned tomorrow improves rows collected yesterday.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 4: `port_occupancy()` — occupata, uplink, libera, o non lo so

**Files:**
- Modify: `collectors/mac_history.py` (dopo `endpoint_inventory()`)
- Test: `tests/test_endpoint_inventory.py` (classe nuova)

**Interfaces:**
- Consumes: `topology_uplinks() -> (uplink_map, known_switches)` dove `uplink_map[switch_ip] = {porta_normalizzata: etichetta_vicino}`; `core.core_engine._normalize_iface(name) -> str`; `_is_physical_iface()` da Task 3.
- Produces:
  ```python
  port_occupancy(switch_ip, tenants=None) -> dict
  # {"switch": str, "port_list_known": bool, "if_list_age_s": float|None,
  #  "ports": [{"interface", "state", "physical", "macs": [...], "uplink_to"}],
  #  "counts": {"total", "occupied", "uplink", "free"}}
  # state ∈ {"occupied", "uplink", "free"}
  ```

- [ ] **Step 1: Scrivi il test che fallisce**

In coda a `tests/test_endpoint_inventory.py`:

```python
class TestOccupazionePorte(_Base):
    """L'elenco interfacce viene da switch_if_macs, popolata a ogni scansione
    MAC da collect_interface_macs(). Quando manca, si dice che manca."""

    def setUp(self):
        super().setUp()
        self._porta_n = 0

    def _porta(self, interface, switch_ip="192.0.2.1"):
        """Una porta nell'elenco interfacce dello switch. Il MAC e' quello
        DELL'INTERFACCIA (infrastruttura): un contatore basta, purche' sia
        deterministico — un hash di stringa cambia a ogni processo."""
        self._porta_n += 1
        self._infra_mac(mac=f"aa:bb:cc:00:00:{self._porta_n:02d}",
                        switch_ip=switch_ip, interface=interface)

    def test_porta_occupata_e_porta_libera(self):
        self._porta("GigabitEthernet1/0/1")
        self._porta("GigabitEthernet1/0/2")
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/1")

        out = mac_history.port_occupancy("192.0.2.1")
        stati = {p["interface"]: p["state"] for p in out["ports"]}

        self.assertTrue(out["port_list_known"])
        self.assertEqual(stati["GigabitEthernet1/0/1"], "occupied")
        self.assertEqual(stati["GigabitEthernet1/0/2"], "free")

    def test_elenco_assente_non_e_zero_porte_libere(self):
        """Se la raccolta if_macs e' fallita — non e' fatale — rispondere
        'zero porte libere' manderebbe a cercare nel posto sbagliato."""
        self._sighting(switch_ip="192.0.2.7", interface="GigabitEthernet1/0/1")

        out = mac_history.port_occupancy("192.0.2.7")

        self.assertFalse(out["port_list_known"])
        self.assertEqual(out["ports"], [])

    def test_un_uplink_noto_alla_topologia_non_e_libero(self):
        """Una porta di trunk momentaneamente muta non e' una porta libera:
        proporla come tale manda a infilare un cavo in un uplink.

        La chiave della mappa e' il nome NORMALIZZATO da
        ``core_engine._normalize_iface()``, che sui nomi con le barre non fa
        altro che minuscolizzare: 'GigabitEthernet1/0/24' resta intero.
        Un patch annidato sullo stesso bersaglio ripristina il mock esterno
        all'uscita: non serve fermare quello di setUp.
        """
        self._porta("GigabitEthernet1/0/24")
        with patch("collectors.mac_history.topology_uplinks",
                   return_value=({"192.0.2.1": {"gigabitethernet1/0/24": "switch-02"}},
                                 {"192.0.2.1"})):
            out = mac_history.port_occupancy("192.0.2.1")

        porta = next(p for p in out["ports"]
                     if p["interface"] == "GigabitEthernet1/0/24")
        self.assertEqual(porta["state"], "uplink")
        self.assertEqual(porta["uplink_to"], "switch-02")

    def test_le_interfacce_non_fisiche_non_contano_come_libere(self):
        """Vlan10 resta visibile, ma non e' una porta in cui infilare un cavo."""
        self._porta("GigabitEthernet1/0/1")
        self._porta("Vlan10")

        out = mac_history.port_occupancy("192.0.2.1")
        vlan_port = next(p for p in out["ports"] if p["interface"] == "Vlan10")

        self.assertFalse(vlan_port["physical"])
        self.assertEqual(out["counts"]["free"], 1)      # solo la Gi, non la Vlan

    def test_scoping_per_tenant(self):
        self._porta("GigabitEthernet1/0/1")
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/1",
                       tenant="sede-b")

        out = mac_history.port_occupancy("192.0.2.1", tenants=["sede-a"])
        porta = next(p for p in out["ports"]
                     if p["interface"] == "GigabitEthernet1/0/1")

        self.assertEqual(porta["state"], "free", "il MAC di sede-b non e' visibile")
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_endpoint_inventory.TestOccupazionePorte -v`
Expected: FAIL — `AttributeError: ... has no attribute 'port_occupancy'`.

- [ ] **Step 3: Implementa**

In coda a `collectors/mac_history.py`:

```python
def port_occupancy(switch_ip: str, tenants=None) -> dict:
    """Stato di ogni porta di uno switch: occupata, uplink, o libera.

    L'elenco delle interfacce esiste gia': ``switch_if_macs`` viene popolata a
    ogni scansione MAC da ``collect_interface_macs()`` (``show interfaces``, o
    ``ietf-interfaces`` via NETCONF/RESTCONF). Quando quella raccolta e'
    fallita — non e' fatale, la lista resta vuota — lo si DICE con
    ``port_list_known: False`` invece di rispondere "zero porte libere": zero
    righe travestite da "nessun dato" sono peggio di un buco dichiarato.

    ``free`` significa "nessun MAC imparato", NON "nessun cavo": un
    dispositivo silenzioso legge come porta libera. Sta scritto nella UI.
    """
    from core.core_engine import _normalize_iface

    init_db()
    tenant_list = list(tenants) if tenants is not None else None
    unknown = {"switch": switch_ip, "port_list_known": False,
               "if_list_age_s": None, "ports": [],
               "counts": {"total": 0, "occupied": 0, "uplink": 0, "free": 0}}
    if tenant_list is not None and not tenant_list:
        return unknown

    with _lock, _connect() as c:
        ifaces = [dict(r) for r in c.execute(
            "SELECT interface, MAX(last_seen) AS last_seen FROM switch_if_macs "
            "WHERE switch_ip=? GROUP BY interface ORDER BY interface",
            (switch_ip,)).fetchall()]
        sql = ("SELECT mac, tenant, switch_ip, switch_name, interface, "
               "port_channel, vlan, is_uplink, last_seen FROM mac_sightings "
               "WHERE switch_ip=?")
        args = [switch_ip]
        if tenant_list is not None:
            sql += " AND tenant IN (%s)" % ",".join("?" * len(tenant_list))
            args.extend(tenant_list)
        sightings = [dict(r) for r in c.execute(sql, args).fetchall()]

    if not ifaces:
        return unknown

    reclassify_sightings(sightings)
    uplink_map, _known = topology_uplinks()
    ups = {k: v for k, v in (uplink_map.get(switch_ip) or {}).items()}

    by_port: dict = {}
    for s in sightings:
        by_port.setdefault(_normalize_iface(s.get("interface") or ""), []).append(s)

    ports, counts = [], {"total": 0, "occupied": 0, "uplink": 0, "free": 0}
    for row in ifaces:
        name = row["interface"]
        norm = _normalize_iface(name)
        physical = _is_physical_iface(name)
        neigh = ups.get(norm)
        seen = by_port.get(norm, [])
        access = [s for s in seen if not s.get("is_uplink")]
        if neigh or (seen and not access):
            state = "uplink"
        elif access:
            state = "occupied"
        else:
            state = "free"
        ports.append({"interface": name, "state": state, "physical": physical,
                      "uplink_to": neigh or "",
                      "macs": sorted({s["mac"] for s in access}),
                      "last_seen": row["last_seen"]})
        # Il conteggio riguarda le porte in cui si infila un cavo: una Vlan10
        # fra le "libere" sarebbe una porta che non esiste.
        if physical:
            counts["total"] += 1
            counts[state] += 1

    # Eta' dell'elenco interfacce: quanto e' vecchia la scansione MAC piu'
    # recente di QUESTO switch. None se il timestamp non e' interpretabile —
    # che non e' "aggiornato adesso".
    age_days = _age_days(max(r["last_seen"] for r in ifaces))
    return {"switch": switch_ip, "port_list_known": True,
            "if_list_age_s": None if age_days is None else age_days * 86400.0,
            "ports": ports, "counts": counts}
```

- [ ] **Step 4: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_endpoint_inventory -v`
Expected: PASS.

- [ ] **Step 5: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add collectors/mac_history.py tests/test_endpoint_inventory.py
git commit -m "feat(mac): report port occupancy from the interface list already collected

switch_if_macs holds every interface of a switch, refreshed on each MAC scan,
so occupied/uplink/free is derivable. A switch whose interface collection
failed reports port_list_known false rather than zero free ports.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 5: le due rotte

**Files:**
- Create: `routers/endpoint_inventory.py`
- Modify: `app_server.py:78` (import) e `:106` (registrazione), `tests/test_router_parity.py:58` (`ALLOWED_NEW_PREFIXES`)
- Test: `tests/test_endpoint_inventory.py` (classe nuova)

**Interfaces:**
- Consumes: `mac_history.endpoint_inventory(...)`, `mac_history.port_occupancy(...)` da Task 3-4; `routers.deps.get_current_user`, `user_group_scope`.
- Produces:
  ```
  GET /api/endpoints/list?tenant=&site=&switch=&vlan=&q=&stale_days=7&limit=2000
  GET /api/endpoints/ports?switch=<ip>
  ```

- [ ] **Step 1: Scrivi il test che fallisce**

In coda a `tests/test_endpoint_inventory.py`:

```python
class TestRotte(_Base):
    """Sola lettura: get_current_user basta, require_operator no."""

    def setUp(self):
        super().setUp()
        from routers import endpoint_inventory as ep_router
        self.router = ep_router

    def test_tenant_indicato_restringe(self):
        self._sighting(tenant="sede-a")
        self._sighting(tenant="sede-b", switch_ip="198.51.100.1")

        out = self.router.endpoints_list(tenant="sede-a",
                                         current_user={"sub": "a", "role": "admin"})

        self.assertEqual(out["total"], 1)

    def test_tenant_fuori_scope_e_403(self):
        from fastapi import HTTPException
        with patch("routers.endpoint_inventory.user_group_scope",
                   return_value={"sede-a"}):
            with self.assertRaises(HTTPException) as ctx:
                self.router.endpoints_list(tenant="sede-b",
                                           current_user={"sub": "v", "role": "viewer"})
        self.assertEqual(ctx.exception.status_code, 403)

    def test_lo_scope_dell_utente_e_applicato_senza_chiederlo(self):
        """Il filtro non e' un'opzione: senza parametro vale comunque il
        profilo dell'utente."""
        self._sighting(tenant="sede-a")
        self._sighting(tenant="sede-b", switch_ip="198.51.100.1")

        with patch("routers.endpoint_inventory.user_group_scope",
                   return_value={"sede-b"}):
            out = self.router.endpoints_list(current_user={"sub": "v", "role": "viewer"})

        self.assertEqual([r["tenant"] for r in out["results"]], ["sede-b"])

    def test_ports_richiede_lo_switch(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            self.router.endpoints_ports(switch="  ",
                                        current_user={"sub": "a", "role": "admin"})
        self.assertEqual(ctx.exception.status_code, 400)


class TestRotteRegistrate(unittest.TestCase):
    def test_le_rotte_sono_nell_app(self):
        import app_server
        paths = {r.path for r in app_server.app.routes}
        self.assertIn("/api/endpoints/list", paths)
        self.assertIn("/api/endpoints/ports", paths)
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_endpoint_inventory.TestRotte -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'routers.endpoint_inventory'`.

- [ ] **Step 3: Crea il router**

`routers/endpoint_inventory.py`:

```python
# -*- coding: utf-8 -*-
"""Router inventario endpoint: elenco dei client scoperti, e occupazione porte.

Sottile per scelta, come gli altri: qui stanno routing e scoping per tenant;
le due query stanno in ``collectors/mac_history.py``, che possiede il DB.

Il modulo si chiama ``endpoint_inventory`` e non ``endpoints`` perche' quel
nome e' gia' di ``observability/endpoints.py`` (classificatore di indirizzi):
due moduli omonimi con scopi diversi si confondono alla prima lettura.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status

from collectors import mac_history
from routers.deps import get_current_user, user_group_scope

router = APIRouter(tags=["Endpoint Inventory"])


def _scope(current_user, tenant: Optional[str]):
    """Scope effettivo. ``tenant`` RESTRINGE, non allarga: un tenant fuori dal
    profilo e' 403, non un silenzioso "vabbe', glielo mostro" — risponderebbe
    su una sede che l'utente non puo' vedere."""
    scope = user_group_scope(current_user)
    if not tenant or tenant == "all":
        return scope
    if scope is not None and tenant not in scope:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Tenant '{tenant}' non consentito.")
    return [tenant]


@router.get("/api/endpoints/list")
def endpoints_list(tenant: Optional[str] = None, site: Optional[str] = None,
                   switch: Optional[str] = None, vlan: Optional[str] = None,
                   q: Optional[str] = None, stale_days: int = 7,
                   limit: int = 2000,
                   current_user = Depends(get_current_user)):
    """Gli endpoint scoperti, uno per (MAC, tenant).

    Sola lettura sul dato gia' raccolto: non interroga nessun apparato, quindi
    basta ``get_current_user`` e non ``require_operator``.
    """
    return mac_history.endpoint_inventory(
        tenants=_scope(current_user, tenant), site=site or None,
        switch_ip=switch or None, vlan=vlan or None, q=(q or "").strip() or None,
        stale_days=max(1, min(3650, stale_days)), limit=limit)


@router.get("/api/endpoints/ports")
def endpoints_ports(switch: str, current_user = Depends(get_current_user)):
    """Stato delle porte di uno switch: occupata, uplink, libera."""
    if not switch or not switch.strip():
        raise HTTPException(status_code=400, detail="Parametro switch obbligatorio")
    return mac_history.port_occupancy(switch.strip(),
                                      tenants=user_group_scope(current_user))
```

- [ ] **Step 4: Registra il router**

In `app_server.py`, accanto agli altri import di router (dopo la riga 78):

```python
from routers import endpoint_inventory as _endpoint_inventory_router
```

e accanto alle altre registrazioni (dopo la riga 106):

```python
app.include_router(_endpoint_inventory_router.router)
```

- [ ] **Step 5: Aggiorna l'allowlist di parità**

In `tests/test_router_parity.py`, riga 58, aggiungi `"/api/endpoints"` in coda alla tupla `ALLOWED_NEW_PREFIXES`:

```python
    ALLOWED_NEW_PREFIXES = (..., "/api/fortigate/{ip}/sdwan", "/api/endpoints")
```

- [ ] **Step 6: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_endpoint_inventory tests.test_router_parity -v`
Expected: PASS. Se `TestFullParity` fallisce con "l'insieme dei percorsi è cambiato", aggiungi `/api/endpoints` anche a `TestFullParity.NEW_PREFIXES` — sono due allowlist indipendenti.

- [ ] **Step 7: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add routers/endpoint_inventory.py app_server.py tests/test_endpoint_inventory.py tests/test_router_parity.py
git commit -m "feat(api): expose the endpoint inventory and port occupancy as two read routes

Both read-only over data already collected, so get_current_user is enough.
The tenant parameter restricts the caller's scope and 403s outside it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 6: la tab — guscio, KPI, tabella

**Files:**
- Create: `static/js/endpoint-inventory.js`
- Modify: `templates/dashboard.html` (nav riga 171, sotto-tab righe 954-956 / 1093-1095 / 1196-1198, sezione nuova dopo la riga 1235, include script dopo la riga 3388), `static/js/i18n.js` (due dizionari)
- Test: `tests/test_endpoint_inventory.py` (classe grep)

**Interfaces:**
- Consumes: `GET /api/endpoints/list` da Task 5; `apiFetch`, `escapeHtml`, `jsStr`, `switchTab`, `currentLang`, `i18n` da `core.js`/`i18n.js`.
- Produces: `loadEndpointsTab()`, `endpointsSearch()`, `endpointsRender(data)`, variabile di modulo `_epRows` (le righe a schermo, che Task 7 esporta).

- [ ] **Step 1: Scrivi il test che fallisce**

In coda a `tests/test_endpoint_inventory.py`:

```python
class TestTabFrontend(unittest.TestCase):
    """Verifica grep-style: non c'e' un runner JS."""

    @classmethod
    def setUpClass(cls):
        from tests.test_helpers_frontend import frontend_source
        cls.src = frontend_source()

    def test_la_tab_esiste_ed_e_raggiungibile(self):
        self.assertIn('id="tab-endpoints"', self.src)
        self.assertIn("switchTab('tab-endpoints')", self.src)

    def test_e_la_quarta_sorella_del_gruppo_client(self):
        """Le altre tre sotto-tab devono puntarle, altrimenti si raggiunge
        solo da una direzione."""
        self.assertIn('data-tabs="tab-mac tab-clientmap tab-diagnosi tab-endpoints"',
                      self.src)

    def test_lo_script_e_incluso(self):
        self.assertIn('src="/static/js/endpoint-inventory.js"', self.src)

    def test_le_chiavi_i18n_esistono_in_entrambe_le_lingue(self):
        for key in ("tabEndpoints", "epKpiEndpoints", "epKpiStale", "epThMac",
                    "epExportCsv", "epPortsFreeWarn"):
            self.assertGreaterEqual(self.src.count(key + ":"), 2,
                                    f"chiave {key} assente in una delle due lingue")

    def test_le_icone_stanno_dentro_le_stringhe_i18n(self):
        """changeLanguage() sostituisce innerHTML in blocco: un'icona fuori
        dalla stringa sparisce al cambio lingua."""
        self.assertIn("tabEndpoints: '<i class=", self.src)
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_endpoint_inventory.TestTabFrontend -v`
Expected: FAIL su tutti.

- [ ] **Step 3: Chiavi i18n**

In `static/js/i18n.js`, nel dizionario **italiano** (accanto a `tabDiagnosi`, riga ~682):

```javascript
        tabEndpoints: '<i class="fa-solid fa-boxes-stacked"></i> Endpoint Inventory',
        titleEndpoints: "Endpoint scoperti",
        epKpiEndpoints: "Endpoint",
        epKpiSwitches: "Switch",
        epKpiVlans: "VLAN",
        epKpiStale: "Non visti di recente",
        epKpiNew: "Nuovi",
        epKpiNoIp: "Senza IP",
        epThMac: "MAC",
        epThVendor: "Vendor",
        epThTenant: "Tenant / sede",
        epThIps: "IP",
        epThWhere: "Switch / porta",
        epThVlan: "VLAN",
        epThFirst: "Primo avvistamento",
        epThLast: "Ultimo avvistamento",
        epThFlags: "Note",
        epFilterQ: "Cerca MAC, vendor, switch, porta",
        epFilterStale: "Soglia 'non visto' (giorni)",
        epExportCsv: '<i class="fa-solid fa-file-csv"></i> Esporta CSV',
        epExportJson: '<i class="fa-solid fa-file-code"></i> Esporta JSON',
        epExportPartial: "L'export contiene le righe caricate, non l'inventario intero.",
        epTruncated: "Mostrate {shown} di {total} — restringi i filtri per vederle tutte.",
        epEmpty: "Nessun endpoint. Avvia una MAC Scan per popolare lo storico.",
        epModeList: "Elenco",
        epModePorts: "Occupazione porte",
        epPortsPick: "Scegli uno switch",
        epPortsUnknown: "Elenco porte non disponibile per questo switch: la raccolta delle interfacce non e' riuscita. Non significa zero porte libere.",
        epPortsFreeWarn: "«Libera» significa nessun MAC imparato, non nessun cavo: un dispositivo silenzioso legge come porta libera.",
        epPortsAge: "Elenco interfacce aggiornato all'ultima scansione MAC di questo switch",
        epStateOccupied: "occupata",
        epStateUplink: "uplink",
        epStateFree: "libera",
```

E gli stessi identici nomi di chiave nel dizionario **inglese** (accanto a `tabDiagnosi`, riga ~1952):

```javascript
        tabEndpoints: '<i class="fa-solid fa-boxes-stacked"></i> Endpoint Inventory',
        titleEndpoints: "Discovered endpoints",
        epKpiEndpoints: "Endpoints",
        epKpiSwitches: "Switches",
        epKpiVlans: "VLANs",
        epKpiStale: "Not seen recently",
        epKpiNew: "New",
        epKpiNoIp: "Without IP",
        epThMac: "MAC",
        epThVendor: "Vendor",
        epThTenant: "Tenant / site",
        epThIps: "IPs",
        epThWhere: "Switch / port",
        epThVlan: "VLAN",
        epThFirst: "First seen",
        epThLast: "Last seen",
        epThFlags: "Notes",
        epFilterQ: "Search MAC, vendor, switch, port",
        epFilterStale: "'Not seen' threshold (days)",
        epExportCsv: '<i class="fa-solid fa-file-csv"></i> Export CSV',
        epExportJson: '<i class="fa-solid fa-file-code"></i> Export JSON',
        epExportPartial: "The export contains the loaded rows, not the whole inventory.",
        epTruncated: "Showing {shown} of {total} — narrow the filters to see them all.",
        epEmpty: "No endpoints. Run a MAC Scan to populate the history.",
        epModeList: "List",
        epModePorts: "Port occupancy",
        epPortsPick: "Pick a switch",
        epPortsUnknown: "Port list unavailable for this switch: the interface collection did not succeed. This does not mean zero free ports.",
        epPortsFreeWarn: "\"Free\" means no MAC learned, not no cable: a silent device reads as a free port.",
        epPortsAge: "Interface list as of this switch's last MAC scan",
        epStateOccupied: "occupied",
        epStateUplink: "uplink",
        epStateFree: "free",
```

- [ ] **Step 4: Nav e sotto-tab in `dashboard.html`**

Alla riga 171, aggiungi `tab-endpoints` all'attributo `data-tabs`:

```html
        <button class="nav-item" data-tabs="tab-mac tab-clientmap tab-diagnosi tab-endpoints" onclick="switchTab('tab-mac', this)">
```

In **tutte e tre** le barre di sotto-tab esistenti (righe ~954-956, ~1093-1095, ~1196-1198) aggiungi come quarto pulsante:

```html
        <button class="btn btn-secondary ti-subtab" onclick="switchTab('tab-endpoints'); loadEndpointsTab();" data-i18n="tabEndpoints"></button>
```

- [ ] **Step 5: La sezione della tab**

In `templates/dashboard.html`, subito dopo la chiusura di `tab-diagnosi` (riga 1235, prima del commento `<!-- TAB: Live Flows -->`):

```html
    <!-- TAB: Endpoint Inventory -->
    <div id="tab-endpoints" class="tab-content">
      <div class="subtab-bar" style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px;">
        <button class="btn btn-secondary ti-subtab" onclick="switchTab('tab-mac');" data-i18n="tabMacTracker"></button>
        <button class="btn btn-secondary ti-subtab" onclick="switchTab('tab-clientmap'); loadClientMapTab();" data-i18n="tabClientMap"></button>
        <button class="btn btn-secondary ti-subtab" onclick="switchTab('tab-diagnosi');" data-i18n="tabDiagnosi"></button>
        <button class="btn btn-secondary ti-subtab active" onclick="switchTab('tab-endpoints'); loadEndpointsTab();" data-i18n="tabEndpoints"></button>
      </div>
      <div id="epKpis" style="display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; margin-bottom:16px;"></div>
      <div class="panel" style="margin-bottom:16px;">
        <h3 style="font-size:15px; margin-bottom:12px;">
          <i class="fa-solid fa-boxes-stacked" style="color:var(--primary);"></i>
          <span data-i18n="titleEndpoints"></span>
        </h3>
        <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; align-items:end;">
          <div class="form-group" style="margin-bottom:0;">
            <label for="epFilterQ" data-i18n="epFilterQ"></label>
            <input id="epFilterQ" type="text" style="padding-left:12px; font-size:13px;"
                   onkeydown="if(event.key==='Enter')endpointsSearch();">
          </div>
          <div class="form-group" style="margin-bottom:0;">
            <label for="epFilterTenant" data-i18n="epThTenant"></label>
            <select id="epFilterTenant" style="padding:6px 12px; border-radius:8px; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:13px;"></select>
          </div>
          <div class="form-group" style="margin-bottom:0;">
            <label for="epFilterStale" data-i18n="epFilterStale"></label>
            <input id="epFilterStale" type="number" min="1" max="3650" value="7"
                   style="padding-left:12px; font-size:13px;">
          </div>
          <button class="btn btn-secondary" style="width:auto;" onclick="endpointsSearch()">
            <i class="fa-solid fa-magnifying-glass"></i>
          </button>
          <button class="btn btn-secondary" style="width:auto;" onclick="endpointsExport('csv')" data-i18n="epExportCsv"></button>
          <button class="btn btn-secondary" style="width:auto;" onclick="endpointsExport('json')" data-i18n="epExportJson"></button>
        </div>
      </div>
      <div id="epResults"></div>
    </div>
```

E dopo la riga 3388 (`<script src="/static/js/diagnosi.js"></script>`):

```html
  <script src="/static/js/endpoint-inventory.js"></script>
```

- [ ] **Step 6: Crea `static/js/endpoint-inventory.js`**

```javascript
// Inventario endpoint: elenco dei client scoperti, filtrabile ed esportabile.
// Ogni valore che arriva dagli apparati passa da escapeHtml(jsStr(x)).
//
// La vista e' DERIVATA: nessuna annotazione salvata, nessuno stato da tenere
// allineato a una rete che cambia da sola. Quello che si vede e' quello che
// le scansioni hanno raccolto, con l'eta' del dato sempre a schermo.

let _epRows = [];          // righe a schermo: sono queste che l'export porta via
let _epTruncated = false;

function loadEndpointsTab() {
    endpointsSearch();
}

async function endpointsSearch() {
    const host = document.getElementById('epResults');
    if (!host) return;
    const en = currentLang === 'en';
    const L = i18n[currentLang];

    const q = ((document.getElementById('epFilterQ') || {}).value || '').trim();
    const tenant = (document.getElementById('epFilterTenant') || {}).value || '';
    const staleDays = parseInt((document.getElementById('epFilterStale') || {}).value, 10) || 7;

    host.innerHTML = `<div class="panel" style="padding:26px; text-align:center; color:var(--text-muted); font-size:13px;">
        <i class="fa-solid fa-circle-notch fa-spin" style="margin-right:8px;"></i>${escapeHtml(en ? 'Loading…' : 'Caricamento…')}</div>`;

    const params = new URLSearchParams({ stale_days: String(staleDays) });
    if (q) params.set('q', q);
    if (tenant && tenant !== 'all') params.set('tenant', tenant);

    const res = await apiFetch('/api/endpoints/list?' + params.toString());
    if (!res || !res.ok) {
        host.innerHTML = `<div class="panel" style="padding:22px; text-align:center; color:var(--danger); font-size:13px;">${escapeHtml(en ? 'Could not load the inventory.' : 'Inventario non caricabile.')}</div>`;
        return;
    }
    endpointsRender(await res.json());
}

function endpointsRender(d) {
    const L = i18n[currentLang];
    _epRows = d.results || [];
    _epTruncated = !!d.truncated;

    const kpis = document.getElementById('epKpis');
    if (kpis) {
        const c = d.counts || {};
        const tile = (label, value, color) => `<div class="panel" style="padding:12px 14px;">
            <div style="font-size:22px; font-weight:800; color:${color || 'var(--text)'};">${escapeHtml(String(value ?? 0))}</div>
            <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; font-weight:700;">${escapeHtml(label)}</div>
        </div>`;
        kpis.innerHTML =
            tile(L.epKpiEndpoints, c.endpoints, 'var(--primary)') +
            tile(L.epKpiSwitches, c.switches) +
            tile(L.epKpiVlans, c.vlans) +
            tile(L.epKpiStale, c.stale, c.stale ? 'var(--warning)' : undefined) +
            tile(L.epKpiNew, c.new) +
            tile(L.epKpiNoIp, c.no_ip);
    }

    const host = document.getElementById('epResults');
    if (!host) return;
    if (!_epRows.length) {
        host.innerHTML = `<div class="panel" style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;">
            <i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.epEmpty)}</div>`;
        return;
    }

    const banner = _epTruncated
        ? `<div style="padding:10px 12px; margin-bottom:10px; border-radius:8px; background:rgba(255,184,77,0.12); border:1px solid rgba(255,184,77,0.35); color:var(--warning); font-size:12px;">
            <i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${escapeHtml(
                L.epTruncated.replace('{shown}', String(_epRows.length)).replace('{total}', String(d.total)))}</div>`
        : '';

    const body = _epRows.map(r => `<tr style="cursor:pointer;" onclick="endpointsDiagnose('${escapeHtml(jsStr(r.mac))}','${escapeHtml(jsStr(r.tenant || ''))}')">
        <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(jsStr(r.mac))}</td>
        <td style="font-size:12px;">${escapeHtml(jsStr(r.oui_vendor || '—'))}</td>
        <td style="font-size:12px;">${escapeHtml(jsStr(r.tenant || '—'))} <span style="color:var(--text-muted);">/ ${escapeHtml(jsStr(r.site || '—'))}</span></td>
        <td style="font-family:var(--font-code); font-size:11px;">${escapeHtml(jsStr((r.ips || []).join(', ') || '—'))}</td>
        <td style="font-size:12px;">${escapeHtml(jsStr(r.switch_name || r.switch_ip || '—'))} <span style="color:var(--text-muted);">${escapeHtml(jsStr(r.interface || ''))}</span></td>
        <td style="font-size:12px;">${escapeHtml(jsStr(r.vlan || '—'))}</td>
        <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(jsStr(_epTime(r.first_seen)))}</td>
        <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(jsStr(_epTime(r.last_seen)))}</td>
        <td>${(r.flags || []).map(_epFlag).join(' ')}</td>
    </tr>`).join('');

    host.innerHTML = `${banner}
        <div class="panel" style="padding:0;">
          <div class="table-container">
            <table>
              <thead><tr>
                <th>${escapeHtml(L.epThMac)}</th><th>${escapeHtml(L.epThVendor)}</th>
                <th>${escapeHtml(L.epThTenant)}</th><th>${escapeHtml(L.epThIps)}</th>
                <th>${escapeHtml(L.epThWhere)}</th><th>${escapeHtml(L.epThVlan)}</th>
                <th>${escapeHtml(L.epThFirst)}</th><th>${escapeHtml(L.epThLast)}</th>
                <th>${escapeHtml(L.epThFlags)}</th>
              </tr></thead>
              <tbody>${body}</tbody>
            </table>
          </div>
        </div>`;
}

// I flag sono derivati in lettura e dicono una cosa sola ciascuno: nessuno
// di loro e' un giudizio, tutti sono un fatto sul dato raccolto.
const _EP_FLAG_COLOR = {
    'AMBIGUOUS': 'var(--warning)', 'STALE': 'var(--warning)',
    'TRANSIT-ONLY': 'var(--warning)', 'RANDOM': 'var(--text-muted)',
    'NO-IP': 'var(--text-muted)', 'VM': 'var(--primary)',
    'MULTI-IP': 'var(--primary)', 'NEW': 'var(--success)',
};

function _epFlag(f) {
    const color = _EP_FLAG_COLOR[f] || 'var(--text-muted)';
    return `<span style="font-size:10px; color:${color}; border:1px solid ${color}; border-radius:4px; padding:0 4px; white-space:nowrap;">${escapeHtml(jsStr(f))}</span>`;
}

function _epTime(iso) {
    return String(iso || '').replace('T', ' ').slice(0, 16) || '—';
}
```

- [ ] **Step 7: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_endpoint_inventory.TestTabFrontend -v`
Expected: PASS.

- [ ] **Step 8: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add static/js/endpoint-inventory.js static/js/i18n.js templates/dashboard.html tests/test_endpoint_inventory.py
git commit -m "feat(ui): add the Endpoint Inventory tab with KPIs, filters and a flag column

Fourth sibling of MAC Tracker / Client Map / Client Diagnosis. Flags are
derived at read time and each states one fact about the collected data.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 7: export CSV/JSON e click di riga verso la diagnosi

**Files:**
- Modify: `static/js/endpoint-inventory.js`
- Test: `tests/test_endpoint_inventory.py` (classe grep)

**Interfaces:**
- Consumes: `_epRows` e `_epTruncated` da Task 6; `switchTab` da `core.js`; `_diagClient`/`_diagTenant`/`runDiagnosi` da `diagnosi.js`.
- Produces: `endpointsExport(format)`, `endpointsDiagnose(mac, tenant)`.

**Punto di integrazione con la Parte B:** la riga conosce già il proprio tenant (la chiave è (MAC, tenant)), quindi lo passa e la diagnosi **non entra mai** nello stato `ambiguous`. La domanda si pone a chi digita un indirizzo a mano, non a chi arriva da una riga che la sede ce l'ha scritta sopra.

- [ ] **Step 1: Scrivi il test che fallisce**

In coda alla classe `TestTabFrontend` di `tests/test_endpoint_inventory.py`:

```python
    def test_l_export_e_lato_client(self):
        """Stesso schema di topology.js: nessuna rotta di export, nessun
        secondo formattatore che col tempo diverge dall'ordine di colonne."""
        self.assertIn("function endpointsExport(", self.src)
        self.assertIn("new Blob(", self.src)
        self.assertNotIn("/api/endpoints/export", self.src)

    def test_l_export_avverte_quando_le_righe_sono_tagliate(self):
        """Esportare 2000 righe di 4711 senza dirlo consegna un inventario
        parziale spacciato per intero."""
        self.assertIn("epExportPartial", self.src)

    def test_il_click_di_riga_passa_anche_il_tenant(self):
        """La riga sa gia' la sede: passarla evita alla diagnosi di dover
        chiedere quello che qui e' gia' noto."""
        self.assertIn("function endpointsDiagnose(mac, tenant)", self.src)
        self.assertIn("_diagTenant = tenant", self.src)

    def test_nessun_secondo_renderer_del_referto(self):
        """Il referto si rende in un posto solo: due copie sarebbero due
        copie da tenere allineate."""
        self.assertEqual(self.src.count("function renderDiagnosi("), 1)
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_endpoint_inventory.TestTabFrontend -v`
Expected: FAIL sui quattro nuovi.

- [ ] **Step 3: Implementa**

In coda a `static/js/endpoint-inventory.js`:

```javascript
// Export lato client, come exportCategoriesCsv() in topology.js: il file si
// costruisce da cio' che la tabella mostra. Una rotta di export sarebbe un
// secondo formattatore, e i due ordini di colonne divergerebbero.
const _EP_COLS = ['mac', 'oui_vendor', 'tenant', 'site', 'ips', 'switch_ip',
                  'switch_name', 'interface', 'vlan', 'client_type',
                  'first_seen', 'last_seen', 'seen_count', 'access_port_count',
                  'flags'];

function endpointsExport(format) {
    const L = i18n[currentLang];
    if (!_epRows.length) return;
    // Se l'elenco e' tagliato lo si dice PRIMA di scaricare: un inventario
    // parziale spacciato per intero e' peggio di un export rifiutato.
    if (_epTruncated && !confirm(L.epExportPartial)) return;

    const stamp = new Date().toISOString().slice(0, 10);
    let blob, name;
    if (format === 'json') {
        blob = new Blob([JSON.stringify(_epRows, null, 2)], { type: 'application/json' });
        name = `sentinelnet-endpoints-${stamp}.json`;
    } else {
        const cell = v => {
            const s = Array.isArray(v) ? v.join(' ') : (v === null || v === undefined ? '' : String(v));
            return /[",;\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
        };
        const lines = [_EP_COLS.join(',')];
        _epRows.forEach(r => lines.push(_EP_COLS.map(k => cell(r[k])).join(',')));
        // BOM: senza, Excel legge gli accenti come mojibake.
        blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
        name = `sentinelnet-endpoints-${stamp}.csv`;
    }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
}

// La riga conosce gia' il proprio tenant — la chiave e' (MAC, tenant) — quindi
// lo passa alla diagnosi, che percio' non deve chiedere quale sede. La domanda
// resta per chi digita un indirizzo a mano.
function endpointsDiagnose(mac, tenant) {
    const input = document.getElementById('diagClientInput');
    if (input) input.value = mac;
    _diagClient = mac;
    _diagTenant = tenant || null;
    switchTab('tab-diagnosi');
    runDiagnosi();
}
```

> **Attenzione:** `runDiagnosi()` alla riga 39 di `diagnosi.js` azzera `_diagTenant` quando il client cambia (`if (_diagClient !== client.trim()) _diagTenant = null;`). Impostando **sia** `_diagClient` sia il campo di input prima di chiamarla, il confronto è già vero e il tenant sopravvive. Verificalo con il test dello Step 4: se il tenant venisse azzerato, la diagnosi tornerebbe a chiedere la sede pur arrivando da una riga che la conosce.

- [ ] **Step 4: Aggiungi il test di regressione sul tenant che sopravvive**

In `tests/test_endpoint_inventory.py`, nella classe `TestTabFrontend`:

```python
    def test_il_client_e_impostato_prima_di_lanciare_la_diagnosi(self):
        """runDiagnosi() azzera _diagTenant quando il client cambia: se
        endpointsDiagnose non impostasse _diagClient prima, il tenant appena
        passato verrebbe buttato e la diagnosi tornerebbe a chiedere la sede."""
        start = self.src.index("function endpointsDiagnose(mac, tenant)")
        body = self.src[start:start + 600]
        self.assertLess(body.index("_diagClient = mac"), body.index("runDiagnosi()"))
```

- [ ] **Step 5: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_endpoint_inventory -v`
Expected: PASS.

- [ ] **Step 6: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add static/js/endpoint-inventory.js tests/test_endpoint_inventory.py
git commit -m "feat(ui): export the endpoint list and hand a row to the diagnosis tab

CSV and JSON built in the browser from the rows on screen, warning first
when the list is truncated. A row already knows its tenant, so it passes it
and the diagnosis never has to ask which site.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 8: modalità occupazione porte

**Files:**
- Modify: `static/js/endpoint-inventory.js`, `templates/dashboard.html` (interruttore di modalità nella sezione `tab-endpoints`)
- Test: `tests/test_endpoint_inventory.py` (classe grep)

**Interfaces:**
- Consumes: `GET /api/endpoints/ports?switch=<ip>` da Task 5.
- Produces: `endpointsMode(mode)`, `endpointsPorts()`, `endpointsPortsRender(data)`.

- [ ] **Step 1: Scrivi il test che fallisce**

In `tests/test_endpoint_inventory.py`, classe `TestTabFrontend`:

```python
    def test_le_avvertenze_sulle_porte_sono_a_schermo(self):
        """Le quattro avvertenze della spec vivono nella UI, non nei commenti:
        chi legge sta per andare a infilare un cavo."""
        self.assertIn("epPortsFreeWarn", self.src)      # libera != nessun cavo
        self.assertIn("epPortsUnknown", self.src)       # elenco assente != 0 libere
        self.assertIn("epPortsAge", self.src)           # eta' dell'elenco

    def test_elenco_porte_assente_non_mostra_zero_libere(self):
        """Il ramo dell'elenco mancante deve uscire PRIMA di qualunque
        conteggio, altrimenti mostrerebbe 0 libere su 0 porte."""
        start = self.src.index("function endpointsPortsRender(")
        body = self.src[start:start + 900]
        self.assertLess(body.index("port_list_known"), body.index("counts"))

    def test_le_porte_non_fisiche_sono_visibili_ma_marcate(self):
        self.assertIn("p.physical", self.src)
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_endpoint_inventory.TestTabFrontend -v`
Expected: FAIL sui tre nuovi.

- [ ] **Step 3: Interruttore di modalità in `dashboard.html`**

Nella sezione `tab-endpoints`, subito dopo la `subtab-bar` e prima di `<div id="epKpis">`:

```html
      <div style="display:flex; gap:8px; margin-bottom:12px; align-items:center; flex-wrap:wrap;">
        <button id="epModeListBtn" class="btn btn-secondary btn-small" style="width:auto; margin:0; border-color:var(--primary); color:var(--primary);"
                onclick="endpointsMode('list')" data-i18n="epModeList"></button>
        <button id="epModePortsBtn" class="btn btn-secondary btn-small" style="width:auto; margin:0;"
                onclick="endpointsMode('ports')" data-i18n="epModePorts"></button>
        <select id="epPortsSwitch" style="display:none; padding:6px 12px; border-radius:8px; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:13px;"
                onchange="endpointsPorts()"></select>
      </div>
```

- [ ] **Step 4: Implementa in `static/js/endpoint-inventory.js`**

```javascript
// Seconda modalita' della stessa tab. L'elenco delle interfacce arriva da
// switch_if_macs, popolata a ogni scansione MAC: e' fresco quanto l'ultima
// scansione di QUELLO switch, e la sua eta' si mostra sempre.
let _epMode = 'list';

function endpointsMode(mode) {
    _epMode = mode;
    const listBtn = document.getElementById('epModeListBtn');
    const portsBtn = document.getElementById('epModePortsBtn');
    const picker = document.getElementById('epPortsSwitch');
    const active = 'border-color:var(--primary); color:var(--primary);';
    if (listBtn) listBtn.style.cssText = 'width:auto; margin:0;' + (mode === 'list' ? active : '');
    if (portsBtn) portsBtn.style.cssText = 'width:auto; margin:0;' + (mode === 'ports' ? active : '');
    if (picker) picker.style.display = mode === 'ports' ? '' : 'none';

    if (mode === 'list') { endpointsSearch(); return; }
    // Gli switch li conosce gia' l'elenco caricato: nessuna chiamata in piu'.
    if (picker) {
        const seen = {};
        _epRows.forEach(r => { if (r.switch_ip) seen[r.switch_ip] = r.switch_name || r.switch_ip; });
        picker.innerHTML = Object.keys(seen).sort().map(ip =>
            `<option value="${escapeHtml(jsStr(ip))}">${escapeHtml(jsStr(seen[ip]))} — ${escapeHtml(jsStr(ip))}</option>`).join('');
    }
    endpointsPorts();
}

async function endpointsPorts() {
    const host = document.getElementById('epResults');
    const picker = document.getElementById('epPortsSwitch');
    const L = i18n[currentLang];
    if (!host) return;
    const sw = picker ? picker.value : '';
    if (!sw) {
        host.innerHTML = `<div class="panel" style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;">${escapeHtml(L.epPortsPick)}</div>`;
        return;
    }
    const res = await apiFetch('/api/endpoints/ports?switch=' + encodeURIComponent(sw));
    if (!res || !res.ok) return;
    endpointsPortsRender(await res.json());
}

function endpointsPortsRender(d) {
    const host = document.getElementById('epResults');
    const L = i18n[currentLang];
    if (!host) return;

    // Elenco assente: si DICE, e si esce prima di qualunque conteggio. "0
    // porte libere su 0 porte" e' un'informazione falsa travestita da dato.
    if (!d.port_list_known) {
        host.innerHTML = `<div class="panel" style="padding:22px; font-size:13px; color:var(--warning);">
            <i class="fa-solid fa-triangle-exclamation" style="margin-right:8px;"></i>${escapeHtml(L.epPortsUnknown)}</div>`;
        return;
    }

    const c = d.counts || {};
    const ageDays = d.if_list_age_s === null || d.if_list_age_s === undefined
        ? null : Math.round(d.if_list_age_s / 86400);
    const stateColor = { occupied: 'var(--success)', uplink: 'var(--warning)', free: 'var(--text-muted)' };
    const stateLabel = { occupied: L.epStateOccupied, uplink: L.epStateUplink, free: L.epStateFree };

    const rows = (d.ports || []).map(p => `<tr>
        <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(jsStr(p.interface))}${
            p.physical ? '' : ' <span style="font-size:10px; color:var(--text-muted); border:1px solid var(--border); border-radius:4px; padding:0 4px;">virt</span>'}</td>
        <td><span style="font-size:10px; color:${stateColor[p.state]}; border:1px solid ${stateColor[p.state]}; border-radius:4px; padding:1px 5px;">${escapeHtml(jsStr(stateLabel[p.state] || p.state))}</span></td>
        <td style="font-family:var(--font-code); font-size:11px;">${escapeHtml(jsStr((p.macs || []).join(', ') || (p.uplink_to ? '→ ' + p.uplink_to : '—')))}</td>
    </tr>`).join('');

    host.innerHTML = `
        <div style="padding:10px 12px; margin-bottom:10px; border-radius:8px; background:rgba(255,184,77,0.12); border:1px solid rgba(255,184,77,0.35); color:var(--warning); font-size:12px;">
            <i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.epPortsFreeWarn)}
            ${ageDays === null ? '' : `<div style="margin-top:4px; color:var(--text-muted);">${escapeHtml(L.epPortsAge)} — ${escapeHtml(String(ageDays))}g</div>`}
        </div>
        <div class="panel" style="padding:12px 14px; margin-bottom:10px; font-size:13px;">
            <b>${escapeHtml(String(c.free ?? 0))}</b> ${escapeHtml(L.epStateFree)} ·
            <b>${escapeHtml(String(c.occupied ?? 0))}</b> ${escapeHtml(L.epStateOccupied)} ·
            <b>${escapeHtml(String(c.uplink ?? 0))}</b> ${escapeHtml(L.epStateUplink)}
            <span style="color:var(--text-muted);">/ ${escapeHtml(String(c.total ?? 0))}</span>
        </div>
        <div class="panel" style="padding:0;"><div class="table-container"><table>
            <thead><tr><th>${escapeHtml(L.epThWhere)}</th><th></th><th>${escapeHtml(L.epThMac)}</th></tr></thead>
            <tbody>${rows}</tbody>
        </table></div></div>`;
}
```

- [ ] **Step 5: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_endpoint_inventory -v`
Expected: PASS.

- [ ] **Step 6: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add static/js/endpoint-inventory.js templates/dashboard.html tests/test_endpoint_inventory.py
git commit -m "feat(ui): add the port occupancy view to the Endpoint Inventory tab

States the four caveats on screen: free means no MAC learned rather than no
cable, the interface list is only as fresh as that switch's last MAC scan,
a switch without a list says so instead of reporting zero free ports, and
non-physical interfaces stay visible but out of the free count.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 9: build dell'eseguibile

**Files:** nessuno modificato — è la verifica finale.

- [ ] **Step 1: Ricostruisci l'eseguibile**

```sh
uv run pyinstaller SentinelNet.spec
```

Expected: build completata senza errori.

> **Nota nota:** `SentinelNet.spec:7` impacchetta `('data','data')`, quindi la build non è deterministica (i sidecar `-wal`/`-shm` di SQLite compaiono e spariscono, e una build è già fallita così) e il binario distribuibile contiene un DB con dati reali. Se la build fallisce per un file sparito, rilanciala. Il problema è già registrato come lavoro a parte, non risolverlo qui.

---

## Self-Review

**Copertura della spec:**

| Sezione spec | Task |
|---|---|
| A.1 cosa conta come endpoint | 3 (`TestRollup`) |
| A.2 colonne | 3 + 6 |
| A.3 flag | 3 (`TestFlag`) |
| A.4 occupazione porte + 4 avvertenze | 4 (backend) + 8 (avvertenze a schermo) |
| A.5 API | 5 |
| A.6 frontend, i18n, escaping, un solo renderer | 6 + 7 |
| A.7 test | 3, 4, 5, 6, 7, 8 |
| B.1-B.2 stato `ambiguous` | 1 |
| B.3 frontend | 2 |
| B.4 test | 1 + 2 |
| B.5 lacuna port bounce | **fuori ambito dichiarato** — nessun task, resta scritta nella spec |
| C (già fatta) | commit `bdc8d5f` |

**Nota sul flag `RANDOM`:** nella spec §A.3 le due righe `RANDOM` e `VM` sono indipendenti; nell'implementazione di Task 3 sono in `if/elif`, perché `is_stable_identity()` è già vera per gli OUI di virtualizzazione — una VM non è un MAC randomizzato, e marcarla come tale direbbe il falso. Il test `test_vm_oui_di_virtualizzazione` fissa questo comportamento.

**Nota sull'ordine dei task:** 1-2 (Parte B) prima di 3-8 (Parte A) perché Task 7 vi si aggancia — la riga di inventario passa il tenant proprio per non far scattare lo stato `ambiguous`. Invertire l'ordine renderebbe il test di Task 7 verde per il motivo sbagliato.
