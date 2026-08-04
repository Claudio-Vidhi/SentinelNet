# Azioni di riga in Endpoint Inventory + SNMP gerarchico — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dare all'Endpoint Inventory una colonna di azioni esplicite (diagnosi, localizza, configurazione porta), e rendere la community SNMP ereditabile dal tenant con override per apparato.

**Architecture:** La colonna azioni riusa funzioni globali che esistono già (`endpointsDiagnose`, `macLocate`, `showPortConfig`) — nessuna logica nuova, solo raggiungibilità. Il default SNMP di tenant vive in uno store separato cifrato (`data/tenant_snmp.json`, gemello di `identities.json`), MAI in `groups.json`; la risoluzione della community effettiva sta in **una** funzione che tutti i lettori attraversano.

**Tech Stack:** Python 3.12 + FastAPI + JSON store cifrato Fernet (`security/crypto_vault.py`), frontend vanilla JS senza build step, test `unittest`.

## Global Constraints

- **Nessun dato reale nel repo.** Indirizzi RFC 5737 (`192.0.2.x`, `198.51.100.x`), nomi segnaposto (`switch-01`, `sede-a`), community di esempio (`esempio-community`). Mai un valore del laboratorio. Vedi `CLAUDE.md` §"Protect real data".
- **Una community è un segreto.** Non esce mai da un'API di lettura, nemmeno cifrata — stessa regola già scritta in `routers/inventory.py:84-86` e in `security/identity_manager.py`. Alla UI serve sapere SE è configurata, non quale sia.
- **Lingua:** codice, commenti, docstring e stringhe di test in italiano.
- **Prima di ogni commit**, eseguiti davvero e con l'output letto:
  ```sh
  uv run pyrefly check                          # 0 errors
  uv run python -m unittest discover -s tests   # tutti verdi (~90s, in FOREGROUND)
  node --check static/js/<file toccato>.js      # se si tocca JS
  graphify update .                             # dopo modifiche al codice
  ```
  Mai dichiarare verde un controllo che non è stato eseguito.
- **Escaping frontend:** ogni valore che arriva dagli apparati passa da `escapeHtml(jsStr(x))`. Le icone Font Awesome degli elementi tradotti stanno DENTRO la stringa i18n. Ogni chiave nuova va in ENTRAMBI i dizionari di `static/js/i18n.js`.
- **Due allowlist di parità sui percorsi, più una sugli schemi** in `tests/test_router_parity.py`: `TestRouterParity.ALLOWED_NEW_PREFIXES` (riga ~58), `TestFullParity.NEW_PREFIXES` (riga ~146) e — per gli schemi pydantic nuovi — `TestFullParity.NEW_SCHEMAS` (riga ~151). Una rotta nuova può passare la prima e fallire la seconda; uno schema nuovo fallisce il confronto degli schemi se non sta nella terza. Mai indebolire un'asserzione, mai rigenerare uno snapshot golden.
- **Test grep-style:** nessun runner JS. Si usa `frontend_source()` da `tests/test_helpers_frontend.py`. Per contare i chiamanti di una funzione serve il FILE singolo, non la sorgente concatenata. In `tests/test_endpoint_inventory.py` esiste già `TestTabFrontend._fn(signature)`, che ritaglia il corpo di una funzione fino alla successiva: **usalo**, non fette a lunghezza fissa.

## Decisioni prese con l'utente

- **Azioni di riga**: non un solo pulsante ma un piccolo insieme — diagnosi, localizza, configurazione porta.
- **Community vuota = eredita.** Un apparato senza community usa quella del tenant. Per escluderne uno c'è un flag esplicito `SNMP Disabled`: "non impostata" e "spenta di proposito" smettono di essere lo stesso valore. Oggi coincidono, ed è la ragione per cui serve il flag: senza, attivare un default di tenant comincerebbe a interrogare apparati che erano volutamente fuori.

---

## File Structure

| File | Responsabilità | Stato |
|---|---|---|
| `static/js/endpoint-inventory.js` | colonna azioni nella tabella | modifica |
| `static/js/i18n.js` | chiavi IT + EN delle azioni e dell'SNMP di tenant | modifica |
| `security/snmp_defaults.py` | store cifrato dei default per tenant + risoluzione della community effettiva | **nuovo** |
| `services/inventory_manager.py` | colonna `SNMP Disabled` in hosts.csv e in `add_or_update_device` | modifica |
| `observability/ingesters/snmp_poller.py` | `_snmp_devices()` passa dalla risoluzione condivisa; `poll_once()` interroga in parallelo con un tetto | modifica |
| `routers/inventory.py` | campo `snmp_disabled` nello schema, `snmp_inherited` in lettura | modifica |
| `routers/settings.py` | due rotte per il default di tenant | modifica |
| `templates/dashboard.html` | colonna azioni, colonna SNMP nella tabella tenant, checkbox nel modale device | modifica |
| `static/js/devices.js` | riga tenant con stato SNMP, checkbox opt-out nel modale | modifica |
| `static/js/core.js` | `loadSnmpDefaults()` chiamata in `appInit()` dopo `renderGroupsTable()` | modifica |
| `services/site_agent.py` | intestazione di ripiego di `_agent_get_inventory` con la colonna nuova | modifica |
| `scripts/vm_agent_test_helper.py` | `CSV_HEADERS` sincronizzata con le colonne canoniche | modifica |
| `docs/remote-sites.md` | schema canonico: tredici colonne, non dodici | modifica |
| `tests/test_snmp_defaults.py` | store, precedenza, opt-out, scoping | **nuovo** |
| `tests/test_endpoint_inventory.py` | grep della colonna azioni | modifica |
| `tests/test_router_parity.py` | rotta nuova nelle DUE allowlist dei percorsi + `SnmpDefaultSchema` in `TestFullParity.NEW_SCHEMAS` | modifica |
| `tests/test_snmp_poller.py` | `TestDeviceSelection` esistente resta verde sulla nuova `_snmp_devices()`; classe nuova per la concorrenza | modifica |
| `tests/test_remote_site.py` | il giro dell'inventario di sede regge la colonna nuova | verifica |

**Perché uno store separato e non `groups.json`.** `routers/inventory.py:79` restituisce al browser il dizionario di ogni gruppo **per intero** (`groups = {g: v for g, v in groups.items() if g in scope}`). Mettere lì un segreto lo spedirebbe a ogni utente, e la protezione dipenderebbe dal fatto che ogni futuro serializzatore di gruppi si ricordi di ripulirlo. Un file a parte rende la fuga strutturalmente impossibile, ed è il precedente che il progetto ha già scelto per le identità.

---

## Task 1: colonna azioni in Endpoint Inventory

**Files:**
- Modify: `static/js/endpoint-inventory.js` (riga tabella e intestazione dentro `endpointsRender`), `static/js/i18n.js`
- Test: `tests/test_endpoint_inventory.py`

**Interfaces:**
- Consumes: `endpointsDiagnose(mac, tenant)` (stesso file); `macLocate(mac, tenant)` da `static/js/client-map.js:639`; `showPortConfig(switchIp, port, switchName)` da `static/js/core.js:694`. Tutte globali: gli script condividono uno scope solo.
- Produces: nessuna funzione nuova. Solo una colonna.

**Nota sul click di riga.** La riga resta cliccabile: toglierlo non è stato chiesto. I tre pulsanti devono quindi chiamare `event.stopPropagation()`, altrimenti il click sul pulsante fa partire ANCHE la diagnosi della riga. **Aspetto dichiarato:** con la riga cliccabile non si può selezionare col mouse un MAC per copiarlo — il click naviga. Se dà fastidio, la correzione è togliere l'`onclick` dal `<tr>` e lasciare le azioni ai pulsanti: una riga.

- [ ] **Step 1: Scrivi il test che fallisce**

Nella classe `TestTabFrontend` di `tests/test_endpoint_inventory.py`:

```python
    def test_la_riga_ha_le_azioni_esplicite(self):
        """Il click sulla riga diagnosticava gia', ma non lo sapeva nessuno:
        niente lo diceva. Le tre azioni sono ora visibili come pulsanti."""
        body = self._fn("function endpointsRender(d)")
        self.assertIn("endpointsDiagnose(", body)
        self.assertIn("macLocate(", body)
        self.assertIn("showPortConfig(", body)

    def test_i_pulsanti_non_fanno_partire_anche_il_click_di_riga(self):
        """Senza stopPropagation il pulsante lancia la sua azione E la
        diagnosi della riga: due schermate per un click. La chiamata sta
        UNA volta nell'helper `act`, comune ai tre pulsanti.

        Si asserisce sulle TRE icone distintive e non su un conteggio di
        ``act(``: quel token di tre lettere lo produrrebbe anche un futuro
        ``compact(`` o la parola dentro un commento, e su questo ramo i
        conteggi di sottostringhe generiche hanno gia' rotto due test.
        """
        body = self._fn("function endpointsRender(d)")
        self.assertIn("event.stopPropagation()", body)
        for icon in ("fa-stethoscope", "fa-magnifying-glass-location",
                     "fa-file-lines"):
            self.assertIn(icon, body)

    def test_la_configurazione_porta_si_offre_solo_se_c_e_una_porta(self):
        """Un endpoint TRANSIT-ONLY non ha switch ne' interfaccia: il
        pulsante aprirebbe la configurazione di un'interfaccia vuota."""
        body = self._fn("function endpointsRender(d)")
        self.assertIn("r.switch_ip && r.interface", body)

    def test_le_nuove_chiavi_i18n_esistono_in_entrambe_le_lingue(self):
        """Stessa convenzione del test analogo gia' in questa classe: una
        chiave presente in un solo dizionario darebbe un titolo vuoto
        nell'altra lingua."""
        for key in ("epThActions", "epActDiagnose", "epActLocate",
                    "epActPortCfg"):
            self.assertGreaterEqual(self.src.count(key + ":"), 2,
                                    f"chiave {key} assente in una delle lingue")
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_endpoint_inventory.TestTabFrontend -v`
Expected: FAIL sui quattro nuovi (i test esistenti restano verdi).

- [ ] **Step 3: Chiavi i18n**

In `static/js/i18n.js`, dizionario **italiano** (accanto alle altre `ep*`):

```javascript
        epThActions: "Azioni",
        epActDiagnose: "Diagnostica questo client",
        epActLocate: "Localizza il MAC fra gli switch",
        epActPortCfg: "Configurazione della porta",
```

Dizionario **inglese**, stesse chiavi:

```javascript
        epThActions: "Actions",
        epActDiagnose: "Diagnose this client",
        epActLocate: "Locate this MAC across switches",
        epActPortCfg: "Port configuration",
```

- [ ] **Step 4: Implementa la colonna**

In `static/js/endpoint-inventory.js`, dentro `endpointsRender`, aggiungi prima della costruzione di `body` un helper:

```javascript
    // Le tre azioni esistono gia' altrove: qui si rendono solo raggiungibili
    // dalla riga. stopPropagation perche' la riga stessa e' cliccabile e
    // senza di esso ogni pulsante farebbe partire anche la diagnosi.
    const act = (icon, title, call, enabled) => enabled
        ? `<button onclick="event.stopPropagation(); ${call}" title="${escapeHtml(title)}"
             style="border:none; background:none; color:var(--primary); cursor:pointer; font-size:12px; margin-right:8px;">
             <i class="fa-solid ${icon}"></i></button>`
        : `<span style="color:var(--text-muted); font-size:12px; margin-right:8px; opacity:0.35;"><i class="fa-solid ${icon}"></i></span>`;
```

Aggiungi la cella in coda a ogni `<tr>` di `body`, dopo la cella dei flag:

```javascript
        <td style="white-space:nowrap;">${
            act('fa-stethoscope', L.epActDiagnose,
                `endpointsDiagnose('${escapeHtml(jsStr(r.mac))}','${escapeHtml(jsStr(r.tenant || ''))}')`, true) +
            act('fa-magnifying-glass-location', L.epActLocate,
                `macLocate('${escapeHtml(jsStr(r.mac))}','${escapeHtml(jsStr(r.tenant || ''))}')`, true) +
            act('fa-file-lines', L.epActPortCfg,
                `showPortConfig('${escapeHtml(jsStr(r.switch_ip))}','${escapeHtml(jsStr(r.interface))}','${escapeHtml(jsStr(r.switch_name || ''))}')`,
                !!(r.switch_ip && r.interface))
        }</td>
```

E l'intestazione, in coda alla riga di `<th>`:

```javascript
                <th>${escapeHtml(L.epThActions)}</th>
```

- [ ] **Step 5: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_endpoint_inventory -v` → PASS
Run: `node --check static/js/endpoint-inventory.js`

- [ ] **Step 6: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add static/js/endpoint-inventory.js static/js/i18n.js tests/test_endpoint_inventory.py
git commit -m "feat(ui): give endpoint rows explicit diagnose, locate and port-config actions

The row already ran the diagnosis on click, but nothing said so. The three
actions reuse functions that already exist elsewhere; the buttons stop
propagation so they do not also fire the row.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 2: lo store dei default SNMP di tenant

**Files:**
- Create: `security/snmp_defaults.py`
- Test: `tests/test_snmp_defaults.py` (nuovo)

**Interfaces:**
- Consumes: `security.crypto_vault.encrypt_password` / `decrypt_password`; `services.inventory_manager.safe_json_write` (scrittura atomica, già usata da `identity_manager._save`).
- Produces:
  ```python
  get_tenant_community(tenant: str) -> str        # in chiaro, uso interno
  set_tenant_community(tenant: str, community: str) -> None   # "" rimuove
  tenants_with_default() -> set                   # solo i NOMI, nessun segreto
  resolve_snmp_community(device: dict) -> str     # "" = non interrogare
  ```

- [ ] **Step 1: Scrivi il test che fallisce**

Crea `tests/test_snmp_defaults.py`:

```python
# -*- coding: utf-8 -*-
"""Community SNMP gerarchica: default di tenant, override per apparato.

La regola in una riga: l'apparato vince sul tenant, e il flag di esclusione
vince su entrambi. "Non impostata" e "spenta di proposito" sono due cose
diverse — prima coincidevano, ed e' il motivo per cui il flag esiste:
altrimenti attivare un default comincerebbe a interrogare apparati che erano
volutamente fuori.
"""

import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_snmpdef_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from security import snmp_defaults  # noqa: E402
from security.crypto_vault import encrypt_password  # noqa: E402


def _device(ip="192.0.2.1", group="sede-a", community=None, disabled=""):
    d = {"IP": ip, "Group": group, "SNMP Disabled": disabled}
    if community is not None:
        d["SNMP Community"] = encrypt_password(community)
    return d


class _Base(unittest.TestCase):
    def setUp(self):
        # "Generale" compreso: TENANT_SNMP_JSON e' fissata all'import del
        # modulo (come identities.json), quindi lo stato lasciato qui vive
        # anche per i moduli di test importati dopo questo.
        snmp_defaults.set_tenant_community("sede-a", "")
        snmp_defaults.set_tenant_community("sede-b", "")
        snmp_defaults.set_tenant_community("Generale", "")


class TestStore(_Base):

    def test_scrittura_e_rilettura(self):
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")

        self.assertEqual(snmp_defaults.get_tenant_community("sede-a"),
                         "esempio-community")

    def test_tenant_senza_default(self):
        self.assertEqual(snmp_defaults.get_tenant_community("sede-b"), "")

    def test_stringa_vuota_rimuove(self):
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")
        snmp_defaults.set_tenant_community("sede-a", "")

        self.assertEqual(snmp_defaults.get_tenant_community("sede-a"), "")
        self.assertNotIn("sede-a", snmp_defaults.tenants_with_default())

    def test_il_segreto_non_e_in_chiaro_su_disco(self):
        """Cifrata nel vault come ogni altra credenziale del progetto."""
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")

        with open(snmp_defaults.TENANT_SNMP_JSON, encoding="utf-8") as fh:
            self.assertNotIn("esempio-community", fh.read())

    def test_l_elenco_espone_i_nomi_non_i_segreti(self):
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")

        self.assertEqual(snmp_defaults.tenants_with_default(), {"sede-a"})


class TestPrecedenza(_Base):

    def test_l_apparato_vince_sul_tenant(self):
        snmp_defaults.set_tenant_community("sede-a", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community(_device(community="propria")),
            "propria")

    def test_senza_community_eredita_dal_tenant(self):
        snmp_defaults.set_tenant_community("sede-a", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community(_device(community="")),
            "del-tenant")

    def test_campo_assente_eredita_come_campo_vuoto(self):
        """Le righe di hosts.csv scritte prima di questa colonna non hanno la
        chiave: assente e vuoto devono comportarsi uguale."""
        snmp_defaults.set_tenant_community("sede-a", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community({"IP": "192.0.2.1", "Group": "sede-a"}),
            "del-tenant")

    def test_senza_niente_non_si_interroga(self):
        self.assertEqual(
            snmp_defaults.resolve_snmp_community(_device(community="")), "")

    def test_il_flag_di_esclusione_vince_su_tutto(self):
        """Anche con una community propria: 'mai interrogare' e' un'istruzione
        esplicita, non un ripiego."""
        snmp_defaults.set_tenant_community("sede-a", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community(
                _device(community="propria", disabled="1")), "")

    def test_il_default_e_per_tenant_non_globale(self):
        """Un tenant non eredita il default di un altro: sono reti diverse."""
        snmp_defaults.set_tenant_community("sede-a", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community(
                _device(group="sede-b", community="")), "")

    def test_tenant_mancante_sul_device(self):
        """Group vuoto = 'Generale', come ovunque nell'inventario."""
        snmp_defaults.set_tenant_community("Generale", "del-tenant")

        self.assertEqual(
            snmp_defaults.resolve_snmp_community({"IP": "192.0.2.1"}),
            "del-tenant")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_snmp_defaults -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'security.snmp_defaults'`.

- [ ] **Step 3: Implementa**

Crea `security/snmp_defaults.py`:

```python
# -*- coding: utf-8 -*-
"""Community SNMP predefinita per tenant, con override per apparato.

PERCHE' UN FILE A PARTE E NON ``groups.json``: ``routers/inventory.py``
restituisce al browser il dizionario di ogni gruppo per intero. Un segreto
messo li' verrebbe spedito a ogni utente, e la protezione dipenderebbe dal
fatto che ogni futuro serializzatore di gruppi si ricordi di ripulirlo. Qui
la fuga e' strutturalmente impossibile — stessa scelta gia' fatta per le
identita' in ``identity_manager.py``.

La community e' cifrata con Fernet come ogni altra credenziale. Le API di
lettura espongono i NOMI dei tenant che ne hanno una, mai il valore.
"""
import json
import logging
import os
import threading
from typing import Optional

from core import data_config
from security.crypto_vault import encrypt_password, decrypt_password

TENANT_SNMP_JSON = data_config.get_path("tenant_snmp.json")
_lock = threading.RLock()


def _load() -> dict:
    if not os.path.exists(TENANT_SNMP_JSON):
        return {}
    try:
        with open(TENANT_SNMP_JSON, "r", encoding="utf-8") as f:
            return json.load(f).get("tenants", {})
    except Exception as e:
        # Stessa tolleranza di identities.json: un file corrotto non deve
        # impedire l'avvio, ma non deve nemmeno fingere che ci sia un default.
        logging.warning("Errore caricamento tenant_snmp.json: %s", e)
        return {}


def _save(tenants: dict) -> None:
    from services.inventory_manager import safe_json_write
    safe_json_write(TENANT_SNMP_JSON, {"tenants": tenants})


def get_tenant_community(tenant: str) -> str:
    """Community predefinita del tenant, in chiaro. "" se non configurata.

    SOLO per uso interno (interrogazione degli apparati): non deve finire in
    nessuna risposta HTTP.
    """
    with _lock:
        entry = _load().get(tenant or "Generale") or {}
    return decrypt_password(entry.get("community_enc", "")) or ""


def set_tenant_community(tenant: str, community: str) -> None:
    """Imposta o rimuove ("" rimuove) il default del tenant."""
    key = tenant or "Generale"
    with _lock:
        tenants = _load()
        if community:
            tenants[key] = {"community_enc": encrypt_password(community)}
        else:
            tenants.pop(key, None)
        _save(tenants)


def tenants_with_default() -> set:
    """I NOMI dei tenant che hanno un default. Nessun segreto."""
    with _lock:
        return set(_load().keys())


def resolve_snmp_community(device: dict) -> str:
    """Community effettiva di un apparato. "" significa NON interrogarlo.

    Precedenza, dalla piu' forte: il flag di esclusione, poi la community
    dell'apparato, poi il default del tenant.

    Il flag esiste perche' senza di lui "non impostata" e "spenta di
    proposito" sarebbero lo stesso valore: attivare un default di tenant
    comincerebbe a interrogare apparati che erano volutamente fuori, e la
    community viaggia in chiaro (SNMPv2c).
    """
    if str(device.get("SNMP Disabled") or "").strip() in ("1", "true", "True"):
        return ""
    own = decrypt_password(device.get("SNMP Community") or "") or ""
    if own:
        return own
    return get_tenant_community(device.get("Group") or "Generale")
```

- [ ] **Step 4: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_snmp_defaults -v` → PASS

- [ ] **Step 5: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add security/snmp_defaults.py tests/test_snmp_defaults.py
git commit -m "feat(snmp): add a per-tenant default community with device override

Kept in its own encrypted store rather than groups.json, whose whole value
dict is returned to the browser. Device community wins over the tenant
default, and an explicit disable flag wins over both - so 'not set' and
'deliberately off' stop being the same value.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3: il flag di esclusione sull'apparato

**Files:**
- Modify: `services/inventory_manager.py` (`_fieldnames` riga 264, `_CSV_ALIASES` — il dizionario parte alla riga 167, la voce `"snmpcommunity"` da affiancare è l'ultima, riga 198, `add_or_update_device` riga 348), `routers/inventory.py` (schema riga 39, lettura riga 86), `observability/ingesters/snmp_poller.py` (`_snmp_devices` riga 265)
- Modify (sincronizzazione delle colonne canoniche): `services/site_agent.py` (intestazione di ripiego di `_agent_get_inventory`, riga ~314), `scripts/vm_agent_test_helper.py` (`CSV_HEADERS` righe 44-49, il commento impone di restare sincronizzati con `safe_write_hosts_csv`), `docs/remote-sites.md` (§3.3: "twelve columns" → tredici, esempio di intestazione)
- Test: `tests/test_snmp_defaults.py` (classe nuova)
- Verifica: `tests/test_snmp_poller.py` — la classe esistente `TestDeviceSelection` (riga ~110) prova proprio `_snmp_devices()`, che questo task riscrive: va eseguita e deve restare verde

**Interfaces:**
- Consumes: `snmp_defaults.resolve_snmp_community(device)` da Task 2.
- Produces: colonna `SNMP Disabled` in `network_hosts.csv`; parametro `snmp_disabled=None` in `add_or_update_device` (None preserva, come già fanno credenziali e community); campi `snmp_enabled` e `snmp_inherited` nella risposta di `/api/local-devices`.

- [ ] **Step 1: Scrivi il test che fallisce**

In coda a `tests/test_snmp_defaults.py`:

```python
class TestPollerUsaLaRisoluzione(_Base):
    """Il poller e' l'unico consumatore runtime della community: se non passa
    dalla risoluzione condivisa, l'ereditarieta' non esiste per nessuno."""

    def test_il_poller_include_un_apparato_che_eredita(self):
        from unittest.mock import patch
        from observability.ingesters import snmp_poller

        snmp_defaults.set_tenant_community("sede-a", "del-tenant")
        devices = [_device(ip="192.0.2.1", group="sede-a", community="")]

        with patch("services.inventory_manager.get_all_devices",
                   return_value=devices):
            out = snmp_poller._snmp_devices()

        self.assertEqual([d["ip"] for d in out], ["192.0.2.1"])
        self.assertEqual(out[0]["community"], "del-tenant")

    def test_il_poller_salta_un_apparato_escluso(self):
        from unittest.mock import patch
        from observability.ingesters import snmp_poller

        snmp_defaults.set_tenant_community("sede-a", "del-tenant")
        devices = [_device(ip="192.0.2.1", group="sede-a",
                           community="propria", disabled="1")]

        with patch("services.inventory_manager.get_all_devices",
                   return_value=devices):
            self.assertEqual(snmp_poller._snmp_devices(), [])
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_snmp_defaults.TestPollerUsaLaRisoluzione -v`
Expected: FAIL — il poller decifra ancora la community da sé e ignora sia il default sia il flag.

- [ ] **Step 3: La colonna in `services/inventory_manager.py`**

Nel dizionario `_CSV_ALIASES` (inizia alla riga 167), aggiungi gli alias accanto a `"snmpcommunity"` (ultima voce, riga 198):

```python
    "snmpdisabled": "SNMP Disabled", "snmpescluso": "SNMP Disabled",
```

Riga 264, aggiungi il campo in coda a `_fieldnames` (in coda, così i CSV esistenti restano leggibili):

```python
    _fieldnames = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret', 'Group', 'Hostname', 'Site', 'SSH Port', 'Transports', 'SNMP Community', 'SNMP Disabled']
```

In `add_or_update_device`, aggiungi il parametro in coda alla firma:

```python
def add_or_update_device(ip, vendor, profile, username, password, enable_secret, group, site=None, ssh_port=None, transports=None, snmp_community=None, snmp_disabled=None):
```

e accanto alla risoluzione di `enc_community` (riga ~410):

```python
        # Esclusione SNMP: None = lascia com'e' (i moduli che aggiornano un
        # device per altri motivi non devono cambiarla), come per la community.
        if snmp_disabled is None:
            disabled_val = (existing.get('SNMP Disabled') if existing else '') or ''
        else:
            disabled_val = '1' if snmp_disabled else ''
```

e nel dizionario scritto (riga ~424), accanto a `'SNMP Community'`:

```python
            'SNMP Disabled': disabled_val,
```

- [ ] **Step 4: Il poller passa dalla risoluzione condivisa**

In `observability/ingesters/snmp_poller.py`, sostituisci il corpo di `_snmp_devices()`:

```python
def _snmp_devices() -> list:
    """Apparati da interrogare, con la community EFFETTIVA.

    La precedenza (flag di esclusione, community dell'apparato, default del
    tenant) vive in ``snmp_defaults.resolve_snmp_community``: qui non si
    decifra piu' niente a mano, cosi' non c'e' una seconda regola che col
    tempo diverge dalla prima.
    """
    from security.snmp_defaults import resolve_snmp_community
    from services import inventory_manager
    out = []
    for device in inventory_manager.get_all_devices():
        community = resolve_snmp_community(device)
        if not community:
            continue
        out.append({"ip": device.get("IP"),
                    "tenant": device.get("Group") or "Generale",
                    "community": community})
    return out
```

- [ ] **Step 5: Lo schema e la lettura in `routers/inventory.py`**

Riga ~39, accanto a `snmp_community`:

```python
    snmp_disabled: Optional[bool] = None
```

Riga ~140, nella chiamata a `add_or_update_device`, aggiungi:

```python
            snmp_disabled=device.snmp_disabled,
```

Riga ~86, sostituisci la riga di `snmp_enabled` con la coppia:

```python
        # Alla UI serve sapere SE il polling e' configurato e DA DOVE arriva
        # la community: senza il secondo campo, un apparato che eredita e uno
        # con la sua sembrano identici, e l'admin non sa cosa sta modificando.
        own = bool(dev_copy.pop("SNMP Community", ""))
        disabled = str(dev_copy.get("SNMP Disabled") or "").strip() in ("1", "true", "True")
        inherited = (not own) and (not disabled) and \
            (d.get("Group") or "Generale") in _snmp_default_tenants
        dev_copy["snmp_enabled"] = (own or inherited) and not disabled
        dev_copy["snmp_inherited"] = inherited
```

e prima del ciclo `for d in devices:` (riga ~81), leggi una volta sola l'insieme dei tenant con default:

```python
    from security.snmp_defaults import tenants_with_default
    _snmp_default_tenants = tenants_with_default()
```

- [ ] **Step 6: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_snmp_defaults tests.test_import_csv_parsing tests.test_snmp_poller -v` → PASS
`test_import_csv_parsing` copre le intestazioni CSV: se la colonna nuova rompe la lettura tollerante, fallisce lì. `test_snmp_poller.TestDeviceSelection` copriva la vecchia `_snmp_devices()`: con lo store dei default vuoto deve restare verde com'è, senza modifiche.

- [ ] **Step 7: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add services/inventory_manager.py routers/inventory.py observability/ingesters/snmp_poller.py tests/test_snmp_defaults.py
git commit -m "feat(snmp): resolve the effective community in one shared place

The poller decrypted the device field itself, which is where inheritance
would have had to be duplicated. It now asks resolve_snmp_community(), and
a device carries an explicit SNMP Disabled flag so a tenant default cannot
start polling a device that was deliberately left out.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3b: propagare la colonna alle altre dichiarazioni dello schema

Task a sé perché è una preoccupazione diversa da quella del 3 — lì si cambia
COME si risolve la community, qui si allinea DOVE è dichiarato lo schema del
CSV — e perché un revisore deve poter respingere l'una senza l'altra.

**Files:**
- Modify: `services/site_agent.py` (~riga 314), `scripts/vm_agent_test_helper.py` (`CSV_HEADERS`, righe 44-49), `docs/remote-sites.md` (§3.3)
- Verifica: `tests/test_import_csv_parsing.py`, `tests/test_remote_site.py`

**Interfaces:** nessuna nuova. Si allinea la colonna `SNMP Disabled` introdotta dal Task 3.

Le colonne di `network_hosts.csv` sono dichiarate in **quattro** posti, non
uno. Il più insidioso non è documentazione: l'intestazione di ripiego in
`site_agent._agent_get_inventory` è un percorso di RUNTIME, quello che un
agente restituisce quando non ha ancora un inventario. Lasciarla a dodici
colonne mentre la centrale ne scrive tredici è un bug, non un refuso.

- [ ] **Step 1: L'intestazione di ripiego dell'agente**

In `services/site_agent.py`, `_agent_get_inventory` (~riga 314), la stringa
finisce con `"...,Transports,SNMP Community\n"`: aggiungi `,SNMP Disabled`
prima del `\n`.

- [ ] **Step 2: L'helper di test della VM**

In `scripts/vm_agent_test_helper.py`, `CSV_HEADERS` (righe 44-49), aggiungi
`"SNMP Disabled"` in coda alla lista. Il commento sopra dice che sono le
stesse colonne di `safe_write_hosts_csv`: ora tornano a esserlo.

- [ ] **Step 3: La documentazione**

In `docs/remote-sites.md` §3.3: nell'esempio
`cat << 'EOF' > agent-data/network_hosts.csv` aggiungi `,SNMP Disabled` alla
riga di intestazione e una virgola in più alle righe dati; la frase
"These twelve columns are the canonical schema" (riga ~149) diventa
"thirteen". `docs/development.md` §6.4 impone di aggiornare la documentazione
toccata dalla modifica.

- [ ] **Step 4: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_import_csv_parsing tests.test_remote_site -v`
Expected: PASS. `test_remote_site` esercita il giro dell'inventario di sede:
è il test che si accorge se le due estremità non concordano sulle colonne.

- [ ] **Step 5: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add services/site_agent.py scripts/vm_agent_test_helper.py docs/remote-sites.md
git commit -m "fix(inventory): declare the new CSV column everywhere it is declared

hosts.csv columns are written down in four places. The site agent's fallback
inventory header is one of them and it is a runtime path, not documentation:
left at twelve columns it disagrees with what central writes.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3c: il poller non deve serializzare gli apparati muti

**Decisione presa con l'utente** (scopo del default: "il meglio per la
gestibilità"). Il default vale per **tutti** gli apparati del tenant,
compresi quelli con `Site` remoto — `_snmp_devices()` non ha mai filtrato per
sede, quindi la centrale già oggi interroga anche quelli. Perché quello scopo
sia sicuro serve togliere la ragione per temerlo.

`poll_once()` (`observability/ingesters/snmp_poller.py:294`) cicla gli
apparati **in sequenza**, con `TIMEOUT_S = 2` e `RETRIES = 1`: ogni apparato
che non risponde costa ~4 s e blocca il successivo. È una debolezza che esiste
già; un default di tenant la rende solo più probabile, perché aggiunge in un
colpo tutti gli apparati della sede che non hanno una community propria.

**Files:**
- Modify: `observability/ingesters/snmp_poller.py` (`poll_once`)
- Test: `tests/test_snmp_poller.py` (classe nuova)

**Interfaces:**
- Produces: `poll_once()` invariata nella firma e nel valore di ritorno (numero di snapshot scritti). Cambia solo che gli apparati vengono interrogati in parallelo, con un tetto.

- [ ] **Step 1: Scrivi il test che fallisce**

In coda a `tests/test_snmp_poller.py`:

```python
class TestConcorrenza(unittest.TestCase):
    """Un apparato muto non deve fermare gli altri.

    Non e' un'ottimizzazione: con TIMEOUT_S=2 e RETRIES=1 ogni apparato
    irraggiungibile costa ~4s, e in sequenza venti apparati muti allungano
    ogni giro di oltre un minuto. Il default di tenant li aggiunge in blocco,
    quindi il costo va tolto prima, non dopo.
    """

    def test_gli_apparati_sono_interrogati_in_parallelo(self):
        import asyncio
        from unittest.mock import patch
        from observability.ingesters import snmp_poller

        in_volo = {"ora": 0, "max": 0}

        async def lento(ip, community, port=161):
            in_volo["ora"] += 1
            in_volo["max"] = max(in_volo["max"], in_volo["ora"])
            await asyncio.sleep(0.05)
            in_volo["ora"] -= 1
            return []

        devices = [{"ip": f"192.0.2.{i}", "tenant": "sede-a",
                    "community": "esempio-community"} for i in range(6)]

        with patch.object(snmp_poller, "_snmp_devices", return_value=devices), \
             patch.object(snmp_poller, "_poll_device", side_effect=lento):
            asyncio.run(snmp_poller.poll_once())

        self.assertGreater(in_volo["max"], 1,
                           "in sequenza il massimo in volo resta 1")

    def test_il_parallelismo_ha_un_tetto(self):
        """Senza tetto, mille apparati aprirebbero mille socket UDP insieme."""
        import asyncio
        from unittest.mock import patch
        from observability.ingesters import snmp_poller

        in_volo = {"ora": 0, "max": 0}

        async def lento(ip, community, port=161):
            in_volo["ora"] += 1
            in_volo["max"] = max(in_volo["max"], in_volo["ora"])
            await asyncio.sleep(0.02)
            in_volo["ora"] -= 1
            return []

        devices = [{"ip": f"192.0.2.{i}", "tenant": "sede-a",
                    "community": "esempio-community"} for i in range(40)]

        with patch.object(snmp_poller, "_snmp_devices", return_value=devices), \
             patch.object(snmp_poller, "_poll_device", side_effect=lento):
            asyncio.run(snmp_poller.poll_once())

        self.assertLessEqual(in_volo["max"], snmp_poller.MAX_CONCURRENT_POLLS)

    def test_un_apparato_che_solleva_non_ferma_il_giro(self):
        """Gia' vero oggi e deve restarlo: SNMP su UDP tace di continuo."""
        import asyncio
        from unittest.mock import patch
        from observability.ingesters import snmp_poller

        async def uno_esplode(ip, community, port=161):
            if ip.endswith(".2"):
                raise OSError("rete irraggiungibile")
            return [("snmp_system", "{}")]

        devices = [{"ip": f"192.0.2.{i}", "tenant": "sede-a",
                    "community": "esempio-community"} for i in (1, 2, 3)]

        with patch.object(snmp_poller, "_snmp_devices", return_value=devices), \
             patch.object(snmp_poller, "_poll_device", side_effect=uno_esplode), \
             patch("core.db.enqueue_write"):
            scritti = asyncio.run(snmp_poller.poll_once())

        self.assertEqual(scritti, 2, "gli altri due passano comunque")
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_snmp_poller.TestConcorrenza -v`
Expected: FAIL — il primo con `1 not greater than 1` (il ciclo è sequenziale), il secondo con `AttributeError: MAX_CONCURRENT_POLLS`.

- [ ] **Step 3: Implementa**

In `observability/ingesters/snmp_poller.py`, accanto a `TIMEOUT_S` e `RETRIES`:

```python
# Tetto agli apparati interrogati insieme. Serve perche' un default di tenant
# puo' aggiungere in un colpo tutta la sede: senza tetto sarebbero altrettanti
# socket UDP aperti nello stesso istante.
MAX_CONCURRENT_POLLS = 10
```

e sostituisci il ciclo di `poll_once()`:

```python
    n = 0
    ts = int(time.time())
    semaforo = asyncio.Semaphore(MAX_CONCURRENT_POLLS)

    async def _uno(device: dict) -> list:
        # Un apparato che solleva non ferma il giro: su UDP il silenzio e' il
        # caso comune, non l'eccezione.
        async with semaforo:
            try:
                return await _poll_device(device["ip"], device["community"])
            except Exception as e:
                logger.info("SNMP fallito su %s: %s", device["ip"], e)
                return []

    for device, snapshots in zip(devices,
                                 await asyncio.gather(*(_uno(d) for d in devices))):
        for kind, summary in snapshots:
            db.enqueue_write(
                "INSERT INTO api_observations(ts, tenant, device_ip, kind, summary_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (ts, device["tenant"], device["ip"], kind, summary))
            n += 1
    return n
```

Le scritture restano in sequenza dopo la raccolta: `db.enqueue_write` accoda
già, e tenere l'inserimento fuori dal parallelismo evita di doversi chiedere
in che ordine arrivano.

- [ ] **Step 4: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_snmp_poller -v` → PASS, `TestDeviceSelection` compresa.

- [ ] **Step 5: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add observability/ingesters/snmp_poller.py tests/test_snmp_poller.py
git commit -m "perf(snmp): poll devices concurrently instead of one after another

A device that does not answer costs TIMEOUT_S x RETRIES and blocked the next
one, so twenty silent devices added over a minute to every cycle. A tenant
default adds a whole site at once, which is what made this worth fixing now.
Bounded by a semaphore so it cannot open a socket per device.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 4: le rotte del default di tenant

**Files:**
- Modify: `routers/settings.py`, `tests/test_router_parity.py` (le due allowlist dei percorsi + `NEW_SCHEMAS`)
- Test: `tests/test_snmp_defaults.py` (classi nuove: `TestRotte`, `TestRotteSmoke`)

**Interfaces:**
- Consumes: `snmp_defaults.tenants_with_default()`, `set_tenant_community()`; `routers.deps.get_current_user`, `require_admin`, `user_group_scope`, `assert_group_allowed`.
- Produces:
  ```
  GET  /api/settings/snmp-defaults        -> {"tenants": ["sede-a", ...]}   (solo nomi, scoped)
  POST /api/settings/snmp-defaults        {tenant, community}  (admin; "" rimuove)
  ```

- [ ] **Step 1: Scrivi il test che fallisce**

In coda a `tests/test_snmp_defaults.py`:

```python
class TestRotte(_Base):
    """La community non esce MAI da un'API di lettura, nemmeno cifrata."""

    def setUp(self):
        super().setUp()
        from routers import settings as settings_router
        self.router = settings_router

    def test_la_lettura_espone_solo_i_nomi(self):
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")

        out = self.router.snmp_defaults_get(
            current_user={"sub": "a", "role": "admin"})

        self.assertEqual(out["tenants"], ["sede-a"])
        # Ne' in chiaro ne' cifrata: la risposta e' fatta di soli nomi.
        self.assertNotIn("esempio-community", repr(out))
        self.assertEqual(set(out.keys()), {"tenants"})

    def test_la_lettura_e_ristretta_ai_tenant_dell_utente(self):
        from unittest.mock import patch
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")
        snmp_defaults.set_tenant_community("sede-b", "altra-community")

        with patch("routers.settings.user_group_scope", return_value={"sede-a"}):
            out = self.router.snmp_defaults_get(
                current_user={"sub": "v", "role": "viewer"})

        self.assertEqual(out["tenants"], ["sede-a"])

    def test_la_scrittura_imposta_il_default(self):
        from routers.settings import SnmpDefaultSchema

        self.router.snmp_defaults_set(
            SnmpDefaultSchema(tenant="sede-a", community="esempio-community"),
            current_user={"sub": "a", "role": "admin"})

        self.assertEqual(snmp_defaults.get_tenant_community("sede-a"),
                         "esempio-community")

    def test_la_scrittura_vuota_rimuove(self):
        from routers.settings import SnmpDefaultSchema
        snmp_defaults.set_tenant_community("sede-a", "esempio-community")

        self.router.snmp_defaults_set(
            SnmpDefaultSchema(tenant="sede-a", community=""),
            current_user={"sub": "a", "role": "admin"})

        self.assertEqual(snmp_defaults.get_tenant_community("sede-a"), "")

    def test_tenant_fuori_scope_e_403(self):
        from fastapi import HTTPException
        from routers.settings import SnmpDefaultSchema
        from unittest.mock import patch

        with patch("routers.settings.user_group_scope", return_value={"sede-a"}):
            with self.assertRaises(HTTPException) as ctx:
                self.router.snmp_defaults_set(
                    SnmpDefaultSchema(tenant="sede-b", community="x"),
                    current_user={"sub": "a", "role": "operator"})
        self.assertEqual(ctx.exception.status_code, 403)


class TestRotteSmoke(unittest.TestCase):
    """Regola di .agents/AGENTS.md: una rotta nuova va colpita DAVVERO via
    TestClient — chiamare la funzione del handler non esegue i Depends e
    nasconde NameError/ImportError. 401 basta: prova che il codice gira
    (precedente: tests/test_ai_conversations.py, stesso pattern)."""

    def test_le_rotte_rispondono_anche_senza_autenticazione(self):
        from fastapi.testclient import TestClient
        import app_server

        client = TestClient(app_server.app)
        self.assertEqual(401, client.get(
            "/api/settings/snmp-defaults").status_code)
        self.assertEqual(401, client.post(
            "/api/settings/snmp-defaults",
            json={"tenant": "sede-a", "community": "x"}).status_code)
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_snmp_defaults.TestRotte tests.test_snmp_defaults.TestRotteSmoke -v`
Expected: FAIL — `AttributeError: module 'routers.settings' has no attribute 'snmp_defaults_get'`; lo smoke fallisce con 404 (la rotta non esiste ancora) invece di 401.

- [ ] **Step 3: Implementa**

In `routers/settings.py`. Il file importa già `APIRouter`, `Depends`, `HTTPException`, `BaseModel` e `log_audit`; la riga degli import di deps è oggi `from routers.deps import require_admin` e va estesa:

```python
from routers.deps import (require_admin, get_current_user, user_group_scope,
                          assert_group_allowed)
```

Poi, in coda al file:

```python
class SnmpDefaultSchema(BaseModel):
    tenant: str
    community: str = ""          # "" rimuove il default


@router.get("/api/settings/snmp-defaults")
def snmp_defaults_get(current_user = Depends(get_current_user)):
    """I tenant che hanno una community predefinita. SOLO i nomi.

    Il valore non esce da qui nemmeno cifrato: alla UI serve sapere SE il
    default c'e', non quale sia — stessa regola dei device in
    ``/api/local-devices`` e delle identita'.
    """
    from security.snmp_defaults import tenants_with_default
    scope = user_group_scope(current_user)
    names = tenants_with_default()
    if scope is not None:
        names = {t for t in names if t in scope}
    return {"tenants": sorted(names)}


@router.post("/api/settings/snmp-defaults")
def snmp_defaults_set(payload: SnmpDefaultSchema,
                      current_user = Depends(require_admin)):
    """Imposta o rimuove ("" rimuove) la community predefinita di un tenant.

    ``require_admin``: e' una credenziale che vale per OGNI apparato della
    sede, quindi non e' un'impostazione di comodo.
    """
    from security.snmp_defaults import set_tenant_community
    assert_group_allowed(current_user, payload.tenant)
    set_tenant_community(payload.tenant, payload.community)
    log_audit(f"Community SNMP predefinita del tenant '{payload.tenant}' "
              f"{'impostata' if payload.community else 'rimossa'} da "
              f"'{current_user.get('sub')}'.")
    return {"status": "success"}
```

- [ ] **Step 4: Le allowlist di parità: due sui percorsi, una sugli schemi**

In `tests/test_router_parity.py`, aggiungi `"/api/settings/snmp-defaults"` a `TestRouterParity.ALLOWED_NEW_PREFIXES` (riga ~58). Esegui poi i test di parità: se `TestFullParity` protesta con "l'insieme dei percorsi è cambiato", aggiungi lo stesso prefisso anche a `TestFullParity.NEW_PREFIXES` (riga ~146). Sono due allowlist indipendenti.

In più: `SnmpDefaultSchema` è uno schema NUOVO e va aggiunto a `TestFullParity.NEW_SCHEMAS` (riga ~151), altrimenti il confronto degli schemi fallisce — è la terza lista, distinta dalle due dei percorsi, e `HANDOFF.md` la segnala esplicitamente ("Uno schema nuovo va in `TestFullParity.NEW_SCHEMAS`"). Il campo nuovo su `DeviceSchema` non richiede niente: quello schema è già in entrambe le `ALLOWED_CHANGED_SCHEMAS` (righe ~113 e ~190).

- [ ] **Step 5: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_snmp_defaults tests.test_router_parity -v` → PASS

- [ ] **Step 6: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add routers/settings.py tests/test_router_parity.py tests/test_snmp_defaults.py
git commit -m "feat(api): read and write the per-tenant SNMP default

Reading returns tenant names only - the community never leaves the server,
not even encrypted. Writing is admin-only: it is a credential valid for
every device in the site.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 5: la UI

**Files:**
- Modify: `static/js/devices.js` (`renderGroupsTable` riga 21, il modale device intorno a riga 310 e 359), `static/js/core.js` (chiamata di `loadSnmpDefaults()` in `appInit()`, riga ~526), `templates/dashboard.html` (intestazione della tabella tenant, campo nel modale device), `static/js/i18n.js`
- Test: `tests/test_snmp_defaults.py` (classe grep)

**Interfaces:**
- Consumes: `GET /api/settings/snmp-defaults` e `POST /api/settings/snmp-defaults` da Task 4; `snmp_enabled` e `snmp_inherited` da Task 3.
- Produces: `loadSnmpDefaults()`, `setTenantSnmp(tenant)`; una colonna SNMP nella tabella tenant e una checkbox `devSnmpDisabled` nel modale device.

- [ ] **Step 1: Scrivi il test che fallisce**

In coda a `tests/test_snmp_defaults.py`:

```python
class TestUi(unittest.TestCase):
    """Verifica grep-style: non c'e' un runner JS."""

    @classmethod
    def setUpClass(cls):
        from tests.test_helpers_frontend import frontend_source
        cls.src = frontend_source()

    def test_la_tabella_tenant_mostra_lo_stato_snmp(self):
        self.assertIn("setTenantSnmp(", self.src)
        self.assertIn("snmpDefaultTenants", self.src)

    def test_il_modale_device_ha_l_esclusione(self):
        self.assertIn('id="devSnmpDisabled"', self.src)
        self.assertIn("payload.snmp_disabled", self.src)

    def test_l_ereditarieta_e_dichiarata_nel_modale(self):
        """Un apparato che eredita e uno con la sua community sembrano
        identici se non lo si dice: l'admin non saprebbe cosa sta cambiando."""
        self.assertIn("snmp_inherited", self.src)

    def test_le_chiavi_i18n_esistono_in_entrambe_le_lingue(self):
        for key in ("thTenantSnmp", "btnSetTenantSnmp", "lblSnmpDisabled",
                    "hintSnmpInherited", "promptTenantSnmp"):
            self.assertGreaterEqual(self.src.count(key + ":"), 2,
                                    f"chiave {key} assente in una delle lingue")
```

- [ ] **Step 2: Esegui il test e verifica che fallisca**

Run: `uv run python -m unittest tests.test_snmp_defaults.TestUi -v`
Expected: FAIL su tutti e quattro.

- [ ] **Step 3: Chiavi i18n**

In `static/js/i18n.js`, dizionario **italiano**:

```javascript
        thTenantSnmp: "SNMP predefinito",
        btnSetTenantSnmp: '<i class="fa-solid fa-key"></i> Imposta',
        lblSnmpDisabled: "Non interrogare mai via SNMP",
        hintSnmpInherited: "Eredita la community predefinita del tenant",
        promptTenantSnmp: "Community SNMP predefinita per questo tenant (vuoto per rimuoverla):",
```

Dizionario **inglese**, stesse chiavi:

```javascript
        thTenantSnmp: "Default SNMP",
        btnSetTenantSnmp: '<i class="fa-solid fa-key"></i> Set',
        lblSnmpDisabled: "Never poll over SNMP",
        hintSnmpInherited: "Inherits the tenant's default community",
        promptTenantSnmp: "Default SNMP community for this tenant (blank to remove):",
```

- [ ] **Step 4: La colonna nella tabella tenant**

In `templates/dashboard.html`, nella tabella dei tenant (`groupsTableBody`), aggiungi un `<th data-i18n="thTenantSnmp"></th>` prima della colonna delle azioni.

In `static/js/devices.js`, sopra `renderGroupsTable` (riga 21):

```javascript
    // Solo i NOMI dei tenant con un default: la community non arriva mai al
    // browser, quindi la tabella puo' dire "configurata" e nient'altro.
    let snmpDefaultTenants = [];

    async function loadSnmpDefaults() {
        const res = await apiFetch('/api/settings/snmp-defaults');
        if (!res || !res.ok) return;
        snmpDefaultTenants = (await res.json()).tenants || [];
        renderGroupsTable();
    }

    async function setTenantSnmp(tenant) {
        const L = i18n[currentLang];
        const value = prompt(L.promptTenantSnmp, '');
        if (value === null) return;               // annullato: non toccare nulla
        const res = await apiFetch('/api/settings/snmp-defaults', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant: tenant, community: value })
        });
        if (res && res.ok) loadSnmpDefaults();
    }
```

Dentro `renderGroupsTable`, aggiungi la cella prima di quella delle azioni:

```javascript
            const hasSnmp = snmpDefaultTenants.includes(g);
            const snmpCell = `<td>
                <span style="font-size:11px; color:${hasSnmp ? 'var(--success)' : 'var(--text-muted)'}; border:1px solid ${hasSnmp ? 'var(--success)' : 'var(--border)'}; border-radius:4px; padding:1px 6px;">
                    ${hasSnmp ? (currentLang === 'en' ? 'configured' : 'configurata')
                              : (currentLang === 'en' ? 'not set' : 'non impostata')}</span>
                ${currentRole === 'admin'
                    ? `<button onclick="setTenantSnmp(this.dataset.g)" data-g="${escapeHtml(g)}" style="margin-left:8px; color:var(--primary); background:none; border:none; cursor:pointer;">${i18n[currentLang].btnSetTenantSnmp}</button>`
                    : ''}</td>`;
```

e inseriscila nella stringa della riga, fra la cella della descrizione e quella delle azioni. Chiama `loadSnmpDefaults()` in `static/js/core.js`, dentro `appInit()`, subito dopo la chiamata a `renderGroupsTable()` (riga ~526, accanto al punto che popola `globalGroups` da `/api/local-devices`). Non altrove: `topology.js` riga ~2317 riempie di nuovo `globalGroups` ma non ridisegna la tabella dei tenant, e va lasciato com'è.

- [ ] **Step 5: Il modale device**

In `templates/dashboard.html`, accanto al campo `devSnmp` e alla checkbox `devSnmpClear`, aggiungi:

```html
              <label style="display:flex; align-items:center; gap:6px; font-size:12px; margin-top:6px;">
                <input type="checkbox" id="devSnmpDisabled" style="width:auto; margin:0;">
                <span data-i18n="lblSnmpDisabled"></span>
              </label>
```

In `static/js/devices.js`, nella costruzione del payload (riga ~312), aggiungi:

```javascript
        const snmpDisabled = document.getElementById('devSnmpDisabled');
        if (snmpDisabled) payload.snmp_disabled = snmpDisabled.checked;
```

e nel popolamento del modale (riga ~359), sostituisci il placeholder con la versione che distingue l'ereditarietà:

```javascript
        document.getElementById('devSnmp').value = '';
        document.getElementById('devSnmp').placeholder = dev.snmp_inherited
            ? i18n[currentLang].hintSnmpInherited
            : (dev.snmp_enabled
                ? (currentLang === 'en' ? 'configured — leave blank to keep'
                                        : 'configurata — lascia vuoto per non cambiarla')
                : '—');
        document.getElementById('devSnmpClear').checked = false;
        const dsd = document.getElementById('devSnmpDisabled');
        if (dsd) dsd.checked = !!dev['SNMP Disabled'];
```

- [ ] **Step 6: Esegui i test e verifica che passino**

Run: `uv run python -m unittest tests.test_snmp_defaults -v` → PASS
Run: `node --check static/js/devices.js`
Run: `node --check static/js/core.js`

- [ ] **Step 7: Verifica completa e commit**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

```sh
git add static/js/devices.js static/js/core.js static/js/i18n.js templates/dashboard.html tests/test_snmp_defaults.py
git commit -m "feat(ui): manage the tenant SNMP default and the per-device opt-out

The tenant table says whether a default exists, never what it is. The device
dialog distinguishes 'has its own community' from 'inherits the tenant's',
because otherwise an admin cannot tell what they are about to change.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 6: ricostruzione dell'eseguibile

- [ ] **Step 1: Ricostruisci**

```sh
uv run pyinstaller SentinelNet.spec
```

Expected: build completata; `dist/SentinelNet.exe` aggiornato.

> `SentinelNet.spec:7` impacchetta `('data','data')`, quindi la build non è deterministica (i sidecar `-wal`/`-shm` di SQLite compaiono e spariscono) e il binario contiene un DB con dati reali. Se fallisce per un file sparito, rilancia. È un problema già registrato a parte: non risolverlo qui.

---

## Self-Review

**Copertura della richiesta:**

| Richiesta | Task |
|---|---|
| Pulsante "Diagnose" in Endpoint Inventory | 1 (con localizza e config porta, come deciso) |
| Default SNMP a livello di tenant | 2 (store) + 4 (rotte) + 5 (UI) |
| Override per singolo apparato | 2 (`resolve_snmp_community`) + 3 (flag + poller) + 5 (UI) |
| Colonna CSV allineata ovunque sia dichiarata | 3b |
| Il default può coprire tutto il tenant senza far pagare il giro di polling | 3c |

**Ordine dei task.** 1 è indipendente e può stare ovunque. 2 → 3 → 4 → 5 sono
in catena. 3b dipende dal 3 (la colonna deve esistere). 3c è indipendente da
tutti — si può fare per primo, ed è anzi preferibile: rende sicuro lo scopo
che il 5 mette a portata di clic.

**Rischi noti, dichiarati:**

1. **Il click di riga resta.** I tre pulsanti devono fare `stopPropagation()`; il test di Task 1 verifica che l'helper comune ai tre pulsanti la contenga e che i pulsanti siano tre. Effetto collaterale già presente oggi e non risolto qui: con la riga cliccabile non si può selezionare un MAC per copiarlo. Se dà fastidio, si toglie l'`onclick` dal `<tr>` — una riga.
2. **Attivare un default di tenant cambia il comportamento di apparati esistenti.** Ogni apparato del tenant senza community propria e senza flag di esclusione comincia a essere interrogato. È l'effetto richiesto, ma va detto nella UI al momento dell'impostazione — la stringa `promptTenantSnmp` non lo dice. Se lo si vuole esplicito, va ampliata.
3. **`resolve_snmp_community` legge il file dei default a ogni apparato.** Il poller cicla tutta la flotta, quindi sono N letture di un JSON piccolo per giro. A poche centinaia di apparati non si misura; se un giorno pesasse, la correzione è leggere l'insieme una volta per giro e passarlo, non una cache dentro il modulo.
4. **SNMPv2c, sola lettura.** Non cambia con questo lavoro: la community viaggia in chiaro, come già scritto nell'intestazione di `snmp_poller.py`. Un default di tenant moltiplica il numero di apparati su cui quella stessa stringa transita — vale la pena saperlo, non è una ragione per non farlo su una rete di management.
5. **`test_import_csv_parsing`** copre la lettura tollerante delle intestazioni: è il test che si accorge se la colonna nuova rompe un CSV vecchio. Task 3 lo esegue esplicitamente, insieme a `test_snmp_poller` che copriva la vecchia `_snmp_devices()`.
6. **L'ereditarietà vale per TUTTI gli apparati del tenant, sede remota compresa.** Una versione precedente di questo piano diceva il contrario ("solo la centrale"): era **falsa**, e la correzione è il motivo del Task 3c. Il poller è sì avviato solo dal processo centrale (`observability/listener_manager.py`; l'agente di sede non esegue SNMP), ma `_snmp_devices()` cicla `get_all_devices()` — l'intero `network_hosts.csv` della centrale — **senza alcun filtro su `Site`**. Le righe di sede remota sono già interrogate oggi, se hanno una community. Quindi il default di tenant le raggiunge, ed è la scelta voluta: un default che si ferma a un campo `Site` a cui l'amministratore non sta pensando è meno gestibile, non più sicuro. Il costo — gli apparati che la centrale non raggiunge su UDP/161 — è tolto dal Task 3c invece che evitato restringendo lo scopo.
7. **`snmp_enabled` cambia significato.** Prima: "l'apparato ha una community propria". Ora: "l'apparato viene interrogato" (community propria O default ereditato), con `snmp_inherited` a distinguere i due casi. L'unico consumatore nel codice è `static/js/devices.js:359` (placeholder del modale), che il Task 5 aggiorna; nessun altro lettore esiste (verificato per grep).
8. **File di dati nuovo: niente da fare in spec/compose, ma va verificato.** `docs/development.md` §6.3 chiede di verificare i file di dati nuovi in sorgente/exe/Docker. `tenant_snmp.json` nasce a runtime: `SentinelNet.spec` impacchetta già l'intera `data/` e `docker-compose.yml` monta `./data` con `SENTINELNET_DATA_DIR=/app/data`, quindi nessuna modifica di configurazione serve. Dopo la ricostruzione del Task 6, verificare solo che l'eseguibile legga e scriva il file nella propria directory `data/`.
