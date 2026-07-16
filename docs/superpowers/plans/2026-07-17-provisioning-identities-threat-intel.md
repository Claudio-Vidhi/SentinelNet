# Tenant Identities + Provisioning Tab Reorg + Threat Intel Revamp — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tenant-scoped named credential profiles ("identities") usable by inventory devices, a reorganized two-column Device Provisioning tab, and a revamped Threat Intel tab with a Vendor Watch sub-tab (ported from euvd_dashboard) and a tenant/category-grouped Vulnerability Matcher.

**Architecture:** New `identity_manager.py` module (JSON store, Fernet-encrypted secrets via `crypto_vault`) + CRUD endpoints in `routers/provisioner.py`; `core_engine.get_device_credentials` learns the `identity:<id>` profile form. All UI work is in `templates/dashboard.html` (single-file dashboard, vanilla JS, i18n IT+EN dictionaries).

**Tech Stack:** Python 3 / FastAPI / Pydantic, vanilla JS single-page dashboard, unittest run as scripts (repo convention: `uv run python test_x.py`).

## Global Constraints

- Comments/docstrings in Italian, matching codebase style.
- All new UI strings added to BOTH i18n dictionaries (IT block ~line 2880, EN block ~line 3550 of dashboard.html) using existing key patterns.
- Secrets never returned to the UI, never logged. Mutations audit-logged via `security_manager.log_audit`.
- All new endpoints gated with `Depends(require_operator)` from `routers/deps` (read-only list may use `require_operator` too — operator is the write role; keep it simple: operator for everything).
- No new dependencies.
- Do NOT touch tab-provisioner (Zero-Touch) logic.
- Final step of the whole plan: `uv run pyinstaller SentinelNet.spec` must succeed.
- Run `graphify update .` after code changes if the graphify CLI is available; skip silently if not installed.

---

### Task A: Backend — identity_manager + endpoints + core_engine resolution

**Files:**
- Create: `identity_manager.py`
- Create: `test_identity_manager.py`
- Modify: `routers/provisioner.py` (append identity endpoints + schemas)
- Modify: `core_engine.py:77-84` (`get_device_credentials`)

**Interfaces:**
- Consumes: `inventory_manager.safe_json_write`, `inventory_manager.get_all_devices`, `data_config.get_path`, `crypto_vault.encrypt_password/decrypt_password`, `security_manager.log_audit`, `routers.deps.require_operator`.
- Produces (Task B relies on these):
  - `GET  /api/identities?tenant=<name>` → `{"identities": [{"id","name","tenant","username","devices_using": int}]}` (no secrets)
  - `POST /api/identities` body `{name, tenant, username, password, enable_secret}` → `{"status":"success","id":...}`
  - `PUT  /api/identities/{identity_id}` body `{name, tenant, username, password, enable_secret}` (password/secret required — re-entered on every edit) → `{"status":"success"}`
  - `DELETE /api/identities/{identity_id}` → 200 `{"status":"success"}` or **409** `{"detail": {"error":"in_use","devices":[ips]}}`
  - hosts.csv `Profile` value `identity:<id>` resolved by `core_engine.get_device_credentials`.

- [ ] **Step 1: Write failing tests**

Create `test_identity_manager.py` (pattern: unittest run as script, temp data dir):

```python
# -*- coding: utf-8 -*-
"""Test per identity_manager: CRUD, cifratura, blocco delete-in-uso,
risoluzione credenziali 'identity:<id>' in core_engine."""
import os
import tempfile
import unittest
from unittest import mock


class TestIdentityManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.json_path = os.path.join(self.tmp.name, "identities.json")
        import identity_manager
        self.im = identity_manager
        self._orig = self.im.IDENTITIES_JSON
        self.im.IDENTITIES_JSON = self.json_path

    def tearDown(self):
        self.im.IDENTITIES_JSON = self._orig
        self.tmp.cleanup()

    def test_add_and_list_no_secrets(self):
        ident = self.im.add_identity("noc-admin", "Tenant_Torino", "admin", "pw1", "sec1")
        self.assertTrue(ident["id"])
        rows = self.im.get_identities()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "noc-admin")
        self.assertEqual(rows[0]["tenant"], "Tenant_Torino")
        self.assertNotIn("password_enc", rows[0])
        self.assertNotIn("secret_enc", rows[0])

    def test_tenant_filter(self):
        self.im.add_identity("a", "T1", "u", "p", "s")
        self.im.add_identity("b", "T2", "u", "p", "s")
        self.assertEqual(len(self.im.get_identities(tenant="T1")), 1)

    def test_credentials_roundtrip(self):
        ident = self.im.add_identity("x", "T", "user1", "pw!", "sec!")
        u, p, s = self.im.get_identity_credentials(ident["id"])
        self.assertEqual((u, p, s), ("user1", "pw!", "sec!"))
        # su disco NON in chiaro
        with open(self.json_path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("pw!", raw)
        self.assertNotIn("sec!", raw)

    def test_update(self):
        ident = self.im.add_identity("x", "T", "u1", "p1", "s1")
        self.im.update_identity(ident["id"], name="y", tenant="T", username="u2",
                                password="p2", secret="s2")
        u, p, s = self.im.get_identity_credentials(ident["id"])
        self.assertEqual((u, p, s), ("u2", "p2", "s2"))
        self.assertEqual(self.im.get_identities()[0]["name"], "y")

    def test_delete_blocked_when_in_use(self):
        ident = self.im.add_identity("x", "T", "u", "p", "s")
        with mock.patch("inventory_manager.get_all_devices", return_value=[
                {"IP": "10.0.0.1", "Profile": f"identity:{ident['id']}"}]):
            ok, devices = self.im.delete_identity(ident["id"])
        self.assertFalse(ok)
        self.assertEqual(devices, ["10.0.0.1"])
        self.assertEqual(len(self.im.get_identities()), 1)

    def test_delete_free(self):
        ident = self.im.add_identity("x", "T", "u", "p", "s")
        with mock.patch("inventory_manager.get_all_devices", return_value=[]):
            ok, devices = self.im.delete_identity(ident["id"])
        self.assertTrue(ok)
        self.assertEqual(self.im.get_identities(), [])


class TestCoreEngineIdentityResolution(unittest.TestCase):
    def test_identity_profile_resolved(self):
        import core_engine
        with mock.patch("identity_manager.get_identity_credentials",
                        return_value=("iu", "ip", "is")):
            u, p, s = core_engine.get_device_credentials(
                {"Profile": "identity:abc123"})
        self.assertEqual((u, p, s), ("iu", "ip", "is"))

    def test_identity_missing_falls_back_to_default(self):
        import core_engine
        with mock.patch("identity_manager.get_identity_credentials",
                        return_value=None):
            u, p, s = core_engine.get_device_credentials(
                {"Profile": "identity:gone"})
        self.assertEqual(u, core_engine.DEFAULT_USERNAME)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run — expect FAIL** (`ModuleNotFoundError: identity_manager`)

Run: `uv run python test_identity_manager.py`

- [ ] **Step 3: Implement `identity_manager.py`**

```python
# -*- coding: utf-8 -*-
"""Identita' (profili credenziali) legate a un tenant.

Ogni identita' e' un set nominato di credenziali SSH (username, password,
enable secret) riusabile dai device dell'inventario tramite il valore
'identity:<id>' del campo Profile in hosts.csv. Le password sono cifrate
con Fernet (crypto_vault) come per hosts.csv; le API di lettura non
espongono MAI i segreti.
"""
import os
import json
import uuid
import threading

import data_config
from crypto_vault import encrypt_password, decrypt_password

IDENTITIES_JSON = data_config.get_path("identities.json")
_lock = threading.RLock()


def _load() -> list:
    if not os.path.exists(IDENTITIES_JSON):
        return []
    with open(IDENTITIES_JSON, "r", encoding="utf-8") as f:
        return json.load(f).get("identities", [])


def _save(identities: list):
    from inventory_manager import safe_json_write
    safe_json_write(IDENTITIES_JSON, {"identities": identities})


def _devices_using(identity_id: str) -> list:
    import inventory_manager
    key = f"identity:{identity_id}"
    return [d.get("IP") for d in inventory_manager.get_all_devices()
            if d.get("Profile") == key]


def get_identities(tenant: str = None) -> list:
    """Lista identita' SENZA segreti; opzionale filtro per tenant."""
    with _lock:
        rows = _load()
    if tenant:
        rows = [r for r in rows if r.get("tenant") == tenant]
    return [{"id": r["id"], "name": r["name"], "tenant": r["tenant"],
             "username": r["username"],
             "devices_using": len(_devices_using(r["id"]))} for r in rows]


def get_identity_credentials(identity_id: str):
    """(username, password, secret) in chiaro — SOLO per uso interno
    (connessioni agli apparati). None se l'identita' non esiste."""
    with _lock:
        for r in _load():
            if r["id"] == identity_id:
                return (r["username"],
                        decrypt_password(r.get("password_enc", "")),
                        decrypt_password(r.get("secret_enc", "")))
    return None


def add_identity(name: str, tenant: str, username: str,
                 password: str, secret: str) -> dict:
    ident = {
        "id": uuid.uuid4().hex,
        "name": name.strip(),
        "tenant": tenant,
        "username": username,
        "password_enc": encrypt_password(password),
        "secret_enc": encrypt_password(secret),
    }
    with _lock:
        rows = _load()
        rows.append(ident)
        _save(rows)
    return {"id": ident["id"], "name": ident["name"], "tenant": tenant}


def update_identity(identity_id: str, name: str, tenant: str,
                    username: str, password: str, secret: str) -> bool:
    with _lock:
        rows = _load()
        for r in rows:
            if r["id"] == identity_id:
                r.update(name=name.strip(), tenant=tenant, username=username,
                         password_enc=encrypt_password(password),
                         secret_enc=encrypt_password(secret))
                _save(rows)
                return True
    return False


def delete_identity(identity_id: str):
    """Ritorna (ok, devices_bloccanti). Rifiuta se qualche device usa
    l'identita' (il chiamante risponde 409 con la lista IP)."""
    devices = _devices_using(identity_id)
    if devices:
        return False, devices
    with _lock:
        rows = [r for r in _load() if r["id"] != identity_id]
        _save(rows)
    return True, []
```

- [ ] **Step 4: Modify `core_engine.get_device_credentials`** (core_engine.py:77)

```python
def get_device_credentials(device):
    profile = device.get('Profile', 'custom').lower()
    if profile == 'default':
        return DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_SECRET
    if profile.startswith('identity:'):
        # Identita' tenant (identity_manager): fallback ai default se
        # l'identita' non esiste piu' (non dovrebbe: delete bloccata se in uso).
        import identity_manager
        creds = identity_manager.get_identity_credentials(
            device.get('Profile', '')[len('identity:'):])
        if creds:
            return creds
        return DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_SECRET
    username = device.get('Username') or DEFAULT_USERNAME
    password = decrypt_password(device.get('Password')) or DEFAULT_PASSWORD
    secret   = decrypt_password(device.get('Enable Secret')) or DEFAULT_SECRET
    return username, password, secret
```

Note: slice the ORIGINAL (non-lowercased) Profile value for the id — uuid hex is lowercase anyway, but keep it robust as shown above.

- [ ] **Step 5: Run tests — expect PASS**

Run: `uv run python test_identity_manager.py` → `OK`

- [ ] **Step 6: Add endpoints to `routers/provisioner.py`** (append at end of file)

```python
# ── Identita' tenant (profili credenziali riusabili) ────────────────────────
import identity_manager

class IdentitySchema(BaseModel):
    name: str
    tenant: str
    username: str
    password: str
    enable_secret: str = ""

@router.get("/api/identities")
def identities_list(tenant: Optional[str] = None, current_user = Depends(require_operator)):
    """Lista identita' (senza segreti), opzionalmente filtrate per tenant."""
    return {"identities": identity_manager.get_identities(tenant=tenant)}

@router.post("/api/identities")
def identities_create(payload: IdentitySchema, current_user = Depends(require_operator)):
    if not payload.name.strip() or not payload.username or not payload.password:
        raise HTTPException(status_code=400, detail="Nome, username e password sono obbligatori.")
    ident = identity_manager.add_identity(payload.name, payload.tenant,
                                          payload.username, payload.password,
                                          payload.enable_secret)
    log_audit(f"Identita' '{payload.name}' (tenant '{payload.tenant}') creata da '{current_user.get('sub')}'.")
    return {"status": "success", "id": ident["id"]}

@router.put("/api/identities/{identity_id}")
def identities_update(identity_id: str, payload: IdentitySchema,
                      current_user = Depends(require_operator)):
    if not payload.name.strip() or not payload.username or not payload.password:
        raise HTTPException(status_code=400, detail="Nome, username e password sono obbligatori.")
    if not identity_manager.update_identity(identity_id, payload.name, payload.tenant,
                                            payload.username, payload.password,
                                            payload.enable_secret):
        raise HTTPException(status_code=404, detail="Identita' non trovata.")
    log_audit(f"Identita' '{payload.name}' aggiornata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.delete("/api/identities/{identity_id}")
def identities_delete(identity_id: str, current_user = Depends(require_operator)):
    ok, devices = identity_manager.delete_identity(identity_id)
    if not ok:
        raise HTTPException(status_code=409,
                            detail={"error": "in_use", "devices": devices})
    log_audit(f"Identita' '{identity_id}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}
```

- [ ] **Step 7: Smoke check imports**

Run: `uv run python -c "import identity_manager, routers.provisioner, core_engine; print('ok')"`
Expected: `ok`

- [ ] **Step 8: Run full test again + commit**

```bash
uv run python test_identity_manager.py
git add identity_manager.py test_identity_manager.py routers/provisioner.py core_engine.py
git commit -m "feat(identities): profili credenziali per tenant con endpoint CRUD e risoluzione identity:<id>"
```

---

### Task B: Provisioning tab UI — two-column reorg + identities panel

**Files:**
- Modify: `templates/dashboard.html` — tab-provisioning markup (lines ~1163-1296), device CRUD JS (~4937-5100), `loadProvisioningTab` (~5751), i18n IT (~2880-3300) and EN (~3550-3970) blocks.

**Interfaces:**
- Consumes: Task A endpoints exactly as specified in Task A "Produces".
- Produces: `devProfile` select values are now `default` | `identity:<id>` | `custom` — the save payload (`profile` field of POST /api/add-device) carries the value as-is; backend already accepts arbitrary Profile strings.

**Layout target** (replace the single `<article class="panel requires-write">` block at ~1173-1295):

```html
<div style="display:grid; grid-template-columns: minmax(380px, 1fr) minmax(320px, 420px); gap:18px; align-items:start;" class="prov-grid">
  <article class="panel requires-write"><!-- LEFT: device form, fieldset sections --></article>
  <article class="panel requires-write" id="identitiesPanel"><!-- RIGHT: identities manager --></article>
</div>
```

Add a media query near other responsive CSS: `@media (max-width: 1100px) { .prov-grid { grid-template-columns: 1fr !important; } }`

- [ ] **Step 1: Restructure left panel into sections**

Keep ALL existing element ids (devGroupSelect, devIp, devTransports + tr* inputs, devVendor, devProfile, customCredsForm, devUser, devPass, devSecret, btnSaveDevice, btnCancelEditDevice, devEditNotice, devFormTitle) so existing JS keeps working. Wrap into four sections, each headed:

```html
<h4 style="font-size:12px; text-transform:uppercase; letter-spacing:.08em; color:var(--text-muted); margin:14px 0 8px; display:flex; align-items:center; gap:6px;">
  <i class="fa-solid fa-building"></i> <span data-i18n="secTenant">1 · Tenant</span>
</h4>
```

Sections: `secTenant` (devGroupSelect + inline new-tenant), `secDevice` (devIp + devVendor), `secConnectivity` (devTransports details), `secCredentials` (devProfile + customCredsForm + identity hint).

- [ ] **Step 2: Inline "+ new tenant" replaces bottom group section**

Delete the bottom "Aggiungi Nuovo Gruppo" block (lines ~1285-1294). Next to devGroupSelect add:

```html
<div style="display:flex; gap:8px; align-items:center;">
  <select id="devGroupSelect" style="flex:1;"></select>
  <button class="btn btn-secondary" id="btnInlineNewTenant" type="button" title="Nuovo tenant" style="white-space:nowrap;"><i class="fa-solid fa-plus"></i></button>
</div>
<div id="inlineNewTenantRow" style="display:none; margin-top:8px; gap:8px;">
  <input id="newGroupName" type="text" placeholder="Es. Tenant_Torino" style="flex:1; padding-left:12px;">
  <button class="btn btn-primary" id="btnCreateGroup" style="background:var(--cta); color:var(--cta-text);" data-i18n="btnCreateGroup"><i class="fa-solid fa-folder-plus"></i> Crea Gruppo</button>
</div>
```

JS: `btnInlineNewTenant` toggles `inlineNewTenantRow` display flex/none. Existing `btnCreateGroup` handler keeps working (ids unchanged). After successful creation, refresh devGroupSelect and select the new tenant.

- [ ] **Step 3: IP inline validation + duplicate hint**

Add under devIp: `<div id="devIpHint" style="display:none; font-size:12px; margin-top:4px;"></div>`

```javascript
document.getElementById('devIp').addEventListener('input', () => {
    const v = document.getElementById('devIp').value.trim();
    const hint = document.getElementById('devIpHint');
    const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!v) { hint.style.display = 'none'; return; }
    if (!ipRe.test(v) || v.split('.').some(o => +o > 255)) {
        hint.style.display = 'block'; hint.style.color = 'var(--danger)';
        hint.innerHTML = i18n[currentLang].hintIpInvalid;
        return;
    }
    const existing = (globalDevices || []).find(d => d.IP === v);
    if (existing && !editingDeviceIp) {
        hint.style.display = 'block'; hint.style.color = 'var(--warning)';
        hint.innerHTML = `${i18n[currentLang].hintIpExists} <a href="#" onclick="editDevice('${v}'); return false;">${i18n[currentLang].hintIpEditLink}</a>`;
    } else { hint.style.display = 'none'; }
});
```

(Verify the actual global device list variable name and edit function name in dashboard.html — the edit prefill function near line 5047 — and use those.)

- [ ] **Step 4: Identity options in devProfile**

```javascript
// Carica le identita' del tenant selezionato nella select devProfile,
// preservando default/custom. Chiamata al load della tab e al cambio tenant.
async function refreshIdentityOptions(preserve) {
    const tenant = document.getElementById('devGroupSelect').value;
    const sel = document.getElementById('devProfile');
    const keep = preserve || sel.value;
    const res = await apiFetch('/api/identities?tenant=' + encodeURIComponent(tenant));
    const idents = res && res.ok ? (await res.json()).identities : [];
    sel.innerHTML = `<option value="default">${i18n[currentLang].optProfileDefault.replace(/<[^>]*>/g,'')}</option>` +
        idents.map(i => `<option value="identity:${i.id}">${escapeHtml(i.name)} (${escapeHtml(i.username)})</option>`).join('') +
        `<option value="custom">${i18n[currentLang].optProfileCustom.replace(/<[^>]*>/g,'')}</option>`;
    sel.value = Array.from(sel.options).some(o => o.value === keep) ? keep : 'default';
    document.getElementById('customCredsForm').style.display = sel.value === 'custom' ? 'block' : 'none';
    window._tenantIdentities = idents;
}
document.getElementById('devGroupSelect').addEventListener('change', () => { refreshIdentityOptions(); renderIdentitiesPanel(); });
```

Call `refreshIdentityOptions()` and `renderIdentitiesPanel()` inside `loadProvisioningTab()` (line ~5751). The existing devProfile change listener (line 4939) already hides customCredsForm for non-custom values — identity values need no extra fields.

- [ ] **Step 5: Right panel — identities manager**

```html
<article class="panel requires-write" id="identitiesPanel">
  <h3 style="font-size:16px; margin-bottom:6px;" data-i18n="titleIdentities"><i class="fa-solid fa-id-badge"></i> Identità del Tenant</h3>
  <p style="font-size:13px; color:var(--text-muted); margin-bottom:12px;" data-i18n="descIdentities">Profili credenziali riusabili, legati al tenant selezionato nel form.</p>
  <div class="table-wrap">
    <table>
      <thead><tr><th data-i18n="thIdentName">Nome</th><th>Username</th><th data-i18n="thIdentDevices">Device</th><th data-i18n="thIdentActions">Azioni</th></tr></thead>
      <tbody id="identitiesTableBody"></tbody>
    </table>
  </div>
  <div id="identityForm" style="display:none; border-left:2px solid var(--primary); padding-left:10px; margin-top:12px;">
    <input type="hidden" id="identEditId">
    <div class="form-group"><label data-i18n="thIdentName">Nome</label><input id="identName" type="text" style="padding-left:12px;"></div>
    <div class="form-group"><label>Username</label><input id="identUser" type="text" style="padding-left:12px;"></div>
    <div class="form-group"><label data-i18n="lblPass">Password</label><input id="identPass" type="password" style="padding-left:12px;"></div>
    <div class="form-group"><label data-i18n="lblSecret">Enable Secret</label><input id="identSecret" type="password" style="padding-left:12px;"></div>
    <button class="btn btn-primary" id="btnSaveIdentity" data-i18n="btnSaveIdentity"><i class="fa-solid fa-floppy-disk"></i> Salva Identità</button>
    <button class="btn btn-secondary" id="btnCancelIdentity" data-i18n="btnCancelIdentity"><i class="fa-solid fa-xmark"></i> Annulla</button>
  </div>
  <button class="btn btn-secondary" id="btnNewIdentity" style="margin-top:10px;" data-i18n="btnNewIdentity"><i class="fa-solid fa-plus"></i> Nuova Identità</button>
</article>
```

```javascript
function renderIdentitiesPanel() {
    const body = document.getElementById('identitiesTableBody');
    const idents = window._tenantIdentities || [];
    body.innerHTML = idents.length ? idents.map(i => `<tr>
        <td>${escapeHtml(i.name)}</td>
        <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(i.username)}</td>
        <td>${i.devices_using}</td>
        <td>
          <button class="btn-icon" onclick="editIdentity('${i.id}')" title="Edit"><i class="fa-solid fa-pen"></i></button>
          <button class="btn-icon" onclick="deleteIdentity('${i.id}')" title="Delete"><i class="fa-solid fa-trash"></i></button>
        </td></tr>`).join('')
      : `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:16px; font-size:13px;">${i18n[currentLang].emptyIdentities}</td></tr>`;
}

function editIdentity(id) {
    const i = (window._tenantIdentities || []).find(x => x.id === id);
    if (!i) return;
    document.getElementById('identEditId').value = id;
    document.getElementById('identName').value = i.name;
    document.getElementById('identUser').value = i.username;
    document.getElementById('identPass').value = '';
    document.getElementById('identSecret').value = '';
    document.getElementById('identityForm').style.display = 'block';
}

async function deleteIdentity(id) {
    if (!confirm(i18n[currentLang].confirmDeleteIdentity)) return;
    const res = await apiFetch('/api/identities/' + id, { method: 'DELETE' });
    if (res && res.status === 409) {
        const err = await res.json();
        alert(i18n[currentLang].alertIdentityInUse + '\n' + (err.detail.devices || []).join(', '));
        return;
    }
    await refreshIdentityOptions(); renderIdentitiesPanel();
}

document.getElementById('btnNewIdentity').addEventListener('click', () => {
    document.getElementById('identEditId').value = '';
    ['identName','identUser','identPass','identSecret'].forEach(i => document.getElementById(i).value = '');
    document.getElementById('identityForm').style.display = 'block';
});
document.getElementById('btnCancelIdentity').addEventListener('click', () =>
    document.getElementById('identityForm').style.display = 'none');
document.getElementById('btnSaveIdentity').addEventListener('click', async () => {
    const id = document.getElementById('identEditId').value;
    const payload = {
        name: document.getElementById('identName').value.trim(),
        tenant: document.getElementById('devGroupSelect').value,
        username: document.getElementById('identUser').value.trim(),
        password: document.getElementById('identPass').value,
        enable_secret: document.getElementById('identSecret').value,
    };
    if (!payload.name || !payload.username || !payload.password) {
        alert(i18n[currentLang].alertIdentityFields); return;
    }
    const res = await apiFetch(id ? '/api/identities/' + id : '/api/identities', {
        method: id ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (res && res.ok) {
        document.getElementById('identityForm').style.display = 'none';
        await refreshIdentityOptions(); renderIdentitiesPanel();
    } else if (res) {
        const err = await res.json();
        alert(err.detail || 'Errore');
    }
});
```

- [ ] **Step 6: i18n keys (IT + EN)**

Add to BOTH dictionaries (values translated appropriately):
`secTenant, secDevice, secConnectivity, secCredentials, titleIdentities, descIdentities, thIdentName, thIdentDevices, thIdentActions, btnNewIdentity, btnSaveIdentity, btnCancelIdentity, emptyIdentities, confirmDeleteIdentity, alertIdentityInUse, alertIdentityFields, hintIpInvalid, hintIpExists, hintIpEditLink`.
IT examples: `hintIpInvalid: "Indirizzo IP non valido."`, `hintIpExists: "IP già in inventario."`, `hintIpEditLink: "Passa a modifica"`, `alertIdentityInUse: "Identità in uso dai seguenti device:"`.

- [ ] **Step 7: Verify + commit**

Run app briefly (`uv run python app_server.py` or repo's run entry), open tab, check: sections render, identity CRUD works against live endpoints, saving device with identity profile writes `identity:<id>` to hosts.csv.
Run existing UI tests if present: `uv run python test_ui_revamp.py` — must pass (update selectors it asserts on if the reorg broke any, keeping test intent).

```bash
git add templates/dashboard.html
git commit -m "feat(provisioning-ui): layout a due colonne, sezioni, gestione identita' tenant"
```

---

### Task C: Threat Intel tab — Vendor Watch sub-tab + Matcher rework

**Files:**
- Modify: `templates/dashboard.html` — tab-security markup (~1581-1610), threat JS (~11174 onwards), i18n IT+EN blocks.
- Reference (read-only): `c:\Users\vidhi\dev_ved\euvd_dashboard\dashboard.html` (source of Vendor Watch UI/logic to port).

**Interfaces:**
- Consumes: existing `GET /api/search` proxy (routers/backup.py — EUVD params: vendor, fromScore, toScore, fromEpss, exploited, fromDate, toDate, size, text); `GET /api/local-devices`; `GET /api/network-map?group=`; `GET /api/vendors` (vendor registry with euvd_term); existing category assignments endpoint (find with grep `category` in routers/catalog.py — used by inventory table); existing JS: `runManagedVulnCheck`, `runDiscoveredVulnCheck`, `extractReadableVersion`, `escapeHtml`, `apiFetch`, `globalGroups`.
- Produces: nothing consumed by other tasks.

- [ ] **Step 1: Sub-tab switcher in tab-security**

After the hero (line ~1590), add:

```html
<div style="display:flex; gap:8px; margin-bottom:16px;">
  <button class="btn btn-secondary ti-subtab active" id="tiTabMatcher" onclick="tiSwitchView('matcher')" data-i18n="tiTabMatcher"><i class="fa-solid fa-crosshairs"></i> Vulnerability Matcher</button>
  <button class="btn btn-secondary ti-subtab" id="tiTabWatch" onclick="tiSwitchView('watch')" data-i18n="tiTabWatch"><i class="fa-solid fa-satellite-dish"></i> Vendor Watch</button>
</div>
<div id="tiViewMatcher"><!-- existing controls + securityTriageContainer moved here --></div>
<div id="tiViewWatch" style="display:none;"><!-- Vendor Watch UI --></div>
```

```javascript
function tiSwitchView(v) {
    document.getElementById('tiViewMatcher').style.display = v === 'matcher' ? 'block' : 'none';
    document.getElementById('tiViewWatch').style.display = v === 'watch' ? 'block' : 'none';
    document.getElementById('tiTabMatcher').classList.toggle('active', v === 'matcher');
    document.getElementById('tiTabWatch').classList.toggle('active', v === 'watch');
    if (v === 'watch' && !window._vwLoaded) { vwInit(); window._vwLoaded = true; }
}
```

Style `.ti-subtab.active` with primary border/color like the analyzer sub-tab buttons (reuse that CSS class if one exists; check `caSwitchFwView` usage).

- [ ] **Step 2: Vendor Watch markup (`tiViewWatch`)**

Port from euvd_dashboard/dashboard.html, restyled with SentinelNet vars:

```html
<div class="panel" style="margin-bottom:14px;">
  <div id="vwVendorBtns" style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px;"></div>
  <div style="display:flex; gap:12px; flex-wrap:wrap; align-items:end;">
    <div class="form-group" style="margin:0;"><label data-i18n="vwLblMinCvss">CVSS min</label>
      <select id="vwMinScore"><option value="">—</option><option>7</option><option>8</option><option selected>9</option></select></div>
    <div class="form-group" style="margin:0;"><label>EPSS min %</label>
      <input id="vwMinEpss" type="number" min="0" max="100" value="" style="width:90px; padding-left:10px;"></div>
    <label style="display:flex; align-items:center; gap:6px; font-size:13px;">
      <input type="checkbox" id="vwExploited" style="accent-color:var(--primary);"> <span data-i18n="vwLblExploited">Solo sfruttate</span></label>
    <div class="form-group" style="margin:0;"><label data-i18n="vwLblFrom">Da</label><input id="vwFromDate" type="date"></div>
    <div class="form-group" style="margin:0;"><label data-i18n="vwLblSearch">Cerca</label><input id="vwText" type="text" placeholder="CVE, prodotto..." style="padding-left:10px;"></div>
    <button class="btn btn-primary" id="vwRefresh" onclick="vwFetch()"><i class="fa-solid fa-rotate"></i></button>
  </div>
</div>
<div class="panel">
  <div id="vwStatus" style="font-size:13px; color:var(--text-muted); margin-bottom:10px;"></div>
  <div class="table-wrap"><table>
    <thead><tr><th>CVE / EUVD</th><th data-i18n="vwThProduct">Prodotto</th><th data-i18n="vwThSeverity">Severità</th><th>CVSS</th><th>EPSS</th><th data-i18n="vwThExploited">Sfruttata</th><th data-i18n="vwThPublished">Pubblicata</th></tr></thead>
    <tbody id="vwBody"></tbody></table></div>
</div>
<div id="vwDrawer" style="display:none; position:fixed; top:0; right:0; bottom:0; width:min(480px, 90vw); background:var(--surface); border-left:1px solid var(--border); z-index:1000; padding:20px; overflow-y:auto;"></div>
```

- [ ] **Step 3: Vendor Watch JS**

Port the fetch/normalize/render logic from euvd_dashboard (its `normalize` around line 1053, query building around 1119). Key adaptations:
- Vendor buttons from registry: on `vwInit()`, `apiFetch('/api/vendors')`, render one button per vendor with a non-empty `euvd_term`; clicking sets `window._vwVendor = euvd_term` and calls `vwFetch()`. First vendor auto-selected.
- Query: `/api/search?vendor=<term>&fromScore=<min>&size=40` + `exploited=true` when checked, `fromDate` when set, `fromEpss` when set. Use `apiFetch` (authenticated), NOT bare fetch.
- Normalize each item exactly as euvd_dashboard does: `cve = item.aliases/id fields`, `euvd = item.id||euvdId||enisaId`, nested vendor from `item.enisaIdVendor[0].vendor.name`, product from `item.enisaIdProduct[0].product.name` (copy the `pick()` helper and normalize function from the source file, adapting names to `vw` prefix).
- Text filter client-side over loaded rows (like source line 1162).
- Row click → fill `vwDrawer` with CVE/EUVD ids, severity, CVSS, EPSS, summary, published/updated dates, reference links (`item.references` split by newline, rendered as `<a target="_blank">`), and a close button.
- Severity badge colors: reuse existing badge/severity styles from the matcher results (grep `vuln-card`/severity render in `runManagedVulnCheck`) instead of importing euvd_dashboard CSS.

- [ ] **Step 4: Matcher rework — tenant → category grouping + batch analyze**

Rewrite `startThreatScan()` device rendering (keep data fetching as-is):

```javascript
// Raggruppa: tenant → categoria dispositivo → [device cards]
// catAssignments: mappa node_id/IP → {category, subcategory} dal registro categorie
async function startThreatScan() {
    if (window._threatScanBusy) return;
    window._threatScanBusy = true;
    try {
        const container = document.getElementById("securityTriageContainer");
        // ... fetch /api/local-devices come oggi + fetch assegnazioni categorie ...
        // struttura: { [tenant]: { [categoria]: [deviceEntry] } }
        // deviceEntry = {ip, vendor, version, discovered:false} oppure nodo discovered
        // Render: per ogni tenant un blocco con header:
        //   <h3>tenant</h3> + <button Analizza tutti> + <span id="rollup-<tenant>">
        //   dentro, per ogni categoria: <h4>categoria</h4> + card device esistenti
        // Le card device restano quelle attuali (btn-mgd-*/runManagedVulnCheck).
    } finally { window._threatScanBusy = false; }
}

// Analizza tutti i device online di un tenant, max 4 query concorrenti.
async function analyzeTenant(tenant) {
    const btns = Array.from(document.querySelectorAll(
        `#tenant-block-${cssSafe(tenant)} button[id^="btn-mgd-"], #tenant-block-${cssSafe(tenant)} button[id^="btn-disc-"]`));
    const queue = btns.slice();
    let critical = 0, high = 0, exploited = 0, done = 0;
    const rollup = document.getElementById('rollup-' + cssSafe(tenant));
    async function worker() {
        while (queue.length) {
            const b = queue.shift();
            b.click();                      // riusa runManagedVulnCheck/runDiscoveredVulnCheck
            await waitForResult(b);         // poll finché lo status del device è settled
            done++;
            rollup.textContent = `${done}/${btns.length}`;
        }
    }
    await Promise.all([worker(), worker(), worker(), worker()]);
    // Rollup finale: conta le severità dai badge renderizzati nel blocco tenant
    const block = document.getElementById('tenant-block-' + cssSafe(tenant));
    critical = block.querySelectorAll('[data-sev="critical"]').length;
    high = block.querySelectorAll('[data-sev="high"]').length;
    exploited = block.querySelectorAll('[data-exploited="1"]').length;
    rollup.innerHTML = `<span style="color:var(--danger);">${critical} critical</span> · ${high} high · ${exploited} exploited`;
}
```

Implementation notes for the executor:
- `cssSafe(s)` = `s.replace(/[^a-zA-Z0-9]/g, '-')` (add helper).
- `waitForResult(btn)`: `runManagedVulnCheck` disables the button and writes into `results-<ip>`/`status-<ip>`; poll every 500 ms until the button is re-enabled or its status element shows a settled state, timeout 60 s. Read the actual behavior of `runManagedVulnCheck` (just below line 11332) and key off what it really does — if it doesn't re-enable, key off the results div becoming non-empty.
- For severity counting, when rendering vulnerability rows in `runManagedVulnCheck`/`runDiscoveredVulnCheck` results, add `data-sev="<severity>"` and `data-exploited="1|0"` attributes to each vuln row so the rollup can count them (small, contained edit to the render code).
- Category lookup: use the endpoint the inventory table uses for categories (grep for `category` fetch in dashboard.html); devices with no assignment go under key `Uncategorized` (i18n `tiCatUncategorized`).
- Discovered neighbors (when checkbox on) join the same tenant blocks under their `n.group`, category `Discovered`.

- [ ] **Step 5: i18n keys (IT + EN)**

`tiTabMatcher, tiTabWatch, vwLblMinCvss, vwLblExploited, vwLblFrom, vwLblSearch, vwThProduct, vwThSeverity, vwThExploited, vwThPublished, vwStatusLoading, vwStatusRows, vwStatusError, btnAnalyzeTenant ("Analizza tutti"/"Analyze all"), tiCatUncategorized ("Senza categoria"/"Uncategorized"), tiCatDiscovered`.

- [ ] **Step 6: Verify + commit**

Run app, open Threat Intel: Vendor Watch loads rows from EUVD for each registry vendor, filters work, drawer opens. Matcher: devices grouped tenant→category, per-tenant Analyze-all runs throttled and shows rollup. Per-device Analyze unchanged.

```bash
git add templates/dashboard.html
git commit -m "feat(threat-intel): sub-tab Vendor Watch (EUVD) e matcher raggruppato per tenant/categoria con analisi batch"
```

---

### Task D: Final verification + exe rebuild

**Files:** none new.

- [ ] **Step 1: Run all repo test scripts touched or adjacent**

```bash
uv run python test_identity_manager.py
uv run python test_ui_revamp.py
uv run python test_provisioning_secrets.py
```
Expected: all `OK`.

- [ ] **Step 2: graphify update** (skip if CLI missing)

Run: `graphify update .` — ignore failure if command not found.

- [ ] **Step 3: Rebuild exe (repo rule: always final step)**

Run: `uv run pyinstaller SentinelNet.spec`
Expected: build completes, `dist/SentinelNet/SentinelNet.exe` (or spec's output) produced.

- [ ] **Step 4: Commit any remaining changes**

```bash
git status --short
git add -A && git commit -m "chore: rebuild exe dopo identities + threat intel revamp"
```
(Only if build artifacts/spec-adjacent files are tracked; otherwise skip commit.)
