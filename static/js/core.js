// --- SIDEBAR RAIL (collasso a icone) ---

const SIDEBAR_COLLAPSED_KEY = 'sidebarCollapsed';

// Con la rail collassata restano solo le icone: il tooltip nativo è l'unica
// etichetta disponibile. Il testo viene DERIVATO dal label già tradotto, così
// non esiste una seconda copia della stringa da tenere allineata: basta
// richiamare questa funzione dopo ogni cambio lingua.
function syncNavTooltips() {
    const collapsed = document.body.classList.contains('sidebar-collapsed');
    document.querySelectorAll('.sidenav .nav-item').forEach(btn => {
        const label = btn.querySelector('.nav-left');
        if (!label) return;
        const text = label.textContent.trim();
        if (collapsed && text) btn.setAttribute('title', text);
        else btn.removeAttribute('title');
    });
}

function applySidebarCollapsed(collapsed) {
    document.body.classList.toggle('sidebar-collapsed', collapsed);
    const btn = document.getElementById('sidebarToggle');
    if (btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    syncNavTooltips();
}

function toggleSidebar() {
    const collapsed = !document.body.classList.contains('sidebar-collapsed');
    try { localStorage.setItem(SIDEBAR_COLLAPSED_KEY, collapsed ? '1' : '0'); } catch (e) { }
    applySidebarCollapsed(collapsed);
}

// --- RESA CHIARA / SCURA ---
// Il quadro esiste in due rese reali: targa incisa e schermo SCADA. Senza
// preferenza salvata si segue il sistema operativo, quindi il primo click
// deve partire dalla polarità effettivamente a schermo, non da un default.
const THEME_KEY = 'sentinelnet_theme';
const UI_VARIANT_KEY = 'sentinelnet_ui_variant';

function toggleTheme() {
    const explicit = document.documentElement.getAttribute('data-theme');
    const current = explicit
        || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem(THEME_KEY, next); } catch (e) { }
}

function applyUiVariant(variant, saveServer = false) {
    const valid = ['default', 'design-1', 'design-2', 'design-3'];
    const selected = valid.includes(variant) ? variant : 'default';

    document.documentElement.setAttribute('data-ui-variant', selected);
    try { localStorage.setItem(UI_VARIANT_KEY, selected); } catch (e) { }

    let linkEl = document.getElementById('theme-variant-stylesheet');
    if (selected === 'default') {
        if (linkEl) linkEl.remove();
    } else {
        if (!linkEl) {
            linkEl = document.createElement('link');
            linkEl.id = 'theme-variant-stylesheet';
            linkEl.rel = 'stylesheet';
            document.head.appendChild(linkEl);
        }
        linkEl.href = `/static/css/themes/${selected}.css`;
    }

    const selectEl = document.getElementById('uiVariantSelect');
    if (selectEl && selectEl.value !== selected) {
        selectEl.value = selected;
    }

    if (saveServer) {
        const headers = { 'Content-Type': 'application/json', 'X-Requested-With': 'SentinelNet' };
        fetch('/api/settings/ui-variant', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ ui_variant: selected })
        }).catch(err => console.warn('Save UI variant failed:', err));
    }
}

function initUiVariant() {
    let saved = null;
    try { saved = localStorage.getItem(UI_VARIANT_KEY); } catch (e) { }
    if (saved) {
        applyUiVariant(saved);
        return;
    }
    fetch('/api/settings/ui-variant', {
        headers: { 'X-Requested-With': 'SentinelNet' }
    })
        .then(r => r.ok ? r.json() : null)
        .then(data => {
            if (data && data.ui_variant) {
                applyUiVariant(data.ui_variant);
            }
        })
        .catch(() => {});
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initUiVariant);
} else {
    initUiVariant();
}

// Canvas e librerie esterne (vis.js, xterm.js) vogliono un colore vero: una
// stringa 'var(--x)' non la sanno risolvere. Qui il token viene letto dallo
// stile calcolato, così anche la mappa e il terminale seguono la resa attiva.
function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback || '#000000';
}

let globalDevices = [];
let globalGroups = {};
let globalVendors = {};
let globalVersions = {}; // Cache globale per lo stato delle scansioni (ottimizzazione UI)
let currentRole = 'viewer';   // ruolo dell'utente loggato (admin/operator/viewer)
let currentUsername = '';
let appLoading = false;

// --- AUTENTICAZIONE E UTILITY ---

// Escaping HTML per tutti i valori dinamici (hostname dai config, nomi gruppo/vendor,
// descrizioni EUVD): previene markup rotto e stored XSS nelle tabelle e nei tooltip.
function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Neutralizza la formula injection nei CSV: i valori che iniziano con = + - @ TAB CR
// possono essere interpretati come formule da Excel/LibreOffice. L'apostrofo iniziale
// forza il testo; la quotatura CSV avviene dopo per mantenere l'apostrofo nella cella.
function csvCell(v) {
    let s = Array.isArray(v) ? v.join(' ') : (v === null || v === undefined ? '' : String(v));
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",;\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// ===== Ordinamento generico colonne per TUTTE le tabelle =====
// Click sull'intestazione: ordina crescente/decrescente. Le celle editabili
// (input/select) ordinano per valore del campo
function _cellSortValue(td) {
    if (!td) return '';
    const sv = td.getAttribute('data-sort-value');
    if (sv !== null && sv !== undefined) return String(sv).trim();
    const f = td.querySelector('input, select');
    return f ? String(f.value || '').trim() : td.textContent.trim();
}
function _applySort(table, colIdx, asc) {
    const tbody = table.tBodies[0];
    if (!tbody) return;
    // Una riga di dettaglio (cella unica a tutta larghezza, es. le evidenze
    // aperte nella matrice audit) non e' una voce autonoma: e' la coda della
    // riga che l'ha aperta. Ordinarla da sola la staccava dalla sua regola e
    // la spediva in cima, perche' non ha la colonna su cui si ordina.
    const groups = [];
    Array.from(tbody.rows).forEach(r => {
        if (groups.length && r.cells.length === 1 && r.cells[0].colSpan > 1) {
            groups[groups.length - 1].push(r);
        } else {
            groups.push([r]);
        }
    });
    groups.sort((ga, gb) => {
        const x = _cellSortValue(ga[0].cells[colIdx]);
        const y = _cellSortValue(gb[0].cells[colIdx]);
        const numX = Number(x);
        const numY = Number(y);
        if (x !== '' && y !== '' && !isNaN(numX) && !isNaN(numY)) {
            if (numX === 0 && numY !== 0) return 1;
            if (numY === 0 && numX !== 0) return -1;
            return asc ? numX - numY : numY - numX;
        }
        const c = x.localeCompare(y, undefined, { numeric: true, sensitivity: 'base' });
        return asc ? c : -c;
    });
    const target = groups.flat();
    const current = Array.from(tbody.rows);
    // reapplySort() gira dentro il MutationObserver: riscrivere quando l'ordine
    // e' gia' quello giusto produrrebbe le mutazioni che schedulano la passata
    // successiva, senza mai fermarsi.
    if (target.length === current.length && target.every((r, i) => r === current[i])) return;
    target.forEach(r => tbody.appendChild(r));
}

function sortTableByColumn(table, colIdx, th) {
    const asc = th.getAttribute('data-sort-asc') !== 'true';
    Array.from(table.tHead.rows[0].cells).forEach(c => {
        c.removeAttribute('data-sort-asc');
    });
    th.setAttribute('data-sort-asc', asc ? 'true' : 'false');
    _applySort(table, colIdx, asc);
}

// L'ordine vive solo nel DOM, quindi qualunque re-render lo cancella: la
// matrice audit riscrive tbody.innerHTML dai dati a ogni apertura di dettaglio
// e a ogni cambio filtro, e la tabella tornava all'ordine di partenza sotto gli
// occhi di chi l'aveva appena ordinata. Qui l'ordinamento scelto viene
// riapplicato, conservando il verso: riapplicare non e' cliccare di nuovo.
function reapplySort(table) {
    if (!table.tHead || !table.tHead.rows.length) return;
    const cells = Array.from(table.tHead.rows[0].cells);
    const idx = cells.findIndex(c => c.getAttribute('data-sort-asc') !== null);
    if (idx < 0) return;
    _applySort(table, idx, cells[idx].getAttribute('data-sort-asc') === 'true');
}
function makeTableSortable(table) {
    if (!table || table.dataset.sortable === '1') return;
    if (!table.tHead || !table.tHead.rows.length) return;
    table.dataset.sortable = '1';
    Array.from(table.tHead.rows[0].cells).forEach((th, idx) => {
        if (th.dataset.noSort === '1') return;
        th.setAttribute('data-sortable', '1');
        th.style.cursor = 'pointer';
        th.style.userSelect = 'none';
        // Le intestazioni sono etichette brevi: il nowrap evita che il glifo
        // vada a capo da solo; il margine sinistro del pseudo-elemento non
        // inserisce spazi nel content e quindi non crea punti di rottura.
        th.style.whiteSpace = 'nowrap';
        th.addEventListener('click', () => sortTableByColumn(table, idx, th));
    });
}
function enhanceAllTables(root) {
    (root || document).querySelectorAll('table').forEach(makeTableSortable);
}

// ===== Tastiera sugli elementi cliccabili non nativi =====
// Un onclick su <tr>/<div>/<span> non e' raggiungibile da tastiera: la matrice
// audit, le righe della topologia e la client map si aprivano solo col mouse
// (WCAG 2.1.1 Keyboard). Invece di correggere ogni punto di render, gli
// elementi vengono resi focusabili qui, dove passa tutto il DOM generato.
const NATIVE_INTERACTIVE = 'a[href], button, input, select, textarea, summary, [contenteditable]';
function makeClickablesFocusable(root) {
    (root || document).querySelectorAll('[onclick]').forEach(el => {
        if (el.dataset.kbd === '1' || el.matches(NATIVE_INTERACTIVE)) return;
        el.dataset.kbd = '1';
        if (!el.hasAttribute('tabindex')) el.tabIndex = 0;
        // Una riga o una cella restano tali: role="button" su <tr>/<td>
        // romperebbe la struttura di tabella annunciata dallo screen reader.
        if (!el.hasAttribute('role') && el.tagName !== 'TR' && el.tagName !== 'TD') {
            el.setAttribute('role', 'button');
        }
    });
}
document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const el = e.target;
    if (!(el instanceof Element) || el.dataset.kbd !== '1') return;
    e.preventDefault();          // lo spazio non deve scorrere la pagina
    el.click();
});

function initSortableTables() {
    enhanceAllTables(document);
    makeClickablesFocusable(document);
    // Una passata per frame invece di una per nodo inserito: il render di una
    // tabella lunga produce centinaia di mutazioni, e ognuna rilanciava un
    // querySelectorAll sull'intero sottoalbero.
    let scheduled = false;
    const obs = new MutationObserver(() => {
        if (scheduled) return;
        scheduled = true;
        requestAnimationFrame(() => {
            scheduled = false;
            enhanceAllTables(document);
            makeClickablesFocusable(document);
            document.querySelectorAll('table[data-sortable="1"]').forEach(reapplySort);
        });
    });
    obs.observe(document.body, { childList: true, subtree: true });
}
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSortableTables);
} else {
    initSortableTables();
}

// ===== Port Config Modal (promosso da static/js/topology.js: usato anche
// dal tab MAC-tracker/ARP inline e da static/js/config-analyzer.js) =====
// Espande le abbreviazioni comuni delle interfacce ('Gi1/0/5' -> 'GigabitEthernet1/0/5').
// Speculare a expand_iface() di mac_collector.py: tenerli allineati.
function expandIface(name) {
    if (!name) return '';
    name = String(name).trim();
    const abbr = [
        [/^(?:GigabitEthernet|Gi)(?=\d)/i, 'GigabitEthernet'],
        [/^(?:TenGigabitEthernet|TenGigE|Te|XGi|10Ge)(?=\d)/i, 'TenGigabitEthernet'],
        [/^(?:TwentyFiveGigE|Twe|25Ge)(?=\d)/i, 'TwentyFiveGigE'],
        [/^(?:FortyGigabitEthernet|FortyGigE|Fo|40Ge)(?=\d)/i, 'FortyGigE'],
        [/^(?:HundredGigE|Hu|100Ge)(?=\d)/i, 'HundredGigE'],
        [/^(?:FastEthernet|Fa|fe)(?=\d)/i, 'FastEthernet'],
        [/^(?:Ethernet|Eth|Et|e)(?=\d)/i, 'Ethernet'],
        [/^(?:Port-channel|Port-Channel|Po)(?=\d)/i, 'Port-channel'],
    ];
    for (const [pat, full] of abbr) {
        if (pat.test(name)) return name.replace(pat, full);
    }
    return name;
}

function getAuthHeaders() {
    // Autenticazione via cookie HttpOnly (impostato dal server al login).
    // L'header custom è la prova anti-CSRF sulle richieste che modificano stato.
    return { "X-Requested-With": "SentinelNet" };
}

// Sessione confermata dal server (auth/me ok). Distingue "non ancora
// loggato" — 401 pre-login, da ignorare in silenzio — da "sessione scaduta"
// durante il lavoro, che invece forza il logout. Senza questo flag ogni
// fetch pre-login innescava logout() -> POST logout 401 -> re-check auth.
let _sessionConfirmed = false;

// Dati di /api/auth/me letti in checkAuthRequirements: appInit li riusa
// invece di rifare la stessa chiamata per ruolo/username/tab.
let _meCache = null;

// Funzione centralizzata per iniettare e controllare gli header di autenticazione ed evitare disallineamenti della UI
async function apiFetch(url, options = {}) {
    options.headers = options.headers || {};
    Object.assign(options.headers, getAuthHeaders());
    if (options.body && typeof options.body === 'string' && !options.headers['Content-Type'] && !options.headers['content-type']) {
        options.headers['Content-Type'] = 'application/json';
    }

    try {
        const res = await fetch(url, options);
        if (res.status === 401) {
            if (_sessionConfirmed) {
                console.warn("[AUTH] Sessione scaduta o non valida (401). Forzatura Logout.");
                logout();
            }
            return null;
        }
        return res;
    } catch (err) {
        console.error(`[ApiFetch Error] ${url}:`, err);
        return null;
    }
}

async function checkAuthRequirements() {
    const overlay = document.getElementById('authOverlay');
    const changePw = document.getElementById('changePwSection');
    const wiz = document.getElementById('wizardSection');
    const login = document.getElementById('loginSection');

    if (changePw) changePw.style.display = 'none';

    try {
        // Interroga lo stato del setup/utenti nel sistema
        const res = await fetch('/api/auth/status');
        if (!res.ok) throw new Error('Status endpoint HTTP ' + res.status);
        const data = await res.json();

        if (!data.has_users) {
            // Nessun utente su disco: mostriamo la procedura guidata di primo setup
            if (wiz) wiz.style.display = 'block';
            if (login) login.style.display = 'none';
            if (overlay) overlay.style.display = 'flex';
            return false;
        } else {
            // Esiste già un amministratore: mostriamo la maschera di login standard
            if (wiz) wiz.style.display = 'none';
            if (login) login.style.display = 'block';
            // La sessione vive nel cookie HttpOnly: la verifichiamo lato server.
            const me = await fetch('/api/auth/me');
            if (!me.ok) {
                if (overlay) overlay.style.display = 'flex';
                return false;
            }
            _sessionConfirmed = true;
            _meCache = await me.json().catch(() => null);
            if (overlay) overlay.style.display = 'none';
            return true;
        }
    } catch (err) {
        console.warn('[auth] Error checking auth requirements, displaying login fallback:', err);
        if (wiz) wiz.style.display = 'none';
        if (login) login.style.display = 'block';
        if (overlay) overlay.style.display = 'flex';
        return false;
    }
}

// Evento per la registrazione guidata del primo utente amministratore
document.getElementById('btnRegisterAdmin').addEventListener('click', async () => {
    const user = document.getElementById('wizUser').value.trim();
    const pass = document.getElementById('wizPass').value.trim();

    if (!user || !pass) { alert(i18n[currentLang].alertFirstSetupFill); return; }
    if (pass.length < 8) { alert(i18n[currentLang].alertPassTooShort); return; }

    const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    });

    if (res.ok) {
        // Login automatico con le credenziali appena create: evita di
        // dover ridigitare la stessa password nel form di login.
        const loginRes = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });
        if (loginRes.ok) {
            // La sessione è nel cookie HttpOnly impostato dal server.
            const wp = document.getElementById('wizPass'); if (wp) wp.value = '';
            document.getElementById('authOverlay').style.display = 'none';
            appInit();
        } else {
            // Fallback improbabile: account creato ma login fallito.
            alert(i18n[currentLang].alertFirstSetupSuccess);
            checkAuthRequirements();
        }
    } else {
        const err = await res.json();
        alert(i18n[currentLang].alertFirstSetupError + (err.detail || "Impossibile creare l'account."));
    }
});

// Evento per il Login Standard
document.getElementById('btnLogin').addEventListener('click', async () => {
    const user = document.getElementById('loginUser').value.trim();
    const passInput = document.getElementById('loginPass');
    const pass = passInput ? passInput.value.trim() : '';
    const errDiv = document.getElementById('loginError');

    if (!user || !pass) { errDiv.innerText = i18n[currentLang].alertLoginFill; errDiv.style.display = 'block'; return; }
    errDiv.style.display = 'none';

    const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    });

    if (res.ok) {
        if (passInput) passInput.value = '';
        const data = await res.json();
        // La sessione è nel cookie HttpOnly impostato dal server: nessun
        // token conservato lato JavaScript (finding L-1).
        if (data.must_change_password) {
            // Account creato da un amministratore: forziamo il cambio password.
            pendingOldPass = pass;
            document.getElementById('loginSection').style.display = 'none';
            document.getElementById('changePwSection').style.display = 'block';
            document.getElementById('cpwNewPass').value = '';
            document.getElementById('cpwConfirmPass').value = '';
            document.getElementById('cpwNewPass').focus();
            return;
        }
        // Sblocca la UI nascondendo la schermata oscurante
        document.getElementById('authOverlay').style.display = 'none';
        appInit(); // Avvia il caricamento dei dispositivi di rete
    } else {
        errDiv.innerText = i18n[currentLang].alertLoginDenied;
        errDiv.style.display = 'block';
    }
});

// Password nota all'utente al momento del cambio obbligatorio (usata come
// vecchia password per l'endpoint /api/auth/change-password).
let pendingOldPass = '';

// Cambio password obbligatorio al primo accesso
document.getElementById('btnChangePass').addEventListener('click', async () => {
    const npEl = document.getElementById('cpwNewPass');
    const cpEl = document.getElementById('cpwConfirmPass');
    const np = npEl ? npEl.value.trim() : '';
    const cp = cpEl ? cpEl.value.trim() : '';
    const errDiv = document.getElementById('loginError');
    errDiv.style.display = 'none';

    if (np.length < 8) { errDiv.innerText = i18n[currentLang].alertPassTooShort; errDiv.style.display = 'block'; return; }
    if (np !== cp) { errDiv.innerText = i18n[currentLang].alertPassMismatch; errDiv.style.display = 'block'; return; }

    const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'SentinelNet'
        },
        body: JSON.stringify({ old_password: pendingOldPass, new_password: np })
    });

    if (res.ok) {
        pendingOldPass = '';
        if (npEl) npEl.value = '';
        if (cpEl) cpEl.value = '';
        document.getElementById('changePwSection').style.display = 'none';
        document.getElementById('loginSection').style.display = 'block';
        document.getElementById('authOverlay').style.display = 'none';
        appInit();
    } else {
        errDiv.innerText = i18n[currentLang].alertPassChangeErr;
        errDiv.style.display = 'block';
    }
});

async function logout() {
    _sessionConfirmed = false;
    _meCache = null;
    // Pulisce campi sensibili in memoria nel DOM
    document.querySelectorAll('input[type="password"]').forEach(el => { el.value = ''; });
    // Cancella il cookie di sessione lato server (best-effort).
    try {
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: { 'X-Requested-With': 'SentinelNet' }
        });
    } catch (e) { /* sessione già scaduta: ignora */ }
    currentRole = 'viewer';
    currentUsername = '';
    document.body.classList.remove('role-admin', 'role-operator', 'role-viewer');
    checkAuthRequirements();
}

// --- ETA' DEL BACKUP ---

// Quanto e' vecchio il dato che si sta guardando. Va detto ovunque si mostri
// config letta da un backup: un "2/2 UP" di due settimane fa e uno di tre
// minuti fa altrimenti si leggono uguali.
// Oltre una settimana il testo passa a var(--warning): e' il punto in cui il
// dato smette di descrivere la rete di adesso.
function backupAgeLabel(ts) {
    if (!ts) return '';
    const en = currentLang === 'en';
    const h = (Date.now() / 1000 - ts) / 3600;
    const txt = h < 1 ? `${Math.max(1, Math.round(h * 60))} min`
        : (h < 48 ? `${Math.round(h)} h` : `${Math.round(h / 24)} ${en ? 'd' : 'g'}`);
    const label = en ? `backup ${txt} ago` : `backup ${txt} fa`;
    return `<span style="font-size:11px; color:${h > 168 ? 'var(--warning)' : 'var(--text-muted)'};"`
        + ` title="${en ? 'backup age' : 'eta del backup'}">${escapeHtml(label)}</span>`;
}

// --- RUOLI / PRIVILEGI ---

function roleLabel(role) {
    if (role === 'admin') return currentLang === 'en' ? 'Administrator' : 'Amministratore';
    if (role === 'operator') return currentLang === 'en' ? 'Operator' : 'Operatore';
    return currentLang === 'en' ? 'Viewer' : 'Visualizzatore';
}

// Tab permissions are stored per user in users.json and predate the endpoint
// merge, where four tabs became one. A saved 'tab-mac' must keep revealing the
// group, so the old id is aliased on READ. The stored file is never rewritten:
// it is the user's data, not ours.
function normalizeAllowedTabs(tabs) {
    if (!Array.isArray(tabs) || tabs.length === 0) return [];
    const LEGACY = { 'tab-mac': 'tab-endpoint', 'tab-clientmap': 'tab-endpoint',
                     'tab-diagnosi': 'tab-endpoint', 'tab-endpoints': 'tab-endpoint' };
    return [...new Set(tabs.map(t => LEGACY[t] || t))];
}

function applyRoleUI(username, role, allowedTabs) {
    if (username !== undefined && username !== null) currentUsername = username;
    if (role !== undefined && role !== null) currentRole = role;
    if (!currentRole) currentRole = 'viewer';
    document.body.classList.remove('role-admin', 'role-operator', 'role-viewer');
    document.body.classList.add('role-' + currentRole);
    const badge = document.getElementById('userBadgeLabel');
    if (badge) {
        const icon = currentRole === 'admin' ? 'fa-user-shield'
            : currentRole === 'operator' ? 'fa-user-gear' : 'fa-user';
        badge.innerHTML = `<i class="fa-solid ${icon}"></i> ${escapeHtml(currentUsername)} · ` +
            `<span class="role-pill role-pill-${currentRole}">${roleLabel(currentRole)}</span>`;
    }
    // ponytail: restrizione solo lato frontend (nasconde i pulsanti); vuoto = tutte le tab.
    const allowed = normalizeAllowedTabs(allowedTabs);
    if (allowed.length > 0) {
        document.querySelectorAll('.nav-item').forEach(btn => {
            const tabId = btn.getAttribute('data-tab');
            if (tabId && !allowed.includes(tabId)) btn.style.display = 'none';
        });
    }
}

// Invio rapido con tasto Enter su login, setup wizard e creazione gruppo
function bindEnterKey(inputIds, buttonId) {
    inputIds.forEach(id => {
        document.getElementById(id).addEventListener('keydown', e => {
            if (e.key === 'Enter') document.getElementById(buttonId).click();
        });
    });
}
bindEnterKey(['loginUser', 'loginPass'], 'btnLogin');
bindEnterKey(['wizUser', 'wizPass'], 'btnRegisterAdmin');
bindEnterKey(['newGroupName'], 'btnCreateGroup');
bindEnterKey(['scanNetworkInput'], 'btnAvviaScan');

document.getElementById('themeToggle')?.addEventListener('click', toggleTheme);
document.getElementById('sidebarToggle')?.addEventListener('click', toggleSidebar);
document.getElementById('btnLogout')?.addEventListener('click', (e) => {
    e.preventDefault();
    logout();
});

// Chiusura modali: click sullo sfondo oppure tasto Escape.
// Il modale CLI non si chiude con Escape: il tasto serve dentro al terminale SSH.
document.getElementById('subnetScanModal').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeSubnetScanModal();
});
document.getElementById('cliModalOverlay').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeCliModal();
});
document.getElementById('triageScopeModal').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeTriageScopeModal();
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && document.getElementById('triageScopeModal').style.display === 'flex') {
        closeTriageScopeModal();
    }
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape' &&
        document.getElementById('subnetScanModal').style.display === 'flex') {
        closeSubnetScanModal();
    }
});

// --- INITIALIZATION ---

async function appInit() {
    appLoading = true;
    initLanguageSelector();
    const isAuth = await checkAuthRequirements();
    if (!isAuth) {
        appLoading = false;
        return;
    }

    // Determina ruolo/privilegi dell'utente corrente e adatta la UI.
    // I dati arrivano dalla cache di checkAuthRequirements; il fetch resta
    // solo come fallback se la cache non si e' riempita.
    try {
        let me = _meCache;
        if (!me) {
            const meRes = await apiFetch('/api/auth/me');
            if (meRes && meRes.ok) me = await meRes.json();
        }
        if (me) {
            currentRole = me.role || 'viewer';
            applyRoleUI(me.username, currentRole, me.allowed_tabs || []);
        }
    } catch (e) { /* non bloccante */ }

    // Sincronizza badge di versione dell'applicazione
    try {
        const verRes = await apiFetch('/api/version');
        if (verRes && verRes.ok) {
            const vData = await verRes.json();
            const badge = document.getElementById('appVersionBadge');
            if (badge && vData.version) {
                badge.textContent = 'v' + vData.version;
            }
        }
    } catch (e) { /* non bloccante */ }

    // Gating tab MCP Client (preview): visibile solo ad admin col flag attivo.
    if (currentRole === 'admin' && typeof applyMcpClientGating === 'function') {
        try { await applyMcpClientGating(); } catch (e) { /* non bloccante */ }
    }

    // Flow SIEM, NetSec Audit, Incidenti e Fortigate Management non sono piu'
    // dietro un flag: le tab sono sempre presenti, gated solo dalla RBAC di
    // nav come ogni altra voce.

    try {
        // Indipendenti: partono insieme invece che in sequenza.
        const [res, vRes] = await Promise.all([
            apiFetch('/api/local-devices'),
            apiFetch('/api/vendors'),
        ]);
        if (!res) {
            appLoading = false;
            return;
        }
        const data = await res.json();

        globalDevices = data.devices;
        globalGroups = data.groups;
        globalVersions = data.detected_versions; // Cache globale delle versioni rilevate

        if (vRes && vRes.ok) globalVendors = await vRes.json();

        // Popola tendine Vendor + tendina Gruppi del form di provisioning
        // (estratto in populateProvisioningFormSelects: riusato anche da loadProvisioningTab).
        populateProvisioningFormSelects();

        // Memorizza la selezione corrente del filtro se esiste
        const filterSelect = document.getElementById('filterGroupSelect');
        const prevFilter = filterSelect ? filterSelect.value : 'all';

        // Popola tendina Filtro Gruppi nella tabella dell'inventario
        if (filterSelect) {
            filterSelect.innerHTML = `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
                Object.keys(globalGroups).map(g =>
                    `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            filterSelect.value = prevFilter;
            if (filterSelect.selectedIndex === -1) filterSelect.value = 'all';
        }

        // Popola tendina Filtro Gruppi in TAB 3
        const topoSelect = document.getElementById('topologyGroupSelect');
        if (topoSelect) {
            const prevTopoFilter = topoSelect.value || 'all';
            topoSelect.innerHTML = `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
                Object.keys(globalGroups).map(g =>
                    `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            topoSelect.value = prevTopoFilter;
            if (topoSelect.selectedIndex === -1) topoSelect.value = 'all';
        }

        // Popola tendina Filtro Gruppi in TAB 4
        const interSelect = document.getElementById('interactiveGroupSelect');
        if (interSelect) {
            const prevInterFilter = interSelect.value || 'all';
            interSelect.innerHTML = `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
                Object.keys(globalGroups).map(g =>
                    `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            interSelect.value = prevInterFilter;
            if (interSelect.selectedIndex === -1) interSelect.value = 'all';
        }

        // Popola Tabella Dispositivi tramite la nuova funzione autonoma filtrabile
        renderDeviceTable();

        // Popola la Home operativa (tab di default al login) coi globals appena caricati
        loadHome();

        // Popola Tabella Gestione Gruppi
        renderGroupsTable();

        // Stato SNMP di tenant: solo i nomi, la community non arriva al browser
        loadSnmpDefaults();

        // Forza il reload delle mappe se le tab sono attive
        const activeTabId = document.querySelector('.tab-content.active')?.id;
        if (activeTabId === 'tab-map') {
            await loadTopology();
        } else if (activeTabId === 'tab-map-interactive') {
            await loadInteractiveMap();
        } else if (activeTabId === 'tab-security') {
            loadThreatIntel();
        }

        startTriageStatusPolling();

    } catch (err) {
        console.error(err);
    } finally {
        appLoading = false;
    }
}

// --- CARICAMENTO LAZY DEI MODULI PER TAB ---
// I moduli pesanti e legati a una singola tab non bloccano piu' il primo
// paint: vengono iniettati alla prima visita della tab che li usa.
// I vendor restano in bundle con il modulo che li consuma (vis-network
// prima di topology.js: async=false conserva l'ordine di esecuzione).
const LAZY_TAB_SCRIPTS = {
    'tab-map': ['/static/vendor/vis/vis-network.min.js', '/static/js/topology.js'],
    'tab-map-interactive': ['/static/vendor/vis/vis-network.min.js', '/static/js/topology.js'],
    'tab-categories': ['/static/js/topology.js'],
    'tab-flows': ['/static/js/flow-analytics.js', '/static/js/observability.js'],
    'tab-config': ['/static/js/config-analyzer.js'],
    'tab-ai': ['/static/js/ai.js'],
    'tab-fortigate': ['/static/js/fortigate-management.js'],
    'tab-wlc': ['/static/js/wlc.js'],
    'tab-audit-checklist': ['/static/vendor/html2pdf/html2pdf.bundle.min.js', '/static/js/audit_checklist.js'],
    'tab-settings': ['/static/js/settings.js', '/static/js/observability.js'],
    'tab-incidents': ['/static/js/incidents.js'],
    'tab-redundancy': ['/static/js/redundancy.js'],
    'tab-netsec-audit': ['/static/vendor/html2pdf/html2pdf.bundle.min.js', '/static/js/netsec-audit.js'],
};

const _lazyLoaded = new Set();
const _lazyLoading = new Map();

function loadAssetOnce(src) {
    if (_lazyLoaded.has(src)) return Promise.resolve();
    if (_lazyLoading.has(src)) return _lazyLoading.get(src);
    const isCss = src.endsWith('.css');
    const p = new Promise((resolve, reject) => {
        let el;
        if (isCss) {
            el = document.createElement('link');
            el.rel = 'stylesheet';
            el.href = src;
        } else {
            el = document.createElement('script');
            el.src = src;
            el.async = false;
        }
        el.onload = () => { _lazyLoaded.add(src); _lazyLoading.delete(src); resolve(); };
        el.onerror = () => { _lazyLoading.delete(src); reject(new Error('Load failed: ' + src)); };
        document.head.appendChild(el);
    });
    _lazyLoading.set(src, p);
    return p;
}

async function ensureTabScripts(tabId) {
    const scripts = LAZY_TAB_SCRIPTS[tabId];
    if (!scripts) return;
    try {
        await Promise.all(scripts.map(loadAssetOnce));
    } catch (e) {
        console.error('[lazy]', e);
        showToast('Errore di caricamento modulo', 'error');
    }
}

// Delega per l'apertura delle tab: niente piu' onclick inline (CSP senza
// 'unsafe-inline'). data-tab marca le voci della nav, data-switch-tab gli
// altri pulsanti (home, sotto-tab). I secondi non passano il pulsante:
// switchTab risale alla voce di nav da sola, come prima.
document.addEventListener('click', e => {
    const el = e.target.closest('[data-tab], [data-switch-tab]');
    if (!el) return;
    const tabId = el.getAttribute('data-tab') || el.getAttribute('data-switch-tab');
    switchTab(tabId, el.classList.contains('nav-item') ? el : undefined);
});

async function switchTab(tabId, clickedBtn) {
    await ensureTabScripts(tabId);
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    // Se chiamato senza pulsante (es. dopo import CSV) evidenzia comunque la tab corretta.
    // I sotto-tab passano solo il tabId: la voce di nav che li raggruppa si
    // dichiara con data-tabs, così una sola voce resta attiva per piu' tab.
    const btn = clickedBtn
        || document.querySelector(`.nav-item[data-tab="${tabId}"]`)
        || document.querySelector(`.nav-item[data-tabs~="${tabId}"]`);
    if (btn) {
        btn.classList.add('active');
    }

    if (tabId === 'tab-home') {
        loadHome();
    } else {
        // Leaving home: stop the ping-monitor auto-refresh so it doesn't keep
        // polling and re-rendering a hidden tab. loadHome() re-arms it on return.
        if (typeof _pingRefreshTimer !== 'undefined' && _pingRefreshTimer) {
            clearInterval(_pingRefreshTimer); _pingRefreshTimer = null;
        }
    }
    if (tabId === 'tab-devices') {
        renderDeviceTable();
    } else if (tabId === 'tab-provisioning') {
        loadProvisioningTab();
    } else if (tabId === 'tab-map') loadTopology();
    else if (tabId === 'tab-map-interactive') loadInteractiveMap();
    else if (tabId === 'tab-categories') loadCategoriesData();
    else if (tabId === 'tab-security' && !appLoading) {
        loadThreatIntel();
    }
    else if (tabId === 'tab-endpoint') locSwitchView(_locView);
    else if (tabId === 'tab-config') loadConfigAnalyzer();
    else if (tabId === 'tab-ai') loadAiTab();
    else if (tabId === 'tab-users') loadUsers();
    else if (tabId === 'tab-sites') loadSites();
    else if (tabId === 'tab-mcp') loadMcpTab();
    else if (tabId === 'tab-mcp-client') loadMcpClientTab();
    else if (tabId === 'tab-fortigate') loadFgtTab();
    else if (tabId === 'tab-wlc' && typeof loadWlcTab === 'function') loadWlcTab();
    else if (tabId === 'tab-audit-checklist') loadAuditChecklistTab();
    else if (tabId === 'tab-settings') loadAppSettings();
    // Queste tre tab prima si inizializzavano con una seconda chiamata
    // nell'onclick del pulsante nav; ora il dispatch e' unico e arriva
    // dopo il caricamento lazy del modulo.
    else if (tabId === 'tab-flows') flowsTabShown();
    else if (tabId === 'tab-incidents') loadIncidentsTab();
    else if (tabId === 'tab-redundancy') loadRedundancyTab();
    else if (tabId === 'tab-netsec-audit') loadNetSecAuditTab();
}

// --- FLUSSI LIVE (fase 5): top talker + anomalie correlate -------------
// Toast minimale non bloccante (il resto della dashboard usa alert()).
function showToast(msg, kind) {
    const el = document.createElement('div');
    el.textContent = msg;
    // Il colore significa stato: il fondo resta una superficie del sistema e lo
    // stato lo porta il bordo. Prima erano tre colori fissi (fra cui uno slate
    // che nella palette non esiste): sul laminato chiaro erano fuori sistema.
    const edge = kind === 'error' ? 'var(--lamp-fault)'
        : kind === 'warning' ? 'var(--lamp-warn)'
            : 'var(--border-strong)';
    el.style.cssText = 'position:fixed; bottom:24px; right:24px; z-index:9999;'
        + 'padding:10px 16px; border-radius:0; font-size:13px;'
        + 'font-family:var(--font-prose); color:var(--text);'
        + 'background:var(--surface-3); box-shadow:var(--shadow-float);'
        + 'border:1px solid ' + edge + ';';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}

// --- Shared across tabs (promoted from templates/dashboard.html during
// static/js/provisioning.js extraction): renderVendorTable/buildVendorOptions
// are used by the Provisioning tab (populateProvisioningFormSelects) AND by
// the still-inline Groups tab (loadVendors) AND by changeLanguage() in
// static/js/i18n.js. refreshIdentityOptions/renderIdentitiesPanel are used by
// the Provisioning tab AND by the still-inline Devices tab's editDevice() AND
// by the still-inline Groups tab's btnCreateGroup handler. ---

function buildVendorOptions(selected) {
    const builtins = ["cisco", "hpe"];
    const all = [...new Set([...builtins, ...Object.keys(globalVendors)])];
    return all.map(v =>
        `<option value="${escapeHtml(v)}" ${v === selected ? "selected" : ""}>${escapeHtml(v.toUpperCase())}</option>`
    ).join("");
}

// Vendor select della finestra di scansione. Ha in piu' la voce vuota, che le
// altre select non hanno: aggiungere un dispositivo scoperto senza scegliere un
// vendor deve scrivere "nessun vendor", non il primo della lista. Senza questa
// voce la select non sa dire "non scelto" e il vendor tornerebbe indovinato.
function buildScanVendorOptions(selected) {
    const L = (typeof i18n !== "undefined" && i18n[currentLang]) || {};
    return `<option value="">${escapeHtml(L.optScanNoVendor || "— non impostato —")}</option>`
         + buildVendorOptions(selected);
}

function renderVendorTable() {
    const body = document.getElementById('vendorTableBody');
    if (!body) return;
    body.innerHTML = '';
    Object.entries(globalVendors).forEach(([name, meta]) => {
        const isSystem = name === 'cisco' || name === 'hpe';
        const systemText = currentLang === 'en' ? 'System' : 'Sistema';
        const deleteText = currentLang === 'en' ? 'Delete' : 'Elimina';
        body.innerHTML += `<tr>
            <td><strong>${escapeHtml(name)}</strong></td>
            <td><span style="font-family:var(--font-code); font-size:12px; color:var(--primary);">${escapeHtml(meta.euvd_term) || '—'}</span></td>
            <td><span style="font-family:var(--font-code); font-size:12px; color:var(--text-muted);">${escapeHtml(meta.driver) || '—'}</span></td>
            <td>${currentRole === 'viewer'
                ? '<span style="color:var(--text-muted); font-size:12px;">—</span>'
                : (isSystem
                    ? `<span style="color:var(--text-muted); font-size:12px;">${systemText}</span>`
                    : `<button data-action="delete-vendor" data-v="${escapeHtml(name)}" style="color:var(--danger); background:none; border:none; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> ${deleteText}</button>`)
            }</td>
        </tr>`;
    });
}

document.getElementById('vendorTableBody')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="delete-vendor"]');
    if (btn && btn.dataset.v) {
        deleteVendor(btn.dataset.v);
    }
});

// Carica le identita' del tenant selezionato nella select devProfile,
// preservando default/custom. Chiamata al load della tab e al cambio tenant.
async function refreshIdentityOptions(preserve) {
    const tenant = document.getElementById('devGroupSelect').value;
    const sel = document.getElementById('devProfile');
    const keep = preserve || sel.value;
    const res = await apiFetch('/api/identities?tenant=' + encodeURIComponent(tenant));
    const idents = res && res.ok ? (await res.json()).identities : [];
    sel.innerHTML = `<option value="default">${i18n[currentLang].optProfileDefault.replace(/<[^>]*>/g, '')}</option>` +
        idents.map(i => `<option value="identity:${i.id}">${escapeHtml(i.name)} (${escapeHtml(i.username)})</option>`).join('') +
        `<option value="custom">${i18n[currentLang].optProfileCustom.replace(/<[^>]*>/g, '')}</option>`;
    sel.value = Array.from(sel.options).some(o => o.value === keep) ? keep : 'default';
    document.getElementById('customCredsForm').style.display = sel.value === 'custom' ? 'block' : 'none';
    window._tenantIdentities = idents;
}

function renderIdentitiesPanel() {
    const body = document.getElementById('identitiesTableBody');
    const idents = window._tenantIdentities || [];
    body.innerHTML = idents.length ? idents.map(i => {
        let tenantLabel = '';
        if (!i.tenant || i.tenant === 'all') {
            tenantLabel = `<span class="badge" style="background:var(--surface-2); color:var(--text-muted); font-size:10.5px; padding:2px 6px; border:1px solid var(--border); text-transform:uppercase; letter-spacing:0.02em;">${escapeHtml(i18n[currentLang].optTenantAll || 'Globale')}</span>`;
        } else if (Array.isArray(i.tenant)) {
            tenantLabel = i.tenant.map(t => `<span class="badge" style="background:color-mix(in srgb, var(--primary) 12%, transparent); color:var(--primary); border:1px solid color-mix(in srgb, var(--primary) 30%, transparent); font-size:10.5px; padding:2px 6px; margin-right:3px; display:inline-block; text-transform:uppercase; letter-spacing:0.02em;">${escapeHtml(t)}</span>`).join('');
        } else {
            const parts = String(i.tenant).split(',').map(s => s.trim()).filter(Boolean);
            tenantLabel = parts.map(t => `<span class="badge" style="background:color-mix(in srgb, var(--primary) 12%, transparent); color:var(--primary); border:1px solid color-mix(in srgb, var(--primary) 30%, transparent); font-size:10.5px; padding:2px 6px; margin-right:3px; display:inline-block; text-transform:uppercase; letter-spacing:0.02em;">${escapeHtml(t)}</span>`).join('');
        }
        return `<tr style="border-bottom:1px solid color-mix(in srgb, var(--border) 50%, transparent);">
        <td style="padding:8px 6px; font-weight:600; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;" title="${escapeHtml(i.name)}">${escapeHtml(i.name)}</td>
        <td style="padding:8px 6px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">${tenantLabel}</td>
        <td style="padding:8px 6px; font-family:var(--font-code); font-size:12px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;" title="${escapeHtml(i.username)}">${escapeHtml(i.username)}</td>
        <td style="padding:8px 6px; text-align:center; font-family:var(--font-code); font-size:12px;">${i.devices_using}</td>
        <td style="padding:8px 6px; text-align:right;">
          <div style="display:flex; gap:4px; justify-content:flex-end;">
            <button class="btn-icon" data-action="assign-identity" data-id="${i.id}" style="width:26px; height:26px; padding:0; display:inline-flex; align-items:center; justify-content:center;" title="${escapeHtml(i18n[currentLang].btnAssignIdentityTitle || 'Assign to devices')}"><i class="fa-solid fa-users-rectangle" style="font-size:11px;"></i></button>
            <button class="btn-icon" data-action="edit-identity" data-id="${i.id}" style="width:26px; height:26px; padding:0; display:inline-flex; align-items:center; justify-content:center;" title="Edit"><i class="fa-solid fa-pen" style="font-size:11px;"></i></button>
            <button class="btn-icon danger" data-action="delete-identity" data-id="${i.id}" style="width:26px; height:26px; padding:0; display:inline-flex; align-items:center; justify-content:center;" title="Delete"><i class="fa-solid fa-trash-can" style="font-size:11px;"></i></button>
          </div>
        </td></tr>`;
    }).join('')
        : `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:16px; font-size:13px;">${i18n[currentLang].emptyIdentities}</td></tr>`;
}

// ===== Port Config Modal (promosso da static/js/topology.js: usato anche
// dal tab MAC-tracker/ARP inline e da static/js/config-analyzer.js) =====
// Espande le abbreviazioni comuni delle interfacce ('Gi1/0/5' -> 'GigabitEthernet1/0/5').
// Speculare a expand_iface() di mac_collector.py: tenerli allineati.
function expandIface(name) {
    if (!name) return '';
    name = String(name).trim();
    const abbr = [
        [/^Gi(?=\d)/, 'GigabitEthernet'], [/^Te(?=\d)/, 'TenGigabitEthernet'],
        [/^Fo(?=\d)/, 'FortyGigE'], [/^Twe(?=\d)/, 'TwentyFiveGigE'],
        [/^Hu(?=\d)/, 'HundredGigE'], [/^Fa(?=\d)/, 'FastEthernet'],
        [/^Eth(?=\d)/, 'Ethernet'], [/^Et(?=\d)/, 'Ethernet'], [/^Po(?=\d)/, 'Port-channel'],
    ];
    for (const [pat, full] of abbr) {
        if (pat.test(name)) return name.replace(pat, full);
    }
    return name;
}

// Deep-link verso il Config Analyzer (impostati da showPortConfig, letti da renderCaResults).
let caFocusIp = null;
let caFocusPort = null;

function closePortConfigModal() {
    const m = document.getElementById('portConfigModal');
    if (m) m.remove();
}

async function showPortConfig(switchIp, port, switchName) {
    const L = i18n[currentLang];
    let iface = null;
    try {
        const res = await apiFetch('/api/config-analyzer/' + encodeURIComponent(switchIp));
        if (res && res.ok) {
            const d = await res.json();
            const want = expandIface(port).toLowerCase();
            iface = (d.interfaces || []).find(i => expandIface(i.name).toLowerCase() === want) || null;
        }
    } catch (e) { /* trattato come non trovato */ }

    closePortConfigModal();
    const body = iface
        ? `<pre style="font-family:var(--font-code); background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:12px; margin:0; white-space:pre-wrap; font-size:12px;">${escapeHtml(iface.raw || '—')}</pre>`
        : `<div style="font-size:13px; color:var(--text-muted); padding:10px 0;"><i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.portConfigNotFound)}</div>`;
    const ov = document.createElement('div');
    ov.id = 'portConfigModal';
    ov.style.cssText = 'position:fixed; inset:0; z-index:10050; background:color-mix(in srgb, var(--bg) 82%, transparent); display:flex; align-items:center; justify-content:center; backdrop-filter:blur(4px);';
    ov.innerHTML = `
            <div style="background:var(--surface); border:1px solid var(--border); border-radius:0; padding:22px; width:min(560px,94vw); max-height:86vh; overflow:auto; box-shadow:var(--shadow-float);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <h3 style="font-size:17px;"><i class="fa-solid fa-ethernet" style="color:var(--primary);"></i> ${escapeHtml(L.portConfigTitle)}</h3>
                    <i class="fa-solid fa-xmark" data-action="close-port-config" style="cursor:pointer; color:var(--text-muted); font-size:17px;"></i>
                </div>
                <div style="font-family:var(--font-code); font-size:13px; color:var(--primary); margin-bottom:16px;">${escapeHtml(switchName || switchIp)} — ${escapeHtml(port)}</div>
                ${body}
                <div style="display:flex; justify-content:flex-end; align-items:center; gap:10px; margin-top:16px;">
                    <button data-action="open-port-in-analyzer" data-ip="${escapeHtml(switchIp)}" data-port="${escapeHtml(port)}" class="btn btn-secondary btn-small" style="width:auto; margin:0;"><i class="fa-solid fa-up-right-from-square"></i> ${escapeHtml(L.openInAnalyzer)}</button>
                    <button data-action="close-port-config" class="btn btn-secondary btn-small" style="width:auto; margin:0;">${currentLang === 'en' ? 'Close' : 'Chiudi'}</button>
                </div>
            </div>`;
    ov.addEventListener('click', e => {
        if (e.target === ov || e.target.closest('[data-action="close-port-config"]')) closePortConfigModal();
        const openBtn = e.target.closest('[data-action="open-port-in-analyzer"]');
        if (openBtn && openBtn.dataset.ip) {
            openPortInAnalyzer(openBtn.dataset.ip, openBtn.dataset.port);
        }
    });
    document.body.appendChild(ov);
}

function openPortInAnalyzer(switchIp, port) {
    caFocusIp = switchIp;
    caFocusPort = port;
    closePortConfigModal();
    switchTab('tab-config');
}

// --- GLOBAL KEYBOARD SHORTCUTS (Power User Alex) ---
let _gPendingKey = false;
let _gPendingTimer = null;

document.addEventListener('keydown', e => {
    const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
    const isInput = activeTag === 'input' || activeTag === 'select' || activeTag === 'textarea' || (document.activeElement && document.activeElement.isContentEditable);

    if (e.key === 'Escape') {
        closePortConfigModal();
        return;
    }

    if (isInput) return;

    if (e.key === '/' || (e.ctrlKey && e.key.toLowerCase() === 'k')) {
        e.preventDefault();
        const searchEl = document.querySelector('input[type="search"], input[placeholder*="Search"], input[placeholder*="Cerca"]');
        if (searchEl) searchEl.focus();
        return;
    }

    if (e.key === 'g' && !_gPendingKey) {
        _gPendingKey = true;
        clearTimeout(_gPendingTimer);
        _gPendingTimer = setTimeout(() => { _gPendingKey = false; }, 1000);
        return;
    }

    if (_gPendingKey) {
        _gPendingKey = false;
        clearTimeout(_gPendingTimer);
        const target = e.key.toLowerCase();
        if (target === 'h') switchTab('tab-home');
        else if (target === 's') switchTab('tab-settings');
        else if (target === 'd') switchTab('tab-devices');
        // 'tab-ai-chat' era l'id del prototype: la tab reale e' tab-ai, e il
        // vecchio id faceva morire switchTab su getElementById(null).
        else if (target === 'a') switchTab('tab-ai');
    }
});

// --- DROPDOWN STACKING ELEVATION (Fix clipped dropdown menus across themes) ---
document.addEventListener('toggle', function(e) {
    if (e.target && e.target.tagName === 'DETAILS') {
        const panel = e.target.closest('.panel, .hero-card, .filterbar, aside, main');
        if (panel) {
            if (e.target.open) {
                panel.style.zIndex = '500';
                panel.style.position = 'relative';
                panel.classList.add('has-open-dropdown');
            } else {
                const hasOtherOpen = panel.querySelector('details[open]');
                if (!hasOtherOpen) {
                    panel.style.zIndex = '';
                    panel.classList.remove('has-open-dropdown');
                }
            }
        }
    }
}, true);

document.getElementById('identitiesList')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn || !btn.dataset.id) return;
    const act = btn.dataset.action;
    if (act === 'assign-identity') assignIdentityToDevices(btn.dataset.id);
    else if (act === 'edit-identity') editIdentity(btn.dataset.id);
    else if (act === 'delete-identity') deleteIdentity(btn.dataset.id);
});

window.loadAssetOnce = loadAssetOnce;

