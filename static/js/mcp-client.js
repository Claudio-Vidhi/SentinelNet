// ===== MCP Client (PREVIEW) tab — SentinelNet come client verso server MCP esterni =====
// Gating: la tab e il flag sono admin-only (rispecchia tab-mcp). Le stringhe
// derivate dal server esterno passano sempre da escapeHtml(jsStr(x)).

const jsStr = s => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");

// --- Gating: mostra la tab solo se il flag preview e' attivo (chiamata in appInit) ---
async function applyMcpClientGating() {
    const res = await apiFetch('/api/mcp-client/settings');
    if (!res || !res.ok) return;
    const data = await res.json();
    const nav = document.getElementById('navMcpClient');
    if (nav) nav.style.display = data.preview_enabled ? '' : 'none';
    const toggle = document.getElementById('mcpPreviewToggle');
    if (toggle) toggle.checked = !!data.preview_enabled;
}

// --- Toggle preview (nella tab MCP Server) ---
async function setMcpPreview(enabled) {
    const st = document.getElementById('mcpPreviewStatus');
    const res = await apiFetch('/api/mcp-client/preview', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !!enabled })
    });
    const L = i18n[currentLang];
    if (res && res.ok) {
        if (st) st.textContent = L.mcpPreviewSaved || 'Salvato.';
        await applyMcpClientGating();
    } else {
        const e = res ? await res.json().catch(() => ({})) : {};
        if (st) st.textContent = (currentLang === 'en' ? 'Error: ' : 'Errore: ') + (e.detail || '');
    }
}

// --- Caricamento tab ---
async function loadMcpClientTab() {
    const res = await apiFetch('/api/mcp-client/servers');
    const list = document.getElementById('mcpClientServerList');
    if (!list) return;
    if (!res || !res.ok) { list.innerHTML = ''; return; }
    const data = await res.json();
    renderMcpClientServers(data.servers || []);
}

function renderMcpClientServers(servers) {
    const list = document.getElementById('mcpClientServerList');
    const L = i18n[currentLang];
    if (!servers.length) {
        list.innerHTML = `<span style="color:var(--text-muted); font-size:12px;">${escapeHtml(L.mcpNoServers)}</span>`;
        return;
    }
    list.innerHTML = servers.map(s => {
        const nm = escapeHtml(jsStr(s.name));
        return `<div style="border:1px solid var(--border); border-radius:8px; padding:12px; margin-bottom:10px; background:var(--surface);">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
              <span><strong>${escapeHtml(s.name)}</strong> <code style="font-size:11px; color:var(--text-muted);">${escapeHtml(s.url)}</code>
                ${s.has_auth ? '<span class="chip"><i class="fa-solid fa-key"></i> auth</span>' : ''}</span>
              <span style="display:flex; gap:8px;">
                <button class="btn btn-secondary btn-small" style="width:auto; margin:0;" onclick="mcpClientListTools('${nm}')"><i class="fa-solid fa-list"></i> ${escapeHtml(L.btnMcpListTools)}</button>
                <button class="btn btn-secondary btn-small" style="width:auto; margin:0; color:var(--danger);" onclick="deleteMcpClientServer('${nm}')"><i class="fa-solid fa-trash-can"></i></button>
              </span>
            </div>
            <div id="mcpcTools-${nm}" style="margin-top:10px;"></div>
        </div>`;
    }).join('');
}

async function saveMcpClientServer() {
    const st = document.getElementById('mcpcSaveStatus');
    const name = document.getElementById('mcpcName').value.trim();
    const url = document.getElementById('mcpcUrl').value.trim();
    const auth_token = document.getElementById('mcpcAuth').value;
    if (!name || !url) { if (st) st.textContent = currentLang === 'en' ? 'Name and URL required.' : 'Nome e URL obbligatori.'; return; }
    const res = await apiFetch('/api/mcp-client/servers', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, url, auth_token })
    });
    if (res && res.ok) {
        document.getElementById('mcpcName').value = '';
        document.getElementById('mcpcUrl').value = '';
        document.getElementById('mcpcAuth').value = '';
        document.getElementById('mcpcHint').textContent = '';
        if (st) st.textContent = '';
        loadMcpClientTab();
    } else {
        const e = res ? await res.json().catch(() => ({})) : {};
        if (st) st.textContent = (currentLang === 'en' ? 'Error: ' : 'Errore: ') + (e.detail || '');
    }
}

async function deleteMcpClientServer(name) {
    if (!confirm(currentLang === 'en' ? `Delete server "${name}"?` : `Eliminare il server "${name}"?`)) return;
    const res = await apiFetch('/api/mcp-client/servers/' + encodeURIComponent(name), { method: 'DELETE' });
    if (res && res.ok) loadMcpClientTab();
}

async function mcpClientListTools(name) {
    const target = document.getElementById('mcpcTools-' + name);
    if (target) target.innerHTML = '<span style="color:var(--text-muted); font-size:12px;">…</span>';
    const res = await apiFetch('/api/mcp-client/' + encodeURIComponent(name) + '/tools');
    const L = i18n[currentLang];
    if (!res || !res.ok) {
        const e = res ? await res.json().catch(() => ({})) : {};
        if (target) target.innerHTML = `<span style="color:var(--danger); font-size:12px;">${escapeHtml(e.detail || 'Errore')}</span>`;
        return;
    }
    const data = await res.json();
    const tools = data.tools || [];
    if (!target) return;
    if (!tools.length) { target.innerHTML = `<span style="color:var(--text-muted); font-size:12px;">${escapeHtml(L.mcpNoTools)}</span>`; return; }
    const nm = escapeHtml(jsStr(name));
    target.innerHTML = tools.map((t, i) => {
        const tn = escapeHtml(jsStr(t.name));
        const schema = t.inputSchema ? escapeHtml(JSON.stringify(t.inputSchema, null, 2)) : '';
        return `<div style="border:1px solid var(--border); border-radius:8px; padding:10px; margin-bottom:8px;">
          <div><code style="font-size:12px;">${escapeHtml(t.name)}</code></div>
          <div style="color:var(--text-muted); font-size:11px; margin:4px 0;">${escapeHtml(t.description || '')}</div>
          ${schema ? `<pre style="background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:8px; font-size:11px; overflow-x:auto; white-space:pre;">${schema}</pre>` : ''}
          <textarea id="mcpcArgs-${nm}-${i}" class="input" rows="3" style="font-family:var(--font-code); font-size:12px;" placeholder='{ }'>{}</textarea>
          <div style="margin-top:6px;"><button class="btn btn-primary btn-small" style="width:auto; margin:0;" onclick="mcpClientCall('${nm}','${tn}','mcpcArgs-${nm}-${i}','mcpcResult-${nm}-${i}')"><i class="fa-solid fa-play"></i> ${escapeHtml(L.btnMcpInvoke)}</button></div>
          <pre id="mcpcResult-${nm}-${i}" style="margin-top:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:8px; font-size:11px; overflow-x:auto; white-space:pre-wrap; display:none;"></pre>
        </div>`;
    }).join('');
}

async function mcpClientCall(name, tool, argsId, resultId) {
    const out = document.getElementById(resultId);
    let args = {};
    const raw = document.getElementById(argsId).value.trim() || '{}';
    try { args = JSON.parse(raw); } catch (e) {
        if (out) { out.style.display = 'block'; out.textContent = (currentLang === 'en' ? 'Invalid JSON: ' : 'JSON non valido: ') + e.message; }
        return;
    }
    if (out) { out.style.display = 'block'; out.textContent = '…'; }
    const res = await apiFetch('/api/mcp-client/' + encodeURIComponent(name) + '/call', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool, arguments: args })
    });
    if (!res) return;
    const data = await res.json().catch(() => ({}));
    if (out) out.textContent = res.ok ? JSON.stringify(data.result, null, 2) : (data.detail || 'Errore');
}

// --- Preset ticketing (prefill del form) ---
function mcpClientPreset(kind) {
    const L = i18n[currentLang];
    const map = {
        jira: { name: 'jira', url: 'https://<tuo-dominio>.atlassian.net/mcp', hint: L.hintMcpJira },
        servicenow: { name: 'servicenow', url: 'https://<istanza>.service-now.com/mcp', hint: L.hintMcpServiceNow },
    };
    const p = map[kind];
    if (!p) return;
    document.getElementById('mcpcName').value = p.name;
    document.getElementById('mcpcUrl').value = p.url;
    document.getElementById('mcpcHint').textContent = p.hint;
}
