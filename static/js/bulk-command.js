// --- INVIO COMANDI MASSIVO (BULK) ---
// Estratto dal blocco inline di templates/dashboard.html (CSP senza
// 'unsafe-inline').

let _bulkJobInterval = null;

function openBulkCommandModal() {
    // Popola il filtro gruppo
    const gf = document.getElementById('bulkGroupFilter');
    gf.innerHTML = `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
        Object.keys(globalGroups).map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
    gf.value = 'all';

    document.getElementById('bulkSelectAll').checked = false;
    document.getElementById('bulkMode').value = 'exec';
    document.getElementById('bulkSave').checked = false;
    document.getElementById('bulkCommands').value = '';
    document.getElementById('bulkResults').style.display = 'none';
    document.getElementById('bulkResultsList').innerHTML = '';
    document.getElementById('bulkStatus').textContent = '';
    const btn = document.getElementById('btnBulkRun');
    btn.disabled = false;
    btn.innerHTML = i18n[currentLang].btnBulkRun;

    renderBulkTargets();
    document.getElementById('bulkCommandModal').style.display = 'flex';
}

function closeBulkCommandModal() {
    if (_bulkJobInterval) { clearInterval(_bulkJobInterval); _bulkJobInterval = null; }
    document.getElementById('bulkCommandModal').style.display = 'none';
}

function renderBulkTargets() {
    const group = document.getElementById('bulkGroupFilter').value;
    // Preserva le selezioni correnti durante il re-render
    const checked = new Set(getSelectedBulkIps());
    const list = document.getElementById('bulkTargetList');
    const rows = globalDevices
        .filter(d => group === 'all' || d.Group === group)
        .map(d => {
            const isOn = checked.has(d.IP) ? 'checked' : '';
            const hn = d.Hostname ? escapeHtml(d.Hostname) : '<span style="color:var(--text-muted)">—</span>';
            return `<label style="display:flex; align-items:center; gap:8px; padding:5px 6px; font-size:12px; cursor:pointer; border-radius:0;">
                <input type="checkbox" class="bulk-target" value="${escapeHtml(d.IP)}" ${isOn}>
                <span style="font-family:var(--font-code); color:var(--primary);">${escapeHtml(d.IP)}</span>
                <span>${hn}</span>
                <span class="badge" style="margin-left:auto;">${escapeHtml(d.Group)}</span>
            </label>`;
        }).join('');
    list.innerHTML = rows || `<div style="padding:12px; color:var(--text-muted); font-size:12px;">${currentLang === 'en' ? 'No devices in this tenant.' : 'Nessun dispositivo in questo tenant.'}</div>`;
    syncBulkSelectAll();
}

function toggleAllBulkTargets(on) {
    document.querySelectorAll('#bulkTargetList .bulk-target').forEach(cb => { cb.checked = on; });
}

function syncBulkSelectAll() {
    const boxes = [...document.querySelectorAll('#bulkTargetList .bulk-target')];
    const all = boxes.length > 0 && boxes.every(cb => cb.checked);
    document.getElementById('bulkSelectAll').checked = all;
}

function getSelectedBulkIps() {
    return [...document.querySelectorAll('#bulkTargetList .bulk-target:checked')].map(cb => cb.value);
}

async function startBulkCommand() {
    if (_bulkJobInterval) { clearInterval(_bulkJobInterval); _bulkJobInterval = null; }

    const ips = getSelectedBulkIps();
    const commands = document.getElementById('bulkCommands').value;
    const mode = document.getElementById('bulkMode').value;
    const save = document.getElementById('bulkSave').checked;

    if (ips.length === 0) { alert(currentLang === 'en' ? 'Select at least one device.' : 'Seleziona almeno un dispositivo.'); return; }
    if (!commands.trim()) { alert(currentLang === 'en' ? 'Enter at least one command.' : 'Inserisci almeno un comando.'); return; }

    const btn = document.getElementById('btnBulkRun');
    btn.disabled = true;
    btn.innerHTML = currentLang === 'en' ? '<i class="fa-solid fa-circle-notch fa-spin"></i> Sending...' : '<i class="fa-solid fa-circle-notch fa-spin"></i> Invio in corso...';
    document.getElementById('bulkResults').style.display = 'block';
    document.getElementById('bulkResultsList').innerHTML = '';
    document.getElementById('bulkProgressBar').style.transform = 'scaleX(0)';
    document.getElementById('bulkStatus').textContent = currentLang === 'en' ? 'Starting...' : 'Avvio...';

    const res = await apiFetch('/api/bulk-command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips, commands, mode, save }),
    });
    if (!res || !res.ok) {
        const err = res ? await res.json() : { detail: currentLang === 'en' ? 'Network error' : 'Errore di rete' };
        document.getElementById('bulkStatus').textContent =
            (currentLang === 'en' ? 'Error: ' : 'Errore: ') + (err.detail || '');
        btn.disabled = false;
        btn.innerHTML = i18n[currentLang].btnBulkRun;
        return;
    }
    const { job_id, total } = await res.json();
    pollBulkJob(job_id, total);
}

function pollBulkJob(jobId, total) {
    _bulkJobInterval = setInterval(async () => {
        const res = await apiFetch(`/api/bulk-command/${jobId}`);
        if (!res || !res.ok) {
            clearInterval(_bulkJobInterval); _bulkJobInterval = null;
            const b = document.getElementById('btnBulkRun');
            b.disabled = false; b.innerHTML = i18n[currentLang].btnBulkRun;
            return;
        }
        const data = await res.json();
        const pct = total > 0 ? Math.round((data.progress / total) * 100) : 0;
        document.getElementById('bulkProgressBar').style.transform = `scaleX(${pct / 100})`;
        document.getElementById('bulkStatus').textContent =
            currentLang === 'en' ? `Running — ${data.progress}/${total} devices...` : `In corso — ${data.progress}/${total} dispositivi...`;
        renderBulkResults(data.results || []);

        if (data.status !== 'running') {
            clearInterval(_bulkJobInterval); _bulkJobInterval = null;
            document.getElementById('bulkProgressBar').style.transform = 'scaleX(1)';
            const ok  = (data.results || []).filter(r => r.result && r.result.status === 'success').length;
            const err = (data.results || []).length - ok;
            document.getElementById('bulkStatus').textContent =
                currentLang === 'en' ? `Completed — ${ok} ok, ${err} errors.` : `Completato — ${ok} ok, ${err} errori.`;
            const b = document.getElementById('btnBulkRun');
            b.disabled = false; b.innerHTML = i18n[currentLang].btnBulkRun;
        }
    }, 1500);
}

function renderBulkResults(results) {
    const list = document.getElementById('bulkResultsList');
    list.innerHTML = results.map(r => {
        const ok = r.result && r.result.status === 'success';
        const body = ok ? (r.result.output || '') : (r.result ? (r.result.message || '') : '');
        return `<details style="border-bottom:1px solid var(--border);">
            <summary style="padding:8px 12px; cursor:pointer; display:flex; align-items:center; gap:8px; font-size:12px; list-style:none;">
                <span style="color:${ok ? 'var(--success)' : 'var(--danger)'}; font-weight:700;">${ok ? 'OK' : 'KO'}</span>
                <strong>${escapeHtml(r.hostname || r.ip)}</strong>
                <span style="font-family:var(--font-code); color:var(--text-muted);">${escapeHtml(r.ip)}</span>
            </summary>
            <pre style="margin:0; padding:10px 12px; background:var(--surface); color:var(--text); font-family:var(--font-code); font-size:11px; white-space:pre-wrap; word-break:break-word; max-height:220px; overflow:auto;">${escapeHtml(body) || '<span style="color:var(--text-muted)">—</span>'}</pre>
        </details>`;
    }).join('');
}

document.getElementById('bulkCommandModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'bulkCommandModal' || e.target.closest('#btnCloseBulkCommand')) {
        closeBulkCommandModal();
    }
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && document.getElementById('bulkCommandModal')?.style.display === 'flex') {
        closeBulkCommandModal();
    }
});

document.getElementById('bulkTargetList')?.addEventListener('change', (e) => {
    if (e.target.classList.contains('bulk-target')) {
        syncBulkSelectAll();
    }
});

document.getElementById('bulkGroupFilter')?.addEventListener('change', renderBulkTargets);
document.getElementById('bulkSelectAll')?.addEventListener('change', (e) => toggleAllBulkTargets(e.target.checked));
document.getElementById('btnBulkRun')?.addEventListener('click', startBulkCommand);


