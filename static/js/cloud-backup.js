// static/js/cloud-backup.js
// Offsite backup mirror: settings form, connection test, manual run, status.
// Classic script, one shared global scope (see AGENTS.md).

(function () {
    function fillForm(cfg) {
        document.getElementById('cbEnabled').checked = !!cfg.enabled;
        document.getElementById('cbHost').value = cfg.host || '';
        document.getElementById('cbPort').value = cfg.port || 22;
        document.getElementById('cbUsername').value = cfg.username || '';
        document.getElementById('cbAuth').value = cfg.auth || 'key';
        document.getElementById('cbKeyPath').value = cfg.key_path || '';
        document.getElementById('cbRemoteRoot').value = cfg.remote_root || '';
        document.getElementById('cbEncrypt').checked = !!cfg.encrypt_payload;
        document.getElementById('cbRunAfterBackup').checked = !!cfg.run_after_backup;
        // The secret is never sent back by the API: an empty field means
        // "keep the stored one", and the placeholder says so.
        document.getElementById('cbSecret').value = '';
        document.getElementById('cbSecret').placeholder = (cfg.has_password || cfg.has_key_passphrase)
            ? (currentLang === 'en' ? 'stored - leave empty to keep'
                                    : 'salvata - lascia vuoto per mantenerla')
            : '';
    }

    function formValues() {
        const auth = document.getElementById('cbAuth').value;
        const secret = document.getElementById('cbSecret').value;
        return {
            enabled: document.getElementById('cbEnabled').checked,
            kind: 'sftp',
            host: document.getElementById('cbHost').value.trim(),
            port: parseInt(document.getElementById('cbPort').value, 10) || 22,
            username: document.getElementById('cbUsername').value.trim(),
            auth: auth,
            key_path: document.getElementById('cbKeyPath').value.trim(),
            key_passphrase: auth === 'key' ? secret : '',
            password: auth === 'password' ? secret : '',
            remote_root: document.getElementById('cbRemoteRoot').value.trim(),
            encrypt_payload: document.getElementById('cbEncrypt').checked,
            run_after_backup: document.getElementById('cbRunAfterBackup').checked,
        };
    }

    function renderStatus(st) {
        const box = document.getElementById('cbStatusBox');
        if (!box) return;
        if (!st.enabled) {
            box.textContent = i18n[currentLang].cbDisabled;
            return;
        }
        const hours = st.hours_since_success;
        const stale = hours === null || hours > (st.stale_after_hours || 48);
        const age = hours === null
            ? i18n[currentLang].cbNeverRan
            : `${i18n[currentLang].cbStale}: ${Math.round(hours)} h`;
        const last = st.last_run || {};
        box.innerHTML =
            `<div style="color:${stale ? 'var(--warning)' : 'var(--success)'}; font-weight:700;">${escapeHtml(age)}</div>` +
            `<div>${escapeHtml(i18n[currentLang].cbPending)}: <strong>${st.pending}</strong></div>` +
            `<div>${escapeHtml(i18n[currentLang].cbLastRun)}: ${last.ok ? 'ok' : escapeHtml(last.error || '—')}` +
            ` · ${last.uploaded || 0} ↑ · ${last.verified || 0} ✓</div>`;
    }

    async function loadCloudBackup() {
        const res = await apiFetch('/api/cloud-backup/settings');
        if (res && res.ok) fillForm(await res.json());
        const st = await apiFetch('/api/cloud-backup/status');
        if (st && st.ok) renderStatus(await st.json());
    }

    document.getElementById('cbBtnSave')?.addEventListener('click', async () => {
        const res = await apiFetch('/api/cloud-backup/settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formValues()),
        });
        if (res && res.ok) {
            showToast(i18n[currentLang].cbSaved, 'success');
            loadCloudBackup();
        } else {
            const body = res ? await res.json() : {};
            showToast(body.detail || 'errore', 'error');
        }
    });

    document.getElementById('cbBtnTest')?.addEventListener('click', async () => {
        const res = await apiFetch('/api/cloud-backup/test', { method: 'POST' });
        const data = (res && res.ok) ? await res.json() : { ok: false, error: 'HTTP' };
        showToast(data.ok ? `${i18n[currentLang].cbTestOk} ${data.fingerprint}` : data.error,
                  data.ok ? 'success' : 'error');
    });

    document.getElementById('cbBtnRun')?.addEventListener('click', async () => {
        const res = await apiFetch('/api/cloud-backup/run', { method: 'POST' });
        const data = (res && res.ok) ? await res.json() : { ok: false, error: 'HTTP' };
        showToast(data.ok ? i18n[currentLang].cbRunOk : data.error,
                  data.ok ? 'success' : 'error');
        loadCloudBackup();
    });

    window.loadCloudBackup = loadCloudBackup;
})();
