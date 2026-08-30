// static/js/cloud-backup.js
// Offsite backup mirror: settings form, connection test, manual run, status.
// Classic script, one shared global scope (see AGENTS.md).

(function () {
    // Set true only after the stored config has actually loaded into the
    // form. Save must refuse to run before that: on a failed GET the form
    // sits at its HTML defaults, and a PUT of those defaults would blank
    // out the stored host/username/paths (the router only protects secrets
    // from an accidental clear, not the rest of the fields).
    let loaded = false;

    function fillForm(cfg) {
        document.getElementById('cbEnabled').checked = !!cfg.enabled;
        document.getElementById('cbHost').value = cfg.host || '';
        document.getElementById('cbPort').value = cfg.port || 22;
        document.getElementById('cbUsername').value = cfg.username || '';
        document.getElementById('cbAuth').value = cfg.auth || 'key';
        document.getElementById('cbKeyPath').value = cfg.key_path || '';
        document.getElementById('cbRemoteRoot').value = cfg.remote_root || '';
        document.getElementById('cbFingerprint').value = cfg.host_key_fingerprint || '';
        document.getElementById('cbEncrypt').checked = !!cfg.encrypt_payload;
        document.getElementById('cbRunAfterBackup').checked = !!cfg.run_after_backup;
        // The secret is never sent back by the API: an empty field means
        // "keep the stored one", and the placeholder says so.
        document.getElementById('cbSecret').value = '';
        document.getElementById('cbSecret').placeholder = (cfg.has_password || cfg.has_key_passphrase)
            ? (tr('uiStoredLeaveEmptyTo'))
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
            // Safe to send only because Save refuses to run before the stored
            // config has loaded into the form: an empty field would otherwise
            // unpin the host key (empty pin = trust-on-first-use).
            host_key_fingerprint: document.getElementById('cbFingerprint').value.trim(),
            encrypt_payload: document.getElementById('cbEncrypt').checked,
            run_after_backup: document.getElementById('cbRunAfterBackup').checked,
        };
    }

    function renderStatus(st) {
        const box = document.getElementById('cbStatusBox');
        if (!box) return;
        if (!st.enabled) {
            box.innerHTML =
                `<div style="display:flex; align-items:center; gap:8px; font-size:12.5px; color:var(--text-muted);">` +
                `<span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--lamp-idle); flex-shrink:0;"></span>` +
                `<span>${escapeHtml(i18n[currentLang].cbDisabled)}</span>` +
                `</div>`;
            return;
        }
        const hours = st.hours_since_success;
        const stale = hours === null || hours > (st.stale_after_hours || 48);
        const age = hours === null
            ? i18n[currentLang].cbNeverRan
            : `${Math.round(hours)} h`;
        const last = st.last_run || {};
        const stateColor = stale ? 'var(--lamp-warn)' : 'var(--lamp-up)';
        const stateInk = stale ? 'var(--lamp-warn-ink)' : 'var(--lamp-up-ink)';

        box.innerHTML =
            `<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:10px; font-size:12.5px;">` +
            `  <div style="background:var(--surface); border:1px solid var(--border); padding:8px 12px; display:flex; align-items:center; gap:10px;">` +
            `    <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:${stateColor}; flex-shrink:0;"></span>` +
            `    <div>` +
            `      <div style="font-size:10.5px; text-transform:uppercase; letter-spacing:0.04em; color:var(--text-muted);">${escapeHtml(i18n[currentLang].cbStale)}</div>` +
            `      <div style="font-weight:700; color:${stateInk}; font-family:var(--font-mono, 'Azeret Mono');">${escapeHtml(age)}</div>` +
            `    </div>` +
            `  </div>` +
            `  <div style="background:var(--surface); border:1px solid var(--border); padding:8px 12px; display:flex; align-items:center; gap:10px;">` +
            `    <i class="fa-solid fa-clock-rotate-left" style="color:var(--text-muted); font-size:13px;"></i>` +
            `    <div>` +
            `      <div style="font-size:10.5px; text-transform:uppercase; letter-spacing:0.04em; color:var(--text-muted);">${escapeHtml(i18n[currentLang].cbPending)}</div>` +
            `      <div style="font-weight:700; font-family:var(--font-mono, 'Azeret Mono');">${escapeHtml(String(st.pending))}</div>` +
            `    </div>` +
            `  </div>` +
            `  <div style="background:var(--surface); border:1px solid var(--border); padding:8px 12px; display:flex; align-items:center; gap:10px;">` +
            `    <i class="fa-solid ${last.ok ? 'fa-circle-check' : 'fa-triangle-exclamation'}" style="color:${last.ok ? 'var(--lamp-up)' : 'var(--lamp-fault)'}; font-size:13px;"></i>` +
            `    <div>` +
            `      <div style="font-size:10.5px; text-transform:uppercase; letter-spacing:0.04em; color:var(--text-muted);">${escapeHtml(i18n[currentLang].cbLastRun)}</div>` +
            `      <div style="font-weight:600; font-size:12px; font-family:var(--font-mono, 'Azeret Mono');">${last.ok ? 'OK · ' + escapeHtml(String(last.uploaded || 0)) + ' ↑ · ' + escapeHtml(String(last.verified || 0)) + ' ✓' : escapeHtml(last.error || '—')}</div>` +
            `    </div>` +
            `  </div>` +
            `</div>`;
    }

    function renderLoadError() {
        const box = document.getElementById('cbStatusBox');
        if (box) box.textContent = i18n[currentLang].cbErrGeneric;
        showToast(i18n[currentLang].cbErrGeneric, 'error');
    }

    async function loadCloudBackup() {
        loaded = false;
        const res = await apiFetch('/api/cloud-backup/settings');
        if (!res || !res.ok) { renderLoadError(); return; }
        fillForm(await res.json());
        loaded = true;
        const st = await apiFetch('/api/cloud-backup/status');
        if (st && st.ok) renderStatus(await st.json());
    }

    document.getElementById('cbBtnSave')?.addEventListener('click', async () => {
        if (!loaded) { showToast(i18n[currentLang].cbErrGeneric, 'error'); return; }
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
            showToast(body.detail || i18n[currentLang].cbErrGeneric, 'error');
        }
    });

    document.getElementById('cbBtnTest')?.addEventListener('click', async () => {
        const res = await apiFetch('/api/cloud-backup/test', { method: 'POST' });
        const data = (res && res.ok) ? await res.json() : { ok: false, error: i18n[currentLang].cbErrHttp };
        if (!data.ok) {
            showToast(data.error || i18n[currentLang].cbErrGeneric, 'error');
            return;
        }
        // The observed fingerprint is only useful if it can be pinned: drop it
        // into the empty field and say that Save is what makes it stick.
        let msg = `${i18n[currentLang].cbTestOk} ${data.fingerprint}`;
        const field = document.getElementById('cbFingerprint');
        if (field && !field.value.trim() && data.fingerprint) {
            field.value = data.fingerprint;
            msg += ` — ${i18n[currentLang].cbPinHint}`;
        }
        showToast(msg, 'success');
    });

    document.getElementById('cbBtnRun')?.addEventListener('click', async () => {
        const res = await apiFetch('/api/cloud-backup/run', { method: 'POST' });
        const data = (res && res.ok) ? await res.json() : { ok: false, error: i18n[currentLang].cbErrHttp };
        showToast(data.ok ? i18n[currentLang].cbRunOk : (data.error || i18n[currentLang].cbErrGeneric),
                  data.ok ? 'success' : 'error');
        loadCloudBackup();
    });

    window.loadCloudBackup = loadCloudBackup;
})();
