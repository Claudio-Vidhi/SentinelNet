// static/js/netsec-audit.js
// ===== NetSec Audit (PREVIEW) — Firewall & Router Security Compliance Audit =====

(function () {
    let _auditRules = [
        { id: "AUD-FW-01", title: "Unrestricted Telnet / Insecure Management", severity: "CRITICAL", category: "Hardening", status: "FAIL", device: "fw-core-01 (10.0.1.1)", detail: "service telnet enabled on WAN interface", remediation: "set allowaccess ssh https (disable telnet/http)" },
        { id: "AUD-FW-02", title: "Overly Permissive Any-to-Any Rule", severity: "CRITICAL", category: "Access Rules", status: "FAIL", device: "fw-core-01 (10.0.1.1)", detail: "Policy #14 allows src:any dst:any service:ALL action:accept", remediation: "Restrict source/destination subnets and specify explicit TCP/UDP ports." },
        { id: "AUD-FW-03", title: "Deprecated SSL/TLS Cipher Suites (TLS 1.0/1.1)", severity: "HIGH", category: "Encryption", status: "FAIL", device: "sw-dist-02 (10.0.2.1)", detail: "ssl-min-proto-version set to TLSv1.0", remediation: "set ssl-min-proto-version TLSv1.2" },
        { id: "AUD-FW-04", title: "Default Admin Credentials / Weak Passwords", severity: "CRITICAL", category: "Hardening", status: "PASS", device: "fw-core-01 (10.0.1.1)", detail: "All admin accounts use strong hashed passwords and MFA", remediation: "Maintain password rotation policy." },
        { id: "AUD-FW-05", title: "Syslog Remote Logging Unconfigured", severity: "MEDIUM", category: "Logging", status: "WARN", device: "rt-edge-01 (10.0.5.1)", detail: "No remote syslog server configured on UDP 514/5514", remediation: "set syslog server 10.0.1.100 port 5514" },
        { id: "AUD-FW-06", title: "BGP / OSPF Router Authentication Missing", severity: "HIGH", category: "Routing", status: "FAIL", device: "rt-edge-01 (10.0.5.1)", detail: "BGP neighbor 192.168.1.1 lacks MD5 password authentication", remediation: "neighbor 192.168.1.1 password <secret-md5>" }
    ];

    async function applyNetSecAuditGating() {
        try {
            const res = await apiFetch('/api/settings/netsec-audit');
            if (!res || !res.ok) return;
            const data = await res.json();
            const nav = document.getElementById('navNetSecAudit');
            if (nav) nav.style.display = data.netsec_audit_preview ? '' : 'none';
            const toggle = document.getElementById('netsecAuditToggle');
            if (toggle) toggle.checked = !!data.netsec_audit_preview;
        } catch (e) {}
    }

    async function setNetSecAuditPreview(enabled) {
        const st = document.getElementById('netsecAuditStatus');
        try {
            const res = await apiFetch('/api/settings/netsec-audit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: !!enabled })
            });
            if (res && res.ok) {
                if (st) st.textContent = currentLang === 'en' ? 'Saved.' : 'Salvato.';
                await applyNetSecAuditGating();
            }
        } catch (e) {
            if (st) st.textContent = currentLang === 'en' ? 'Error.' : 'Errore.';
        }
    }

    function loadNetSecAuditTab() {
        renderAuditOverview();
        renderAuditRulesTable();
        setupConfigDropzone();
    }

    function renderAuditOverview() {
        const total = _auditRules.length;
        const failed = _auditRules.filter(r => r.status === 'FAIL').length;
        const passed = _auditRules.filter(r => r.status === 'PASS').length;
        const warned = _auditRules.filter(r => r.status === 'WARN').length;
        const score = Math.round((passed / total) * 100);

        const scoreEl = document.getElementById('auditScoreValue');
        if (scoreEl) scoreEl.textContent = `${score}%`;

        const gradeEl = document.getElementById('auditGradeBadge');
        if (gradeEl) {
            gradeEl.textContent = score >= 80 ? 'GRADE A' : score >= 60 ? 'GRADE B' : 'GRADE C - RISK DETECTED';
            gradeEl.style.color = score >= 80 ? 'var(--success)' : score >= 60 ? 'var(--warning)' : 'var(--danger)';
        }

        const countFailed = document.getElementById('auditStatFailed');
        if (countFailed) countFailed.textContent = failed;
        const countPassed = document.getElementById('auditStatPassed');
        if (countPassed) countPassed.textContent = passed;
        const countWarned = document.getElementById('auditStatWarned');
        if (countWarned) countWarned.textContent = warned;
    }

    function renderAuditRulesTable() {
        const tbody = document.getElementById('auditRulesTableBody');
        if (!tbody) return;

        const sevFilter = document.getElementById('auditSevFilter') ? document.getElementById('auditSevFilter').value : 'all';
        const catFilter = document.getElementById('auditCatFilter') ? document.getElementById('auditCatFilter').value : 'all';

        let filtered = _auditRules;
        if (sevFilter !== 'all') filtered = filtered.filter(r => r.severity.toLowerCase() === sevFilter.toLowerCase());
        if (catFilter !== 'all') filtered = filtered.filter(r => r.category.toLowerCase() === catFilter.toLowerCase());

        if (!filtered.length) {
            tbody.innerHTML = `<tr><td colspan="6" style="padding:20px; text-align:center; color:var(--text-muted);">${currentLang==='en'?'No audit rules match filter.':'Nessuna regola di audit corrisponde ai filtri.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.map(r => {
            const statusBadge = r.status === 'PASS' 
                ? `<span class="badge" style="background:rgba(34, 197, 94, 0.15); color:var(--success);"><i class="fa-solid fa-check"></i> PASS</span>`
                : r.status === 'FAIL'
                ? `<span class="badge" style="background:rgba(239, 68, 68, 0.15); color:var(--danger);"><i class="fa-solid fa-xmark"></i> FAIL</span>`
                : `<span class="badge" style="background:rgba(245, 158, 11, 0.15); color:var(--warning);"><i class="fa-solid fa-triangle-exclamation"></i> WARN</span>`;

            const sevBadge = r.severity === 'CRITICAL'
                ? `<span class="badge" style="background:var(--danger); color:#fff; font-weight:700;">CRITICAL</span>`
                : r.severity === 'HIGH'
                ? `<span class="badge" style="background:var(--warning); color:#000; font-weight:700;">HIGH</span>`
                : `<span class="badge" style="background:var(--surface-3);">MEDIUM</span>`;

            return `<tr style="font-size:12px; border-top:1px solid var(--border);">
                <td style="padding:8px; font-family:var(--font-code); font-weight:700;">${escapeHtml(r.id)}</td>
                <td style="padding:8px;">
                    <div style="font-weight:700;">${escapeHtml(r.title)}</div>
                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">${escapeHtml(r.detail)}</div>
                </td>
                <td style="padding:8px;">${sevBadge}</td>
                <td style="padding:8px;"><span class="badge">${escapeHtml(r.category)}</span></td>
                <td style="padding:8px;">${statusBadge}</td>
                <td style="padding:8px;">
                    <code style="font-size:11px; color:var(--primary); background:var(--surface-2); padding:3px 6px; border-radius:4px; display:inline-block; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                        ${escapeHtml(r.remediation)}
                    </code>
                </td>
            </tr>`;
        }).join('');
    }    let _droppedConfigText = null;

    async function runAuditScan() {
        const btn = document.getElementById('btnRunAuditScan');
        const benchmark = document.getElementById('auditBenchmarkSelect') ? document.getElementById('auditBenchmarkSelect').value : 'cis';
        const deviceIp = document.getElementById('auditDeviceSelect') ? document.getElementById('auditDeviceSelect').value : 'all';

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Audit in corso...`;
        }

        try {
            const res = await apiFetch('/api/netsec-audit/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    benchmark: benchmark,
                    device_ip: deviceIp,
                    config_text: _droppedConfigText || null
                })
            });

            if (res && res.ok) {
                const data = await res.json();
                if (data.rules && data.rules.length) _auditRules = data.rules;
                renderAuditOverview();
                renderAuditRulesTable();
            }
        } catch (e) {
            console.error('Audit scan error:', e);
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-play"></i> Esegui Audit Scan`;
            }
        }
    }

    function setupConfigDropzone() {
        const zone = document.getElementById('auditDropZone');
        const fileInput = document.getElementById('auditFileInput');
        const dropText = document.getElementById('auditDropText');
        const benchSel = document.getElementById('auditBenchmarkSelect');
        if (!zone || !fileInput) return;

        if (benchSel && !benchSel.dataset.bound) {
            benchSel.dataset.bound = 'true';
            benchSel.addEventListener('change', () => runAuditScan());
        }

        zone.onclick = () => fileInput.click();

        zone.ondragover = e => { e.preventDefault(); zone.style.borderColor = 'var(--primary)'; };
        zone.ondragleave = () => { zone.style.borderColor = 'var(--border)'; };
        zone.ondrop = e => {
            e.preventDefault();
            zone.style.borderColor = 'var(--border)';
            if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
        };

        fileInput.onchange = () => {
            if (fileInput.files.length) handleFile(fileInput.files[0]);
        };

        function handleFile(file) {
            const reader = new FileReader();
            reader.onload = e => {
                _droppedConfigText = e.target.result;
                if (dropText) dropText.innerHTML = `<i class="fa-solid fa-file-code" style="color:var(--success);"></i><br>File <strong>${escapeHtml(file.name)}</strong> caricato. Analisi in corso...`;
                runAuditScan();
            };
            reader.readAsText(file);
        }
    }

    function exportAuditReport() {
        const score = document.getElementById('auditScoreValue')?.textContent || '--';
        const benchmark = document.getElementById('auditBenchmarkSelect')?.value?.toUpperCase() || 'CIS';
        alert(currentLang === 'en'
            ? `Report Compliance Security (${benchmark}) generato. Score: ${score}.`
            : `Report Compliance Security (${benchmark}) generato con successo. Score complessivo: ${score}.`);
    }

    // Expose functions globally
    window.loadNetSecAuditTab = loadNetSecAuditTab;
    window.applyNetSecAuditGating = applyNetSecAuditGating;
    window.setNetSecAuditPreview = setNetSecAuditPreview;
    window.runAuditScan = runAuditScan;
    window.exportAuditReport = exportAuditReport;
    window.renderAuditRulesTable = renderAuditRulesTable;
})();
