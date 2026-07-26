// static/js/audit_checklist.js
// Frontend logic for Audit Checklist Tab (Firewall Maintenance Audit)

(function () {
    let currentAuditEngagementId = null;
    let currentAuditData = null;

    async function loadAuditChecklistTab() {
        const btn = document.getElementById("navAuditChecklist");
        if (btn) btn.style.display = "flex";

        const container = document.getElementById("auditEngagementList");
        if (!container) return;

        container.innerHTML = '<div style="color:var(--text-muted); font-size:13px;"><i class="fa-solid fa-spinner fa-spin"></i> Caricamento audit in corso...</div>';

        try {
            const res = await apiFetch("/api/audit-checklist/engagements");
            if (!res || !res.ok) {
                container.innerHTML = '<div style="color:var(--danger); font-size:13px;">Errore durante il caricamento degli audit.</div>';
                return;
            }
            const data = await res.json();
            renderEngagementList(data);
        } catch (e) {
            console.error("Errore audit checklist tab:", e);
            container.innerHTML = '<div style="color:var(--danger); font-size:13px;">Errore di connessione API.</div>';
        }
    }

    function renderEngagementList(engagements) {
        const container = document.getElementById("auditEngagementList");
        if (!engagements || engagements.length === 0) {
            container.innerHTML = `
                <div style="text-align:center; padding:30px 10px; color:var(--text-muted);">
                    <i class="fa-solid fa-folder-open" style="font-size:32px; margin-bottom:10px; opacity:0.5;"></i>
                    <p style="margin:0 0 10px; font-size:14px;">Nessun audit di manutenzione registrato.</p>
                    <button class="btn btn-primary btn-small" style="width:auto;" onclick="openNewAuditModal()"><i class="fa-solid fa-plus"></i> Avvia Primo Audit</button>
                </div>
            `;
            return;
        }

        let html = `
            <table style="width:100%; border-collapse:collapse; font-size:13px;">
                <thead>
                    <tr style="background:var(--surface-3); border-bottom:1px solid var(--border);">
                        <th style="padding:10px; text-align:left;">Cliente</th>
                        <th style="padding:10px; text-align:left;">Modalità</th>
                        <th style="padding:10px; text-align:left;">Stato</th>
                        <th style="padding:10px; text-align:center;">Avanzamento</th>
                        <th style="padding:10px; text-align:center;">Conformi / Anomalie</th>
                        <th style="padding:10px; text-align:right;">Azioni</th>
                    </tr>
                </thead>
                <tbody>
        `;

        engagements.forEach(e => {
            const pct = e.total_items > 0 ? Math.round((e.evaluated_items / e.total_items) * 100) : 0;
            let statusBadge = `<span style="background:var(--surface-2); padding:3px 8px; border-radius:4px; font-size:11px; text-transform:uppercase;">${escapeHtml(e.status)}</span>`;
            if (e.status === 'completed') {
                statusBadge = `<span style="background:var(--success); color:white; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:bold; text-transform:uppercase;">Completato</span>`;
            } else if (e.status === 'in_progress') {
                statusBadge = `<span style="background:var(--cta); color:white; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:bold; text-transform:uppercase;">In Corso</span>`;
            }

            html += `
                <tr style="border-bottom:1px solid var(--border);">
                    <td style="padding:10px;">
                        <strong>${escapeHtml(e.customer_name)}</strong>
                        <div style="font-size:11px; color:var(--text-muted);">v${e.template_version} (${escapeHtml(e.template_name)})</div>
                    </td>
                    <td style="padding:10px; font-size:12px; text-transform:capitalize;">${escapeHtml(e.onsite_or_remote)}</td>
                    <td style="padding:10px;">${statusBadge}</td>
                    <td style="padding:10px; text-align:center;">
                        <div style="font-weight:600; font-size:12px;">${pct}%</div>
                        <div style="background:var(--surface-3); height:5px; border-radius:3px; overflow:hidden; margin-top:3px; width:80px; display:inline-block;">
                            <div style="background:var(--primary); height:100%; width:${pct}%;"></div>
                        </div>
                    </td>
                    <td style="padding:10px; text-align:center; font-size:12px;">
                        <span style="color:var(--success); font-weight:bold;">${e.conforme_count || 0}</span> / 
                        <span style="color:var(--danger); font-weight:bold;">${e.non_conforme_count || 0}</span>
                        ${(e.da_verificare_count || 0) > 0 ? ` / <span style="color:var(--cta); font-weight:bold;">${e.da_verificare_count} da verif.</span>` : ''}
                    </td>
                    <td style="padding:10px; text-align:right;">
                        <button class="btn btn-secondary btn-small" style="width:auto; margin:0 3px;" onclick="openAuditWorkspace(${e.id})"><i class="fa-solid fa-pen-to-square"></i> Apri</button>
                        <button class="btn btn-secondary btn-small" style="width:auto; margin:0;" onclick="viewAuditReportForId(${e.id})"><i class="fa-solid fa-file-lines"></i> Relazione</button>
                    </td>
                </tr>
            `;
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    async function openNewAuditModal() {
        const customerName = prompt("Inserisci il nome del cliente / azienda per l'audit:");
        if (!customerName || !customerName.trim()) return;

        try {
            const res = await apiFetch("/api/audit-checklist/engagements", {
                method: "POST",
                body: JSON.stringify({
                    customer_name: customerName.trim(),
                    onsite_or_remote: "onsite"
                })
            });
            if (!res || !res.ok) {
                alert("Errore durante la creazione dell'audit.");
                return;
            }
            const newEng = await res.json();
            loadAuditChecklistTab();
            openAuditWorkspace(newEng.id);
        } catch (e) {
            console.error("Errore creazione audit:", e);
            alert("Errore di rete durante la creazione dell'audit.");
        }
    }

    async function openAuditWorkspace(engId) {
        currentAuditEngagementId = engId;
        const workspace = document.getElementById("auditWorkspace");
        if (!workspace) return;

        workspace.style.display = "block";
        workspace.scrollIntoView({ behavior: "smooth" });

        const header = document.getElementById("auditWorkHeader");
        const sub = document.getElementById("auditWorkSub");
        const accordion = document.getElementById("auditSectionAccordion");

        header.textContent = "Caricamento in corso...";
        accordion.innerHTML = '<div style="padding:20px; text-align:center; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> Caricamento elementi della checklist...</div>';

        try {
            const res = await apiFetch(`/api/audit-checklist/engagements/${engId}`);
            if (!res || !res.ok) {
                accordion.innerHTML = '<div style="color:var(--danger);">Impossibile caricare i dati dell\'audit.</div>';
                return;
            }
            currentAuditData = await res.json();
            header.textContent = `Audit Firewall — ${currentAuditData.customer_name}`;
            sub.textContent = `Stato: ${currentAuditData.status.toUpperCase()} | Modalità: ${currentAuditData.onsite_or_remote.toUpperCase()} | Template: v${currentAuditData.template_version}`;

            renderAuditWorkspaceSections(currentAuditData.items);
        } catch (e) {
            console.error("Errore workspace audit:", e);
            accordion.innerHTML = '<div style="color:var(--danger);">Errore di comunicazione API.</div>';
        }
    }

    function renderAuditWorkspaceSections(items) {
        const accordion = document.getElementById("auditSectionAccordion");
        if (!accordion) return;

        // Raggruppa item per sezione
        const sectionsMap = {};
        items.forEach(item => {
            const secKey = `Sezione ${item.section_no} — ${item.section_title}`;
            if (!sectionsMap[secKey]) sectionsMap[secKey] = [];
            sectionsMap[secKey].push(item);
        });

        let html = "";
        Object.keys(sectionsMap).forEach((secTitle, idx) => {
            const secItems = sectionsMap[secTitle];
            const evalCount = secItems.filter(i => i.status !== 'non_valutato').length;

            html += `
                <details style="border:1px solid var(--border); border-radius:6px; margin-bottom:12px; background:var(--surface);" ${idx === 0 ? 'open' : ''}>
                    <summary style="padding:12px 16px; cursor:pointer; font-weight:600; font-size:15px; display:flex; justify-content:space-between; align-items:center; background:var(--surface-2);">
                        <span>${escapeHtml(secTitle)}</span>
                        <span style="font-size:12px; color:var(--text-muted); font-weight:normal;">${evalCount}/${secItems.length} valutati</span>
                    </summary>
                    <div style="padding:16px;">
            `;

            secItems.forEach(item => {
                const prereqBadge = item.is_prerequisite ? '<span style="background:var(--danger); color:white; font-size:10px; padding:2px 6px; border-radius:3px; font-weight:bold; margin-left:6px;">PREREQUISITO</span>' : '';
                const evBadge = item.requires_evidence ? '<span style="background:var(--cta); color:white; font-size:10px; padding:2px 6px; border-radius:3px; font-weight:bold; margin-left:6px;">EVIDENZA RICHIESTA</span>' : '';

                html += `
                    <div style="border:1px solid var(--border); border-radius:6px; padding:14px; margin-bottom:14px; background:var(--surface-3);">
                        <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:10px; margin-bottom:8px;">
                            <div>
                                <strong style="font-size:14px;">Item ${escapeHtml(item.item_ref)} — ${escapeHtml(item.title)}</strong>
                                ${prereqBadge} ${evBadge}
                            </div>
                            <div>
                                <select id="status_${item.item_ref}" style="padding:4px 8px; border-radius:4px; border:1px solid var(--border); font-size:12px; font-weight:bold;">
                                    <option value="non_valutato" ${item.status === 'non_valutato' ? 'selected' : ''}>NON VALUTATO</option>
                                    <option value="conforme" ${item.status === 'conforme' ? 'selected' : ''} style="color:green;">CONFORME</option>
                                    <option value="parziale" ${item.status === 'parziale' ? 'selected' : ''} style="color:orange;">PARZIALE</option>
                                    <option value="non_conforme" ${item.status === 'non_conforme' ? 'selected' : ''} style="color:red;">NON CONFORME</option>
                                    <option value="da_verificare" ${item.status === 'da_verificare' ? 'selected' : ''} style="color:blue;">DA VERIFICARE</option>
                                    <option value="non_applicabile" ${item.status === 'non_applicabile' ? 'selected' : ''}>NON APPLICABILE</option>
                                </select>
                                <select id="sev_${item.item_ref}" style="padding:4px 8px; border-radius:4px; border:1px solid var(--border); font-size:12px;">
                                    <option value="critica" ${item.severity === 'critica' ? 'selected' : ''}>Critica</option>
                                    <option value="alta" ${item.severity === 'alta' ? 'selected' : ''}>Alta</option>
                                    <option value="media" ${item.severity === 'media' ? 'selected' : ''}>Media</option>
                                    <option value="bassa" ${item.severity === 'bassa' ? 'selected' : ''}>Bassa</option>
                                    <option value="osservazione" ${item.severity === 'osservazione' ? 'selected' : ''}>Osservazione</option>
                                </select>
                            </div>
                        </div>
                        <div style="font-size:12px; color:var(--text-muted); margin-bottom:10px; background:var(--surface); padding:8px; border-radius:4px; border-left:3px solid var(--primary);">
                            <strong>Perché è importante:</strong> ${escapeHtml(item.guidance_why || '')}<br>
                            <strong>Cosa cercare:</strong> ${escapeHtml(item.guidance_good || '')}
                        </div>
                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:10px;">
                            <div>
                                <label style="display:block; font-size:11px; font-weight:bold; margin-bottom:4px;">Rilievo / Esito dell'audit:</label>
                                <textarea id="finding_${item.item_ref}" rows="2" style="width:100%; font-size:12px; padding:6px; border-radius:4px; border:1px solid var(--border); background:var(--surface);" placeholder="Descrivi il riscontro ottenuto...">${escapeHtml(item.finding_text || '')}</textarea>
                            </div>
                            <div>
                                <label style="display:block; font-size:11px; font-weight:bold; margin-bottom:4px;">Raccomandazione per la relazione:</label>
                                <textarea id="recom_${item.item_ref}" rows="2" style="width:100%; font-size:12px; padding:6px; border-radius:4px; border:1px solid var(--border); background:var(--surface);" placeholder="Azione correttiva consigliata...">${escapeHtml(item.recommendation_text || '')}</textarea>
                            </div>
                        </div>
                        <div style="display:flex; justify-content:flex-end;">
                            <button class="btn btn-primary btn-small" style="width:auto;" onclick="saveAuditItem('${item.item_ref}')"><i class="fa-solid fa-floppy-disk"></i> Salva Rigo</button>
                        </div>
                    </div>
                `;
            });

            html += `</div></details>`;
        });

        accordion.innerHTML = html;
    }

    async function saveAuditItem(itemRef) {
        if (!currentAuditEngagementId) return;

        const st = document.getElementById(`status_${itemRef}`).value;
        const sev = document.getElementById(`sev_${itemRef}`).value;
        const finding = document.getElementById(`finding_${itemRef}`).value;
        const recom = document.getElementById(`recom_${itemRef}`).value;

        try {
            const res = await apiFetch(`/api/audit-checklist/engagements/${currentAuditEngagementId}/items/${itemRef}`, {
                method: "PUT",
                body: JSON.stringify({
                    status: st,
                    severity: sev,
                    finding_text: finding,
                    recommendation_text: recom
                })
            });
            if (!res || !res.ok) {
                alert("Errore durante il salvataggio dell'item.");
                return;
            }
            alert(`Item ${itemRef} salvato con successo!`);
        } catch (e) {
            console.error("Errore salvataggio item audit:", e);
            alert("Errore di comunicazione durante il salvataggio.");
        }
    }

    function viewAuditReport() {
        if (!currentAuditEngagementId) return;
        viewAuditReportForId(currentAuditEngagementId);
    }

    function viewAuditReportForId(engId) {
        window.open(`/api/audit-checklist/engagements/${engId}/report`, "_blank");
    }

    function closeAuditWorkspace() {
        const workspace = document.getElementById("auditWorkspace");
        if (workspace) workspace.style.display = "none";
        currentAuditEngagementId = null;
    }

    async function applyAuditChecklistGating() {
        try {
            const res = await apiFetch('/api/settings/audit-checklist');
            if (!res || !res.ok) return;
            const data = await res.json();
            const nav = document.getElementById('navAuditChecklist');
            if (nav) nav.style.display = data.audit_checklist_preview ? '' : 'none';
            const toggle = document.getElementById('auditChecklistToggle');
            if (toggle) toggle.checked = !!data.audit_checklist_preview;
        } catch (e) {}
    }

    async function setAuditChecklistPreview(enabled) {
        const st = document.getElementById('auditChecklistStatus');
        try {
            const res = await apiFetch('/api/settings/audit-checklist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: !!enabled })
            });
            if (res && res.ok) {
                if (st) st.textContent = (typeof currentLang !== 'undefined' && currentLang === 'en') ? 'Saved.' : 'Salvato.';
                await applyAuditChecklistGating();
            }
        } catch (e) {
            if (st) st.textContent = (typeof currentLang !== 'undefined' && currentLang === 'en') ? 'Error.' : 'Errore.';
        }
    }

    // Esporta funzioni globali
    window.loadAuditChecklistTab = loadAuditChecklistTab;
    window.openNewAuditModal = openNewAuditModal;
    window.openAuditWorkspace = openAuditWorkspace;
    window.saveAuditItem = saveAuditItem;
    window.viewAuditReport = viewAuditReport;
    window.viewAuditReportForId = viewAuditReportForId;
    window.closeAuditWorkspace = closeAuditWorkspace;
    window.setAuditChecklistPreview = setAuditChecklistPreview;
    window.applyAuditChecklistGating = applyAuditChecklistGating;

    document.addEventListener("DOMContentLoaded", () => {
        applyAuditChecklistGating();
    });
})();
