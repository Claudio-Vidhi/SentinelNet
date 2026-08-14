// static/js/audit_checklist.js
// Frontend logic for Audit Checklist Tab (Firewall Maintenance Audit)

(function () {
    let currentAuditEngagementId = null;
    let currentAuditData = null;
    let currentTemplate = null;   // template attivo (versione piu' recente)
    let editingItemRef = null;    // null = modale in modalita' creazione

    async function loadAuditChecklistTab() {
        loadAuditTemplate();

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
                    <i class="fa-solid fa-folder-open" style="font-size:30px; margin-bottom:10px; opacity:0.5;"></i>
                    <p style="margin:0 0 10px; font-size:14px;">Nessun audit di manutenzione registrato.</p>
                    <button class="btn btn-primary btn-small" style="width:auto;" data-action="open-new-audit"><i class="fa-solid fa-plus"></i> Avvia Primo Audit</button>
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
            let statusBadge = `<span style="background:var(--surface-2); padding:3px 8px; border-radius:0; font-size:11px; text-transform:uppercase;">${escapeHtml(e.status)}</span>`;
            if (e.status === 'completed') {
                statusBadge = `<span style="background:var(--success); color:white; padding:3px 8px; border-radius:0; font-size:11px; font-weight:bold; text-transform:uppercase;">Completato</span>`;
            } else if (e.status === 'in_progress') {
                statusBadge = `<span style="background:var(--cta); color:white; padding:3px 8px; border-radius:0; font-size:11px; font-weight:bold; text-transform:uppercase;">In Corso</span>`;
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
                        <div style="background:var(--surface-3); height:5px; border-radius:0; overflow:hidden; margin-top:3px; width:80px; display:inline-block;">
                            <div style="background:var(--primary); height:100%; width:${pct}%;"></div>
                        </div>
                    </td>
                    <td style="padding:10px; text-align:center; font-size:12px;">
                        <span style="color:var(--success); font-weight:bold;">${e.conforme_count || 0}</span> / 
                        <span style="color:var(--danger); font-weight:bold;">${e.non_conforme_count || 0}</span>
                        ${(e.da_verificare_count || 0) > 0 ? ` / <span style="color:var(--cta); font-weight:bold;">${e.da_verificare_count} da verif.</span>` : ''}
                    </td>
                    <td style="padding:10px; text-align:right;">
                        <button class="btn btn-secondary btn-small" style="width:auto; margin:0 3px;" data-action="open-workspace" data-id="${e.id}"><i class="fa-solid fa-pen-to-square"></i> Apri</button>
                        <button class="btn btn-secondary btn-small" style="width:auto; margin:0;" data-action="view-report" data-id="${e.id}"><i class="fa-solid fa-file-lines"></i> Relazione</button>
                    </td>
                </tr>
            `;
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function openNewAuditModal() {
        const modal = document.getElementById("newAuditModal");
        if (modal) {
            const nameEl = document.getElementById("auditCustomerName");
            const intEl = document.getElementById("auditInterviewee");
            if (nameEl) nameEl.value = "";
            if (intEl) intEl.value = "";
            modal.style.display = "flex";
        }
    }

    function closeNewAuditModal() {
        const modal = document.getElementById("newAuditModal");
        if (modal) modal.style.display = "none";
    }

    async function submitNewAuditForm(e) {
        if (e) e.preventDefault();
        const nameEl = document.getElementById("auditCustomerName");
        const modEl = document.getElementById("auditModality");
        const intEl = document.getElementById("auditInterviewee");

        const customerName = nameEl ? nameEl.value.trim() : "";
        const modality = modEl ? modEl.value : "onsite";
        const interviewee = intEl ? intEl.value.trim() : "";

        if (!customerName) return;

        try {
            const res = await apiFetch("/api/audit-checklist/engagements", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    customer_name: customerName,
                    onsite_or_remote: modality,
                    interviewee: interviewee || null
                })
            });
            if (!res || !res.ok) {
                alert("Errore durante la creazione dell'audit.");
                return;
            }
            const newEng = await res.json();
            closeNewAuditModal();
            await loadAuditChecklistTab();
            openAuditWorkspace(newEng.id);
        } catch (err) {
            console.error("Errore creazione audit:", err);
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
                <details style="border:1px solid var(--border); border-radius:0; margin-bottom:12px; background:var(--surface);" ${idx === 0 ? 'open' : ''}>
                    <summary style="padding:12px 16px; cursor:pointer; font-weight:600; font-size:15px; display:flex; justify-content:space-between; align-items:center; background:var(--surface-2);">
                        <span>${escapeHtml(secTitle)}</span>
                        <span style="font-size:12px; color:var(--text-muted); font-weight:normal;">${evalCount}/${secItems.length} valutati</span>
                    </summary>
                    <div style="padding:16px;">
            `;

            secItems.forEach(item => {
                const prereqBadge = item.is_prerequisite ? '<span style="background:color-mix(in srgb, var(--danger) 25%, transparent); color:var(--danger); border:1px solid var(--danger); font-size:10px; padding:2px 8px; border-radius:0; font-weight:bold; margin-left:6px;">PREREQUISITO</span>' : '';
                const evBadge = item.requires_evidence ? '<span style="background:color-mix(in srgb, var(--primary) 25%, transparent); color:var(--primary); border:1px solid var(--primary); font-size:10px; padding:2px 8px; border-radius:0; font-weight:bold; margin-left:6px;">EVIDENZA RICHIESTA</span>' : '';

                html += `
                    <div style="border:1px solid var(--border); border-radius:0; padding:14px; margin-bottom:14px; background:var(--surface-3);">
                        <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:10px; margin-bottom:8px;">
                            <div>
                                <strong style="font-size:14px; color:var(--text);">Item ${escapeHtml(item.item_ref)} — ${escapeHtml(item.title)}</strong>
                                ${prereqBadge} ${evBadge}
                            </div>
                            <div>
                                <select id="status_${item.item_ref}" style="padding:5px 10px; border-radius:0; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:12px; font-weight:bold;">
                                    <option value="non_valutato" ${item.status === 'non_valutato' ? 'selected' : ''}>NON VALUTATO</option>
                                    <option value="conforme" ${item.status === 'conforme' ? 'selected' : ''} style="color:var(--success);">CONFORME</option>
                                    <option value="parziale" ${item.status === 'parziale' ? 'selected' : ''} style="color:var(--warning);">PARZIALE</option>
                                    <option value="non_conforme" ${item.status === 'non_conforme' ? 'selected' : ''} style="color:var(--danger);">NON CONFORME</option>
                                    <option value="da_verificare" ${item.status === 'da_verificare' ? 'selected' : ''} style="color:var(--primary);">DA VERIFICARE</option>
                                    <option value="non_applicabile" ${item.status === 'non_applicabile' ? 'selected' : ''}>NON APPLICABILE</option>
                                </select>
                                <select id="sev_${item.item_ref}" style="padding:5px 10px; border-radius:0; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:12px;">
                                    <option value="critica" ${item.severity === 'critica' ? 'selected' : ''}>Critica</option>
                                    <option value="alta" ${item.severity === 'alta' ? 'selected' : ''}>Alta</option>
                                    <option value="media" ${item.severity === 'media' ? 'selected' : ''}>Media</option>
                                    <option value="bassa" ${item.severity === 'bassa' ? 'selected' : ''}>Bassa</option>
                                    <option value="osservazione" ${item.severity === 'osservazione' ? 'selected' : ''}>Osservazione</option>
                                </select>
                            </div>
                        </div>
                        <div style="font-size:13px; color:var(--text); line-height:1.5; margin-bottom:12px; background:var(--surface-2); padding:10px 14px; border-radius:0; border:1px solid var(--border);">
                            <strong style="color:var(--primary);">Perché è importante:</strong> ${escapeHtml(item.guidance_why || '')}<br>
                            <strong style="color:var(--primary);">Cosa cercare:</strong> ${escapeHtml(item.guidance_good || '')}
                        </div>
                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px;">
                            <div>
                                <label style="display:block; font-size:11px; font-weight:bold; margin-bottom:4px; color:var(--text-muted);">Rilievo / Esito dell'audit:</label>
                                <textarea id="finding_${item.item_ref}" rows="3" style="width:100%; font-size:13px; padding:8px 10px; border-radius:0; border:1px solid var(--border); background:var(--surface); color:var(--text); font-family:var(--font-main);" placeholder="Descrivi il riscontro ottenuto...">${escapeHtml(item.finding_text || '')}</textarea>
                            </div>
                            <div>
                                <label style="display:block; font-size:11px; font-weight:bold; margin-bottom:4px; color:var(--text-muted);">Raccomandazione per la relazione:</label>
                                <textarea id="recom_${item.item_ref}" rows="3" style="width:100%; font-size:13px; padding:8px 10px; border-radius:0; border:1px solid var(--border); background:var(--surface); color:var(--text); font-family:var(--font-main);" placeholder="Azione correttiva consigliata...">${escapeHtml(item.recommendation_text || '')}</textarea>
                            </div>
                        </div>
                        <div style="display:flex; justify-content:flex-end;">
                            <button class="btn btn-primary btn-small" style="width:auto;" data-action="save-item" data-ref="${item.item_ref}"><i class="fa-solid fa-floppy-disk"></i> Salva Rigo</button>
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

    async function viewAuditReportForId(engId) {
        try {
            const res = await apiFetch(`/api/audit-checklist/engagements/${engId}/report`);
            if (!res || !res.ok) {
                alert("Errore durante il caricamento della relazione di audit.");
                return;
            }
            const html = await res.text();
            if (window.openAuditReportModal) {
                window.openAuditReportModal(html, `Relazione_Audit_${engId}`, "SentinelNet — Anteprima Relazione Audit");
            } else {
                const printWin = window.open("", "_blank");
                if (printWin) {
                    printWin.document.write(html);
                    printWin.document.close();
                }
            }
        } catch (e) {
            console.error("Errore apertura relazione:", e);
            window.open(`/api/audit-checklist/engagements/${engId}/report`, "_blank");
        }
    }

    function closeAuditWorkspace() {
        const workspace = document.getElementById("auditWorkspace");
        if (workspace) workspace.style.display = "none";
        currentAuditEngagementId = null;
    }

    // ===== Gestione domande del template (amministratori) =====

    async function loadAuditTemplate() {
        try {
            const res = await apiFetch("/api/audit-checklist/templates");
            if (!res || !res.ok) return;
            const list = await res.json();
            if (!list.length) return;
            // list_templates ordina per versione decrescente: il primo e' l'attivo.
            const full = await apiFetch(`/api/audit-checklist/templates/${list[0].id}`);
            if (!full || !full.ok) return;
            currentTemplate = await full.json();

            const name = document.getElementById("auditTplName");
            if (name) name.textContent = `— v${currentTemplate.version} (${currentTemplate.items.length} domande)`;
            const dl = document.getElementById("tplSectionTitles");
            if (dl) {
                const titles = [...new Set(currentTemplate.items.map(i => i.section_title))];
                dl.innerHTML = titles.map(t => `<option value="${escapeHtml(t)}">`).join("");
            }
            if (document.getElementById("auditTemplateEditor").style.display !== "none") {
                renderTemplateEditor();
            }
        } catch (e) {
            console.error("Errore caricamento template audit:", e);
        }
    }

    function toggleTemplateEditor() {
        const box = document.getElementById("auditTemplateEditor");
        const label = document.getElementById("auditTplToggleLabel");
        const show = box.style.display === "none";
        box.style.display = show ? "block" : "none";
        if (label) label.textContent = show ? "Nascondi" : "Mostra";
        if (show) renderTemplateEditor();
    }

    function renderTemplateEditor() {
        const box = document.getElementById("auditTemplateEditor");
        if (!box || !currentTemplate) return;

        const sections = {};
        currentTemplate.items.forEach(i => {
            const key = `Sezione ${i.section_no} — ${i.section_title}`;
            (sections[key] = sections[key] || []).push(i);
        });

        box.innerHTML = Object.keys(sections).map(sec => `
            <details style="border:1px solid var(--border); border-radius:0; margin-bottom:10px; background:var(--surface);">
                <summary style="padding:10px 14px; cursor:pointer; font-weight:600; font-size:14px; background:var(--surface-2);">
                    ${escapeHtml(sec)} <span style="font-size:12px; font-weight:normal; color:var(--text-muted);">(${sections[sec].length})</span>
                </summary>
                <table style="width:100%; border-collapse:collapse; font-size:12px;">
                    ${sections[sec].map(i => `
                        <tr style="border-top:1px solid var(--border);">
                            <td style="padding:8px 14px; width:60px; font-weight:600;">${escapeHtml(i.ref)}</td>
                            <td style="padding:8px 0;">
                                ${escapeHtml(i.title)}
                                ${i.is_prerequisite ? '<span style="color:var(--danger); font-size:10px; font-weight:bold; margin-left:6px;">PREREQUISITO</span>' : ''}
                                ${i.requires_evidence ? '<span style="color:var(--primary); font-size:10px; font-weight:bold; margin-left:6px;">EVIDENZA</span>' : ''}
                                <div style="color:var(--text-muted); font-size:11px; margin-top:2px;">${escapeHtml(i.guidance_why || '')}</div>
                            </td>
                            <td style="padding:8px 14px; text-align:right; white-space:nowrap;">
                                <button class="btn btn-secondary btn-small" style="width:auto; margin:0 3px;" data-action="edit-tpl-item" data-ref="${escapeHtml(i.ref)}"><i class="fa-solid fa-pen"></i></button>
                                <button class="btn btn-secondary btn-small" style="width:auto; margin:0;" data-action="delete-tpl-item" data-ref="${escapeHtml(i.ref)}"><i class="fa-solid fa-trash"></i></button>
                            </td>
                        </tr>
                    `).join("")}
                </table>
            </details>
        `).join("");
    }

    function openTemplateItemModal(ref) {
        if (!currentTemplate) return;
        editingItemRef = ref || null;
        const item = ref ? currentTemplate.items.find(i => i.ref === ref) : null;

        document.getElementById("tplItemModalTitle").innerHTML = item
            ? `<i class="fa-solid fa-pen" style="color:var(--primary);"></i> Modifica Domanda ${escapeHtml(ref)}`
            : '<i class="fa-solid fa-list-check" style="color:var(--primary);"></i> Nuova Domanda';

        const refEl = document.getElementById("tplItemRef");
        refEl.value = item ? item.ref : "";
        // Il ref lega le valutazioni gia' raccolte all'item: modificabile solo in creazione.
        refEl.disabled = !!item;

        document.getElementById("tplItemSectionNo").value = item ? item.section_no : "";
        document.getElementById("tplItemSortOrder").value = item ? item.sort_order : "";
        document.getElementById("tplItemSectionTitle").value = item ? item.section_title : "";
        document.getElementById("tplItemTitle").value = item ? item.title : "";
        document.getElementById("tplItemWhy").value = item ? (item.guidance_why || "") : "";
        document.getElementById("tplItemGood").value = item ? (item.guidance_good || "") : "";
        document.getElementById("tplItemHow").value = item ? (item.guidance_how || "") : "";
        document.getElementById("tplItemSeverity").value = item ? item.severity_default : "media";
        document.getElementById("tplItemCheckKind").value = item ? (item.check_kind || "manual") : "manual";
        document.getElementById("tplItemPrereq").checked = item ? !!item.is_prerequisite : false;
        document.getElementById("tplItemEvidence").checked = item ? !!item.requires_evidence : false;

        document.getElementById("templateItemModal").style.display = "flex";
    }

    function closeTemplateItemModal() {
        document.getElementById("templateItemModal").style.display = "none";
        editingItemRef = null;
    }

    async function submitTemplateItemForm(e) {
        if (e) e.preventDefault();
        if (!currentTemplate) return;

        const payload = {
            section_no: parseInt(document.getElementById("tplItemSectionNo").value, 10),
            section_title: document.getElementById("tplItemSectionTitle").value.trim(),
            title: document.getElementById("tplItemTitle").value.trim(),
            guidance_why: document.getElementById("tplItemWhy").value.trim(),
            guidance_good: document.getElementById("tplItemGood").value.trim(),
            guidance_how: document.getElementById("tplItemHow").value.trim(),
            severity_default: document.getElementById("tplItemSeverity").value,
            check_kind: document.getElementById("tplItemCheckKind").value,
            is_prerequisite: document.getElementById("tplItemPrereq").checked,
            requires_evidence: document.getElementById("tplItemEvidence").checked,
            sort_order: parseInt(document.getElementById("tplItemSortOrder").value, 10) || 0
        };

        const base = `/api/audit-checklist/templates/${currentTemplate.id}/items`;
        const url = editingItemRef ? `${base}/${encodeURIComponent(editingItemRef)}` : base;
        if (!editingItemRef) payload.ref = document.getElementById("tplItemRef").value.trim();

        try {
            const res = await apiFetch(url, {
                method: editingItemRef ? "PUT" : "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            if (!res || !res.ok) {
                const err = res ? await res.json().catch(() => ({})) : {};
                alert(err.detail || "Errore durante il salvataggio della domanda.");
                return;
            }
            closeTemplateItemModal();
            await loadAuditTemplate();
            renderTemplateEditor();
            // L'audit aperto puo' aver guadagnato o cambiato una domanda.
            if (currentAuditEngagementId) await openAuditWorkspace(currentAuditEngagementId);
        } catch (err) {
            console.error("Errore salvataggio domanda template:", err);
            alert("Errore di rete durante il salvataggio della domanda.");
        }
    }

    async function deleteTemplateItem(ref) {
        if (!currentTemplate) return;
        if (!confirm(`Eliminare la domanda ${ref} dalla checklist?`)) return;
        try {
            const res = await apiFetch(
                `/api/audit-checklist/templates/${currentTemplate.id}/items/${encodeURIComponent(ref)}`,
                { method: "DELETE" }
            );
            if (!res || !res.ok) {
                const err = res ? await res.json().catch(() => ({})) : {};
                alert(err.detail || "Errore durante l'eliminazione della domanda.");
                return;
            }
            await loadAuditTemplate();
            renderTemplateEditor();
            if (currentAuditEngagementId) await openAuditWorkspace(currentAuditEngagementId);
        } catch (e) {
            console.error("Errore eliminazione domanda template:", e);
            alert("Errore di rete durante l'eliminazione della domanda.");
        }
    }

    // Delegated and static event listeners
    document.getElementById('btnOpenNewAuditModal')?.addEventListener('click', openNewAuditModal);
    document.getElementById('btnOpenTemplateItemModal')?.addEventListener('click', () => openTemplateItemModal());
    document.getElementById('btnToggleTemplateEditor')?.addEventListener('click', toggleTemplateEditor);

    document.getElementById('auditEngagementList')?.addEventListener('click', (e) => {
        const btnNew = e.target.closest('[data-action="open-new-audit"]');
        if (btnNew) { openNewAuditModal(); return; }
        const btnOpen = e.target.closest('[data-action="open-workspace"]');
        if (btnOpen && btnOpen.dataset.id) { openAuditWorkspace(Number(btnOpen.dataset.id)); return; }
        const btnRep = e.target.closest('[data-action="view-report"]');
        if (btnRep && btnRep.dataset.id) { viewAuditReportForId(Number(btnRep.dataset.id)); return; }
    });

    document.getElementById('auditSectionAccordion')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action="save-item"]');
        if (btn && btn.dataset.ref) {
            saveAuditItem(btn.dataset.ref);
        }
    });

    document.getElementById('auditTemplateEditor')?.addEventListener('click', (e) => {
        const btnEdit = e.target.closest('[data-action="edit-tpl-item"]');
        if (btnEdit && btnEdit.dataset.ref) { openTemplateItemModal(btnEdit.dataset.ref); return; }
        const btnDel = e.target.closest('[data-action="delete-tpl-item"]');
        if (btnDel && btnDel.dataset.ref) { deleteTemplateItem(btnDel.dataset.ref); return; }
    });

    // Esporta funzioni globali
    window.loadAuditChecklistTab = loadAuditChecklistTab;
    window.openNewAuditModal = openNewAuditModal;
    window.closeNewAuditModal = closeNewAuditModal;
    window.submitNewAuditForm = submitNewAuditForm;
    window.openAuditWorkspace = openAuditWorkspace;
    window.saveAuditItem = saveAuditItem;
    window.viewAuditReport = viewAuditReport;
    window.viewAuditReportForId = viewAuditReportForId;
    window.closeAuditWorkspace = closeAuditWorkspace;
    window.toggleTemplateEditor = toggleTemplateEditor;
    window.openTemplateItemModal = openTemplateItemModal;
    window.closeTemplateItemModal = closeTemplateItemModal;
    window.submitTemplateItemForm = submitTemplateItemForm;
    window.deleteTemplateItem = deleteTemplateItem;
})();
