// static/js/topology.js
// Estratto da templates/dashboard.html: tab-map (Topologia, report Port-Channel),
// tab-map-interactive (mappa vis.js classica + mappa minimalista stile Visio,
// legenda, filtri dispositivi/link, overlay Visio con contenitori Sede e fasci
// Port-Channel/vPC/peer) e tab-categories (Pannello Dispositivi & Categorie,
// classificazione manuale, risoluzione conflitti CDP/LLDP). networkInstance e
// categoriesData vivono qui perche' usati solo da questo modulo.
//
// showPortConfig/closePortConfigModal/openPortInAnalyzer/expandIface e i globali
// caFocusIp/caFocusPort sono stati promossi a static/js/core.js: sono invocati
// anche dal tab MAC-tracker/ARP (ancora inline in dashboard.html) e da
// static/js/config-analyzer.js, quindi non sono esclusivi di questo modulo.

    // La lista adjacency testuale è stata rimossa (non human-readable): il tab
    // mostra solo il report Port-Channel; la topologia vive nella mappa 2D.
    async function loadTopology() {
        const groupSelect = document.getElementById('topologyGroupSelect');
        const selectedGroup = groupSelect ? groupSelect.value : 'all';
        loadPortchannelReport(selectedGroup);
    }

    // Riquadro Port-Channel per switch: aggregati + interfacce membro e interfacce
    // fisiche singole non aggregate (stile elenco).
    async function loadPortchannelReport(selectedGroup) {
        const box = document.getElementById("portchannelReport");
        if (!box) return;
        try {
            const res = await apiFetch('/api/portchannels?group=' + encodeURIComponent(selectedGroup || 'all'));
            if (!res || !res.ok) { box.innerHTML = ''; return; }
            const data = await res.json();
            const devices = (data.devices || []).filter(d => (d.portchannels || []).length);
            if (!devices.length) {
                box.innerHTML = `<p style="color:var(--text-muted); font-size:13px;">${currentLang==='en'?'No Port-Channel data (run a triage first).':'Nessun dato Port-Channel (esegui prima un triage).'}</p>`;
                return;
            }
            const toText = currentLang==='en' ? 'to' : 'verso';
            box.innerHTML = devices.map(d => {
                const pcs = (d.portchannels || []).slice().sort((a,b)=>{
                    const na=parseInt(String(a.name).replace(/\D/g,''))||0, nb=parseInt(String(b.name).replace(/\D/g,''))||0; return na-nb;
                });
                const pcHtml = pcs.length ? pcs.map(po => {
                    const neigh = (po.neighbors && po.neighbors.length)
                        ? `<span style="font-size:11px; color:var(--primary);"> <i class="fa-solid fa-arrow-right-long"></i> ${toText} <strong>${po.neighbors.map(escapeHtml).join(', ')}</strong></span>`
                        : `<span style="font-size:11px; color:var(--text-muted);"> <i class="fa-solid fa-arrow-right-long"></i> ${currentLang==='en'?'unknown neighbor':'vicino sconosciuto'}</span>`;
                    // Stato operativo: verde se tutto su, rosso/giallo se c'è un problema.
                    let stateBadge = '';
                    if (po.status === 'up' && !po.issue) {
                        stateBadge = `<span title="${currentLang==='en'?'All members bundled':'Tutti i membri aggregati'}" style="font-size:10px; color:var(--success); border:1px solid var(--success); border-radius:5px; padding:1px 6px; margin-left:6px;"><i class="fa-solid fa-circle-check"></i> ${po.up}/${po.total} UP</span>`;
                    } else if (po.issue) {
                        const down = po.status === 'down';
                        stateBadge = `<span title="${escapeHtml(po.issue_msg||'')}" style="font-size:10px; color:${down?'#ff6b7c':'#ffb84d'}; border:1px solid ${down?'#ff6b7c':'#ffb84d'}; border-radius:5px; padding:1px 6px; margin-left:6px;"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(po.issue_msg || (currentLang==='en'?'issue':'problema'))}</span>`;
                    }
                    return `<div style="margin-bottom:6px;">
                        <span style="display:inline-block; font-weight:700; color:var(--warning); font-size:12px; min-width:120px;"><i class="fa-solid fa-link"></i> ${escapeHtml(po.name)}</span>
                        <span style="font-family:var(--font-code); font-size:12px; color:var(--success);">${(po.members||[]).map(escapeHtml).join(', ')}</span>
                        <span style="font-size:11px; color:var(--text-muted);"> (${(po.members||[]).length} ${currentLang==='en'?'members':'membri'})</span>
                        ${stateBadge}
                        ${neigh}
                    </div>`;
                }).join('')
                    : `<div style="font-size:12px; color:var(--text-muted);">${currentLang==='en'?'No Port-Channels.':'Nessun Port-Channel.'}</div>`;
                return `<div style="background:var(--surface-2); border:1px solid var(--border); border-radius:10px; padding:14px; margin-bottom:12px;">
                    <h4 style="font-size:14px; margin-bottom:10px;"><i class="fa-solid fa-network-wired" style="color:var(--primary);"></i> ${escapeHtml(d.hostname)} <span style="color:var(--text-muted); font-weight:400; font-size:12px;">${escapeHtml(d.ip)} · ${escapeHtml(d.group)}</span></h4>
                    ${pcHtml}
                </div>`;
            }).join('');
        } catch (e) {
            box.innerHTML = '';
        }
    }

    // Apre/chiude la legenda della mappa su richiesta dell'utente.
    function toggleLegend() {
        const body = document.getElementById("legendBody");
        const btn = document.getElementById("legendToggleBtn");
        if (!body) return;
        const hidden = body.style.display === 'none';
        body.style.display = hidden ? 'flex' : 'none';
        if (btn) btn.innerHTML = `<i class="fa-solid fa-chevron-${hidden ? 'down' : 'up'}"></i>`;
    }

    // --- VIS.JS TOPOLOGY GRAPH VIEW ---

    let networkInstance = null;

    // Generatore dinamico di schede SVG ad alta tecnologia per i nodi del network
    // Metadati per tipo di apparato: colore distintivo (feature: colori per tipo
    // di device) ed etichette bilingue. "switch" è il default.
    const DEVICE_TYPE_META = {
        firewall: { color: "#ff6b7c", it: "Firewall",      en: "Firewall" },
        wlc:      { color: "#b76bff", it: "WLC",           en: "WLC" },
        ap:       { color: "#38bdf8", it: "Access Point",  en: "Access Point" },
        router:   { color: "#5ecf8d", it: "Router",        en: "Router" },
        switch:   { color: "#4f8ef7", it: "Switch",        en: "Switch" },
        server:   { color: "#f7b84f", it: "Server",        en: "Server" },
        phone:    { color: "#38d9c0", it: "Telefono IP",   en: "IP Phone" },
        pc:       { color: "#a3a3a3", it: "PC",            en: "PC" },
        other:    { color: "#8d9bb0", it: "Altro",         en: "Other" },
    };
    function deviceTypeMeta(t) { return DEVICE_TYPE_META[t] || DEVICE_TYPE_META.other; }
    function deviceTypeLabel(t) { const m = deviceTypeMeta(t); return currentLang === 'en' ? m.en : m.it; }

    // Colore stabile per dominio VTP (feature: range dominio VTP).
    const VTP_PALETTE = ["#b76bff","#4f8ef7","#3be188","#ffb84d","#ff6b7c","#38d9c0","#f7b84f","#8d6bff","#e879f9","#22d3ee"];
    function vtpDomainColor(domain) {
        if (!domain) return "#5a6473";
        let h = 0;
        for (let i = 0; i < domain.length; i++) h = (h * 31 + domain.charCodeAt(i)) >>> 0;
        return VTP_PALETTE[h % VTP_PALETTE.length];
    }

    // Categorie di apparato da mostrare sulla mappa (persistite). Default: solo
    // infrastruttura (switch/router/firewall/wlc); il resto si abilita a scelta.
    const MAP_DEFAULT_CATS = ['switch', 'router', 'firewall', 'wlc'];
    let mapCatVis;
    try { mapCatVis = JSON.parse(localStorage.getItem('mapCatVis')); } catch (e) { mapCatVis = null; }
    if (!mapCatVis || typeof mapCatVis !== 'object') {
        mapCatVis = {};
        Object.keys(DEVICE_TYPE_META).forEach(k => { mapCatVis[k] = MAP_DEFAULT_CATS.includes(k); });
    }
    function isMapCatVisible(c) {
        // Categorie note (DEVICE_TYPE_META) sono sempre seminate in mapCatVis.
        // Le categorie dinamiche (custom o "client") non ancora viste vengono
        // trattate come "other": nascoste finché l'utente non le abilita, ma
        // comunque presenti/gestibili nel menu una volta apparse in mappa.
        if (Object.prototype.hasOwnProperty.call(mapCatVis, c)) return mapCatVis[c] !== false;
        return false;
    }
    function toggleMapCat(cat, on) {
        mapCatVis[cat] = on;
        localStorage.setItem('mapCatVis', JSON.stringify(mapCatVis));
        loadInteractiveMap();
    }
    // Metadati (colore + etichetta) per una categoria di mappa, incluse quelle
    // dinamiche non presenti in DEVICE_TYPE_META (es. "client" o categorie
    // custom create dall'utente).
    function mapCatMeta(k) {
        if (DEVICE_TYPE_META[k]) return DEVICE_TYPE_META[k];
        if (k === 'client') return { color: DEVICE_TYPE_META.other.color, it: i18n.it.devTypeClient, en: i18n.en.devTypeClient };
        return { color: DEVICE_TYPE_META.other.color, it: k, en: k };
    }
    function mapCatLabel(k) { const m = mapCatMeta(k); return currentLang === 'en' ? m.en : m.it; }
    function renderMapCatMenu(nodesData) {
        const box = document.getElementById('mapCatList');
        if (!box) return;
        // Menu = categorie built-in + qualsiasi device_type dinamico presente
        // nei nodi correnti (custom category, "client", ecc.), così anche
        // queste diventano filtrabili invece di restare sempre visibili.
        const cats = Object.keys(DEVICE_TYPE_META);
        (nodesData || []).forEach(n => {
            if (n.device_type && !cats.includes(n.device_type)) cats.push(n.device_type);
        });
        box.innerHTML = cats.map(k => `
            <label style="display:flex; align-items:center; gap:8px; font-size:12px; padding:3px 0; cursor:pointer; color:var(--text);">
                <input type="checkbox" ${isMapCatVisible(k)?'checked':''} onchange="toggleMapCat('${k}', this.checked)" style="accent-color:var(--primary);">
                <span style="display:inline-block; width:10px; height:10px; border-radius:2px; background:${mapCatMeta(k).color};"></span>
                ${mapCatLabel(k)}
            </label>`).join('');
    }

    // Costruisce la legenda dei colori per tipo di apparato sotto la mappa.
    function renderDeviceTypeLegend() {
        const box = document.getElementById("deviceTypeLegend");
        if (!box) return;
        box.innerHTML = Object.keys(DEVICE_TYPE_META).map(t => {
            const m = DEVICE_TYPE_META[t];
            return `<div class="legend-item"><span style="width:12px;height:12px;border-radius:3px;background:${m.color};display:inline-block;"></span><span>${deviceTypeLabel(t)}</span></div>`;
        }).join("");
    }

    function createNodeSvg(label, ip, deviceType, status, isBoundary, vendor, vtp) {
        let statusColor = "#8d9bb0";
        let statusBg = "rgba(141, 155, 176, 0.1)";
        let statusGlow = "rgba(141, 155, 176, 0.2)";
        let statusText = "OFFLINE";
        
        if (status === "online") {
            statusColor = "#57d987"; // verde semantico
            statusBg = "rgba(59, 225, 136, 0.15)";
            statusGlow = "rgba(59, 225, 136, 0.4)";
            statusText = "ONLINE";
        } else if (status === "offline") {
            statusColor = "#ff6b7c"; // rosso neon
            statusBg = "rgba(255, 107, 124, 0.15)";
            statusGlow = "rgba(255, 107, 124, 0.4)";
            statusText = "OFFLINE";
        } else if (status === "auth_failed") {
            statusColor = "#ffb84d"; // arancio neon
            statusBg = "rgba(255, 184, 77, 0.15)";
            statusGlow = "rgba(255, 184, 77, 0.4)";
            statusText = "AUTH ERR";
        } else if (status === "discovered") {
            statusColor = "#a3a3a3"; // grigio vicini scoperti
            statusBg = "rgba(163, 163, 163, 0.15)";
            statusGlow = "rgba(163, 163, 163, 0.2)";
            statusText = currentLang === 'en' ? "DISCOVERED" : "RILEVATO";
        }

        if (isBoundary) {
            statusColor = "#4a5568";
            statusBg = "rgba(74, 85, 104, 0.15)";
            statusGlow = "transparent";
            statusText = currentLang === 'en' ? "EXTERNAL" : "ESTERNO";
        }

        // Colore per TIPO di apparato (feature: colori per tipo di device).
        // L'icona usa il colore del tipo; lo stato resta nella barra/badge laterale.
        const typeColor = deviceTypeMeta(deviceType).color;

        // Colore tema per il bordo sfumato della scheda basato sullo stato del nodo
        let borderGradStart = statusColor;
        let borderGradEnd = "#362d59";

        // Badge in alto a destra: SEMPRE il tipo di apparato. Il dominio VTP, se
        // attivo, va su una riga separata sotto (non deve coprire il tipo).
        vtp = vtp || {};
        const badgeText = deviceTypeLabel(deviceType);
        const badgeColor = typeColor;
        // VTP pill: quando presente il riquadro cresce in altezza (vedi hasVtp più
        // sotto) e la pillola prende una fascia orizzontale propria SOTTO le righe
        // IP/badge, così non si sovrappone più al badge tipo né all'hostname.
        let vtpDomainSvg = '';
        const hasVtp = !!(vtp.showDomain && vtp.domain);
        if (hasVtp) {
            const dcol = vtpDomainColor(vtp.domain);
            borderGradStart = dcol;
            const dEsc = String(vtp.domain).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").slice(0, 24);
            // Se disponibile, aggiunge la modalità VTP (server/client/transparent/off)
            // accanto al dominio; troncata per stare nella pillola larga 216px.
            const modeEsc = vtp.mode ? String(vtp.mode).toLowerCase().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") : '';
            const pillTxt = (modeEsc ? `${dEsc} · ${modeEsc}` : dEsc).slice(0, 30);
            vtpDomainSvg = `<rect x="16" y="80" width="216" height="16" rx="4" fill="${dcol}22" stroke="${dcol}" stroke-opacity="0.45" stroke-width="1" />
          <text x="124" y="91.5" font-family="'Rubik','Inter',sans-serif" font-size="8.5" font-weight="800" fill="${dcol}" text-anchor="middle" letter-spacing="0.2">VTP: ${pillTxt}</text>`;
        }
        const cardH = hasVtp ? 106 : 84;

        // Carica icone vettoriali moderne basate sulla tipologia di apparato
        let iconSvg = "";
        if (deviceType === "router") {
            // Icona router
            iconSvg = `<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" fill="${typeColor}"/>`;
        } else if (deviceType === "ap") {
            // Icona Access Point (Wi-Fi)
            iconSvg = `<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15.92c-.32.05-.65.08-1 .08s-.68-.03-1-.08v-2.12c.32.08.65.12 1 .12s.68-.04 1-.12v2.12zm0-4.22c-.32.12-.65.18-1 .18s-.68-.06-1-.18v-3.8c.32.18.65.28 1 .28s.68-.1 1-.28v3.8zm0-5.8c-.32.22-.65.34-1 .34s-.68-.12-1-.34V4.18c.32.28.65.44 1 .44s.68-.16 1-.44v3.28z" fill="${typeColor}"/>`;
        } else if (deviceType === "wlc") {
            // Icona WLC (controller wireless: tower + base)
            iconSvg = `<path d="M12 8a2 2 0 0 0-2 2c0 .74.4 1.38 1 1.72V21h2v-9.28c.6-.34 1-.98 1-1.72a2 2 0 0 0-2-2zM7.05 6.05 5.64 4.64a9 9 0 0 0 0 10.72l1.41-1.41a7 7 0 0 1 0-7.9zm9.9 0a7 7 0 0 1 0 7.9l1.41 1.41a9 9 0 0 0 0-10.72l-1.41 1.41zM4.46 3.46 3.05 2.05a13 13 0 0 0 0 16.9l1.41-1.41a11 11 0 0 1 0-14.08zm16.49-1.41-1.41 1.41a11 11 0 0 1 0 14.08l1.41 1.41a13 13 0 0 0 0-16.9z" fill="${typeColor}"/>`;
        } else if (deviceType === "firewall") {
            // Icona Firewall (muro di mattoni + scudo)
            iconSvg = `<path d="M3 3h18v4H3V3zm0 6h6v4H3V9zm8 0h10v4H11V9zM3 15h10v4H3v-4zm12 0h6v4h-6v-4z" fill="${typeColor}"/>`;
        } else if (deviceType === "server") {
            // Icona Server 2U Rack
            iconSvg = `<path d="M19 13H5c-1.1 0-2 .9-2 2v3c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2v-3c0-1.1-.9-2-2-2zm-8 4H5v-2h6v2zm8 0h-2v-2h2v2zm0-10H5c-1.1 0-2 .9-2 2v3c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V9c0-1.1-.9-2-2-2zm-8 4H5V9h6v2zm8 0h-2V9h2v2z" fill="${typeColor}"/>`;
        } else if (deviceType === "phone") {
            // Icona Telefono IP
            iconSvg = `<path d="M20 15.5c-1.2 0-2.4-.2-3.6-.6-.3-.1-.7 0-1 .2l-2.2 2.2c-2.8-1.4-5.1-3.8-6.6-6.6l2.2-2.2c.3-.3.4-.7.2-1-.4-1.2-.6-2.4-.6-3.6 0-.6-.4-1-1-1H3.5c-.6 0-1 .4-1 1C2.5 17 7 21.5 16.5 21.5c.6 0 1-.4 1-1V16.5c0-.6-.4-1-1-1z" fill="${typeColor}"/>`;
        } else if (deviceType === "pc") {
            // Icona Workstation PC
            iconSvg = `<path d="M21 2H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h7l-2 3v1h8v-1l-2-3h7c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 12H3V4h18v10z" fill="${typeColor}"/>`;
        } else {
            // Icona Switch rack standard
            iconSvg = `<path d="M20 18c1.1 0 1.99-.9 1.99-2L22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6zm3 2h2v2H7V8zm0 4h2v2H7v-2zm4-4h2v2h-2V8zm0 4h2v2h-2v-2zm4-4h2v2h-2V8zm0 4h2v2h-2v-2z" fill="${typeColor}"/>`;
        }

        const escapedLabel = label.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const escapedIp = ip.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const escapedVendor = (vendor && vendor !== 'discovered' ? vendor : (currentLang === 'en' ? 'Neighbor' : 'Vicino')).toUpperCase();
        const escapedBadge = String(badgeText).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").slice(0, 22);

        // Stringa ID per gradienti isolati per ciascun apparato per prevenire conflitti DOM
        const gradId = escapedIp.replace(/[^a-zA-Z0-9]/g, '_');

        const svg = `
        <svg xmlns="http://www.w3.org/2000/svg" width="240" height="${cardH}" viewBox="0 0 240 ${cardH}">
          <defs>
            <linearGradient id="cardGrad_${gradId}" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#251c3e" />
              <stop offset="100%" stop-color="#150f23" />
            </linearGradient>
            <linearGradient id="borderGrad_${gradId}" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="${borderGradStart}" />
              <stop offset="100%" stop-color="${borderGradEnd}" />
            </linearGradient>
          </defs>

          <!-- Sfondo della scheda con gradiente scuro e bordo lucido nello stato corrente -->
          <rect x="2" y="2" width="236" height="${cardH - 4}" rx="12" fill="url(#cardGrad_${gradId})" stroke="url(#borderGrad_${gradId})" stroke-width="1.5" />

          <!-- Barra d'accento laterale colorata in base allo stato (altezza segue cardH) -->
          <path d="M2 14C2 7.37 7.37 2 14 2H18V${cardH - 2}H14C7.37 ${cardH - 2} 2 ${cardH - 7.37} 2 ${cardH - 14}V14Z" fill="${statusColor}" opacity="0.85" />
          
          <!-- Cerchio contenitore per l'icona dell'apparato (bordo nel colore del tipo) -->
          <circle cx="44" cy="42" r="22" fill="#1f1633" stroke="${typeColor}" stroke-dasharray="1.5" stroke-width="1.5" />

          <!-- Posizionamento SVG dell'icona -->
          <g transform="translate(32, 30)">
            <svg width="24" height="24" viewBox="0 0 24 24">
                ${iconSvg}
            </svg>
          </g>

          <!-- Badge tipo apparato (in alto a destra) -->
          <rect x="138" y="9" width="94" height="15" rx="4" fill="${badgeColor}22" stroke="${badgeColor}" stroke-opacity="0.5" stroke-width="1" />
          <text x="185" y="19.5" font-family="'Rubik', 'Inter', sans-serif" font-size="8.5" font-weight="900" fill="${badgeColor}" text-anchor="middle" letter-spacing="0.3">${escapedBadge}</text>

          <!-- Informazioni testuali: Hostname e Indirizzo IP -->
          <text x="78" y="32" font-family="'Rubik', 'Inter', -apple-system, sans-serif" font-size="13" font-weight="900" fill="#ffffff" letter-spacing="-0.3">${escapedLabel}</text>
          <text x="78" y="49" font-family="Menlo, monospace" font-size="11" font-weight="700" fill="#bdb8c0">${escapedIp}</text>

          <!-- Badge del Vendor (Cisco, HPE) -->
          <rect x="78" y="58" width="55" height="14" rx="4" fill="rgba(44, 188, 195, 0.1)" stroke="rgba(44, 188, 195, 0.2)" stroke-width="1" />
          <text x="105.5" y="68" font-family="'Rubik', 'Inter', sans-serif" font-size="9" font-weight="900" fill="#b1a7f0" text-anchor="middle" letter-spacing="0.5">${escapedVendor}</text>

          <!-- Badge dello Stato Operativo (ONLINE, OFFLINE...) -->
          <rect x="139" y="58" width="70" height="14" rx="4" fill="${statusBg}" stroke="rgba(255,255,255,0.05)" stroke-width="1" />
          <text x="174" y="68" font-family="'Rubik', 'Inter', sans-serif" font-size="8" font-weight="900" fill="${statusColor}" text-anchor="middle" letter-spacing="0.5">${statusText}</text>

          <!-- Fascia VTP dedicata sotto le righe IP/badge (solo se presente): mai
               sovrapposta al badge tipo o all'hostname (Fix B). -->
          ${vtpDomainSvg}

        </svg>
        `;
        return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
    }

    // Generatore dinamico del Tooltip HTML premium per ciascun apparato (al passaggio del mouse)
    function createNodeTooltip(n, scan, resolvedVendor) {
        let statusLed = "";
        if (n.status === "online") statusLed = `<span style="color: #57d987; font-weight: bold;">● ONLINE</span>`;
        else if (n.status === "offline") statusLed = `<span style="color: #ff6b7c; font-weight: bold;">● OFFLINE</span>`;
        else if (n.status === "auth_failed") statusLed = `<span style="color: #ffb84d; font-weight: bold;">● AUTH FAILED</span>`;
        else if (n.status === "discovered") statusLed = `<span style="color: #a3a3a3; font-weight: bold;">● DISCOVERED</span>`;
        
        const firmware = (n.version) ? n.version : ((scan && scan.version) ? scan.version : (currentLang === 'en' ? "Not detected / Offline" : "Non rilevato / Offline"));
        const vendorName = (resolvedVendor && resolvedVendor !== 'discovered') ? resolvedVendor : (currentLang === 'en' ? "LLDP/CDP Neighbor" : "Vicino LLDP/CDP");
        
        const titleText = currentLang === 'en' ? 'Device Metadata' : 'Metadati Apparato';
        const labelIpText = currentLang === 'en' ? 'IP Address:' : 'Indirizzo IP:';
        const labelGroupText = currentLang === 'en' ? 'Tenant:' : 'Tenant:';
        const labelStatusText = currentLang === 'en' ? 'Network Status:' : 'Stato Rete:';

        // IP annunciato via CDP/LLDP diverso dall'IP di management reale: il vicino
        // ha pubblicato l'indirizzo di una SVI (es. Vlan1). Lo mostriamo come nota.
        const reportedRow = (n.reported_ip && n.reported_ip !== n.id) ? `
            <tr style="border: none;"><td style="color: var(--warning); font-size: 11px; padding: 2px 0; border: none; background:none;">${currentLang === 'en' ? 'Announced IP:' : 'IP Annunciato:'}</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:var(--warning);" title="${currentLang === 'en' ? 'CDP/LLDP advertised a non-management IP; resolved by hostname' : 'CDP/LLDP ha annunciato un IP non di management; risolto via hostname'}">${escapeHtml(n.reported_ip)} <i class="fa-solid fa-triangle-exclamation"></i></td></tr>` : '';

        const htmlString = `
        <div style="font-family: var(--font-main); min-width: 230px; color: var(--text);">
          <div style="font-size: 14px; font-weight: 700; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 6px; color: var(--primary); display: flex; align-items: center; gap: 8px;">
            <i class="fa-solid fa-network-wired"></i> ${titleText}
          </div>
          <table style="width: 100%; border-collapse: collapse; background: transparent;">
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; width: 90px; border: none; background:none;">Hostname:</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:#fff;">${escapeHtml(n.label)}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">${labelIpText}</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:#fff;">${escapeHtml(n.status === 'discovered' ? (n.reported_ip || '—') : n.id)}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">Vendor:</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; text-transform: uppercase; color:#fff;">${escapeHtml(vendorName)}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">${labelGroupText}</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:#fff;">${escapeHtml(n.group)}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">${labelStatusText}</td><td style="font-size: 11px; padding: 2px 0; border: none; background:none;">${statusLed}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">${currentLang === 'en' ? 'Type:' : 'Tipo:'}</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:${deviceTypeMeta(n.device_type).color};">${escapeHtml(deviceTypeLabel(n.device_type))}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">Firmware:</td><td style="font-size: 11px; padding: 2px 0; border: none; background:none;"><code style="font-family: var(--font-code); color: var(--primary); font-size: 10px;">${escapeHtml(firmware)}</code></td></tr>
            ${(n.vtp_domain || n.vtp_mode) ? `<tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">VTP:</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:${vtpDomainColor(n.vtp_domain)};">${escapeHtml([n.vtp_domain, n.vtp_mode].filter(Boolean).join(' · '))}</td></tr>` : ''}
            ${reportedRow}
          </table>
        </div>
        `;
        const container = document.createElement("div");
        container.innerHTML = htmlString;
        return container;
    }

    // ===== Checklist dispositivi (filtro esplicito per Sede/Gruppo) =====
    // ponytail: storage minimale, solo le ESCLUSIONI (default = tutto visibile),
    // indicizzate per Sede così la scelta non si mescola tra tenant diversi.
    // {"<gruppo>": ["id1","id2", ...]}
    let deviceFilterHidden = {};
    try { deviceFilterHidden = JSON.parse(localStorage.getItem('deviceFilterHidden') || '{}'); } catch (e) { deviceFilterHidden = {}; }
    function saveDeviceFilterHidden() { localStorage.setItem('deviceFilterHidden', JSON.stringify(deviceFilterHidden)); }
    function isDeviceHidden(group, id) {
        const arr = deviceFilterHidden[group];
        return !!(arr && arr.includes(id));
    }
    function toggleDeviceFilter(group, id, hidden) {
        const arr = deviceFilterHidden[group] || (deviceFilterHidden[group] = []);
        const idx = arr.indexOf(id);
        if (hidden && idx === -1) arr.push(id);
        if (!hidden && idx !== -1) arr.splice(idx, 1);
        saveDeviceFilterHidden();
        loadInteractiveMap();
    }
    // Popola la checklist coi dispositivi della Sede selezionata (dati grezzi,
    // prima del filtro per categoria/scoperti: la checklist mostra sempre tutto).
    function renderDeviceFilterMenu(nodesData, group) {
        const box = document.getElementById('deviceFilterList');
        if (!box) return;
        // Solo i dispositivi del Tenant scelto: i nodi "boundary" degli altri
        // tenant restano in mappa ma non compaiono nella checklist. Se il
        // dispositivo è in inventario fa fede il SUO tenant, non quello
        // ereditato via CDP/LLDP dallo switch che lo ha scoperto.
        if (group !== 'all' && Array.isArray(nodesData)) {
            nodesData = nodesData.filter(n => {
                const inv = globalDevices.find(d => d.IP === n.id);
                return (inv ? inv.Group : n.group) === group;
            });
        }
        if (!nodesData || !nodesData.length) {
            box.innerHTML = `<div style="font-size:12px; color:var(--text-muted);">${currentLang==='en'?'No devices':'Nessun dispositivo'}</div>`;
            return;
        }
        box.innerHTML = nodesData.map(n => `
            <label style="display:flex; align-items:center; gap:8px; padding:3px 0; font-size:12px; cursor:pointer; color:var(--text);">
                <input type="checkbox" ${isDeviceHidden(group, n.id) ? '' : 'checked'} onchange="toggleDeviceFilter('${attrEsc(group)}', '${attrEsc(n.id)}', !this.checked)" style="accent-color:var(--primary);">
                <span>${escapeHtml(n.label || n.id)}</span>
            </label>`).join('');
    }

    async function loadInteractiveMap() {
        const groupSelect = document.getElementById('interactiveGroupSelect');
        const selectedGroup = groupSelect ? groupSelect.value : 'all';
        
        const res = await apiFetch("/api/network-map?group=" + encodeURIComponent(selectedGroup));
        if (!res || !res.ok) return;
        const data = await res.json();

        // Stato degli interruttori di filtro/evidenziazione della mappa
        const highlightPC      = document.getElementById("togglePortChannel")?.checked || false;
        const showVtpDomain    = document.getElementById("toggleVtpDomain")?.checked || false;
        const showDiscovered   = document.getElementById("toggleDiscovered")?.checked || false;

        renderDeviceTypeLegend();
        renderMapCatMenu(data.nodes);
        renderDeviceFilterMenu(data.nodes, selectedGroup);

        // Filtra i nodi: terminali (server/telefoni/PC) e access point sono nascosti
        // di default, lasciando in mappa solo switch e router.
        const filteredNodesData = data.nodes.filter(n => {
            // I dispositivi scoperti (CDP/LLDP) si vedono solo col toggle "Mostra
            // Scoperti". La visibilità per TIPO è governata dal selettore Categorie.
            if (n.status === 'discovered' && !showDiscovered) return false;
            // Esclusione manuale via checklist dispositivi (per Sede/Gruppo).
            if (isDeviceHidden(selectedGroup, n.id)) return false;
            return isMapCatVisible(n.device_type);
        });

        // Mantieni solo i link i cui due estremi sono ancora visibili
        const validNodeIds = new Set(filteredNodesData.map(n => n.id));
        const filteredLinksData = data.links.filter(l => validNodeIds.has(l.source) && validNodeIds.has(l.target));

        // La nuova mappa minimalista riusa gli STESSI dati e filtri: cambia solo la
        // resa grafica. I Port-Channel qui sono visibili di default (etichetta
        // aggregata con le interfacce membro), senza bisogno di alcun interruttore.
        updateMapViewButtons();
        if (getMapView() === 'minimal') {
            const hoverInfo = document.getElementById("toggleMinimalHover")?.checked || false;
            const { nodes, edges, options, bundles, groupsInfo } = buildMinimalGraph(filteredNodesData, filteredLinksData, { showVtpDomain, highlightPC, hoverInfo });
            const hasOverlay = (bundles && bundles.length) || (groupsInfo && groupsInfo.length > 1);
            // Conservati per l'export Visio: il .vsdx replica ESATTAMENTE il
            // disegno dell'overlay (cavi paralleli, etichette porta, pillole).
            minimalOverlayData = { bundles, groupsInfo, nodes };
            renderNetwork(nodes, edges, options, MINIMAL_MAP_STYLE.background,
                          hasOverlay ? (ctx => drawMinimalOverlay(ctx, bundles, groupsInfo)) : null);
            return;
        }
        minimalOverlayData = null;

        // Trasforma nodi filtrati per l'interfaccia interattiva Vis.js
        const nodes = filteredNodesData.map(n => {
            const scan = globalVersions[n.id] || { version: currentLang === 'en' ? "Not detected" : "Non rilevato", status: n.status };
            
            // Risolve robustamente il vendor sul client confrontando l'IP con l'anagrafica di globalDevices
            const matchedDev = globalDevices.find(d => d.IP === n.id);
            const resolvedVendor = (n.vendor && n.vendor !== 'discovered')
                ? n.vendor
                : (matchedDev && matchedDev.Vendor ? matchedDev.Vendor : 'discovered');

            const vtp = { domain: n.vtp_domain, mode: n.vtp_mode, showDomain: showVtpDomain };

            return {
                id: n.id,
                shape: "image",
                image: createNodeSvg(n.label, n.id, n.device_type, n.status, n.is_boundary, resolvedVendor, vtp),
                title: createNodeTooltip(n, scan, resolvedVendor), // Tooltip HTML avanzato con vendor risolto
                // Fix B: la card SVG cresce (84->106) quando mostra la fascia VTP; il
                // nodo vis.js deve crescere di conseguenza, altrimenti l'immagine più
                // alta viene ridotta in scala e il testo torna illeggibile.
                size: (vtp.showDomain && vtp.domain) ? 46 : 38,
                labelVal: n.label,
                deviceTypeVal: n.device_type,
                isBoundaryVal: n.is_boundary || false,
                vendorVal: resolvedVendor,
                vtpVal: vtp,
                nodeDataVal: n
            };
        });

        // Trasforma archi filtrati per Vis.js con indicazioni di porta super leggibili ed eleganti
        const edges = filteredLinksData.map(l => {
            // Link aggregato (Port-Channel/LAG): evidenziato solo se il toggle è attivo
            const isPC      = !!l.is_portchannel;
            const emphasize = isPC && highlightPC;

            // Interfacce membro per lato (liste affidabili dal backend)
            const localPorts  = (Array.isArray(l.local_ports)  && l.local_ports.length)  ? l.local_ports  : [l.local_port];
            const remotePorts = (Array.isArray(l.remote_ports) && l.remote_ports.length) ? l.remote_ports : [l.remote_port];

            // Etichetta dell'aggregato: nome Port-channel dalla config, altrimenti
            // "LAG ×N" quando ci sono più link fisici verso lo stesso vicino.
            const pcTag = l.pc_name
                ? shortIface(l.pc_name)
                : (l.member_count > 1 ? `LAG ×${l.member_count}` : 'LAG');

            // Interfacce membro compatte: Et0/1+Et0/2 ⇄ Et0/0+Et0/2
            const localMembers  = localPorts.map(shortIface).filter(Boolean).join('+');
            const remoteMembers = remotePorts.map(shortIface).filter(Boolean).join('+');

            // visualizza le porte collegate come etichetta fluttuante sul cavo
            let portLabel = l.local_port && l.local_port !== 'Vicino' && l.local_port !== 'Neighbor'
                ? `${shortIface(l.local_port)} ⇄ ${shortIface(l.remote_port)}` : '';
            if (emphasize) {
                // Con l'evidenziazione attiva: nome del Port-channel + tutte le interfacce membro
                portLabel = `⛓ ${pcTag}`;
                if (localMembers && remoteMembers) portLabel += `\n${localMembers} ⇄ ${remoteMembers}`;
            }

            const pcBadge = isPC ? `
              <div style="display:inline-flex; align-items:center; gap:6px; font-size:10px; font-weight:700; color:var(--warning); background:rgba(255,184,77,0.12); border:1px solid rgba(255,184,77,0.3); padding:2px 7px; border-radius:5px; margin-bottom:8px;">
                <i class="fa-solid fa-link"></i> ${currentLang === 'en' ? 'AGGREGATED' : 'AGGREGATO'} · ${escapeHtml(l.pc_name || (currentLang === 'en' ? 'Port-Channel / LAG' : 'Port-Channel / LAG'))}${l.member_count > 1 ? ` · ${l.member_count} ${currentLang === 'en' ? 'members' : 'membri'}` : ''}
              </div>` : '';

            // Interfacce membro per lato, mostrate solo per gli aggregati
            const memberRows = (isPC && (localMembers || remoteMembers)) ? `
              <div style="margin-top:8px; border-top:1px solid rgba(255,255,255,0.08); padding-top:6px; font-family:var(--font-code); font-size:10px;">
                <div style="color:var(--text-muted); font-size:9px; text-transform:uppercase; margin-bottom:4px;">${currentLang === 'en' ? 'Member interfaces' : 'Interfacce membro'}</div>
                <div style="display:flex; justify-content:space-between; gap:10px; padding:1px 0;"><span style="color:var(--text-muted);">${escapeHtml(l.source)}</span><span style="color:var(--success);">${escapeHtml(localMembers || '—')}</span></div>
                <div style="display:flex; justify-content:space-between; gap:10px; padding:1px 0;"><span style="color:var(--text-muted);">${escapeHtml(l.target)}</span><span style="color:var(--success);">${escapeHtml(remoteMembers || '—')}</span></div>
              </div>` : '';

            // Generatore del Tooltip HTML premium al passaggio sul collegamento
            const linkTooltip = `
            <div style="font-family: var(--font-main); min-width: 240px; color: var(--text);">
              <div style="font-size: 13px; font-weight: 700; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 6px; color: var(--primary); display: flex; align-items: center; gap: 8px;">
                <i class="fa-solid fa-circle-nodes"></i> ${currentLang === 'en' ? 'Interconnection Link' : 'Link di Interconnessione'}
              </div>
              ${pcBadge}
              <div style="display: grid; grid-template-columns: 1fr 30px 1fr; gap: 8px; align-items: center; font-size: 11px; line-height: 1.4;">
                <div>
                  <span style="color: var(--text-muted); font-size: 9px; display: block; text-transform: uppercase; margin-bottom: 2px;">${currentLang === 'en' ? 'Source' : 'Origine'}</span>
                  <strong style="font-size:11px; color:#fff;">${escapeHtml(l.source)}</strong>
                  <code style="color: var(--success); display: block; font-family: var(--font-code); margin-top: 2px; font-size: 10px;">${escapeHtml(isPC ? (l.pc_name ? shortIface(l.pc_name) : (localMembers || l.local_port)) : l.local_port) || (currentLang === 'en' ? 'Port N/A' : 'Porta N/A')}</code>
                </div>
                <div style="color: var(--primary); font-size: 14px; text-align: center;"><i class="fa-solid fa-right-left"></i></div>
                <div style="text-align: right;">
                  <span style="color: var(--text-muted); font-size: 9px; display: block; text-transform: uppercase; margin-bottom: 2px;">${currentLang === 'en' ? 'Destination' : 'Destinazione'}</span>
                  <strong style="font-size:11px; color:#fff;">${escapeHtml(l.target)}</strong>
                  <code style="color: var(--success); display: block; font-family: var(--font-code); margin-top: 2px; font-size: 10px;">${escapeHtml(isPC ? (remoteMembers || l.remote_port) : l.remote_port) || (currentLang === 'en' ? 'Port N/A' : 'Porta N/A')}</code>
                </div>
              </div>
              ${memberRows}
            </div>
            `;
            const container = document.createElement("div");
            container.innerHTML = linkTooltip;

            return {
                from: l.source,
                to: l.target,
                label: portLabel,
                title: container, // HTML Tooltip DOM element
                font: {
                    color: emphasize ? "#ffb84d" : "#b1a7f0",
                    size: 11,
                    face: "Menlo, monospace",
                    strokeWidth: 0,
                    background: "#150f23" // Combacia con lo sfondo della mappa
                },
                color: emphasize
                    ? { color: "rgba(255, 184, 77, 0.85)", highlight: "#ffb84d", hover: "#ffd27d" }
                    : { color: "rgba(106, 95, 193, 0.45)", highlight: "#a99ff2", hover: "#c4bdf7" },
                dashes: emphasize ? [8, 4] : false,
                arrows: { to: { enabled: false } },
                width: emphasize ? 5 : 3.5,
                hoverWidth: 1.5,
                // ponytail: dati "piatti" (no oggetti color vis.js) usati solo dall'export Visio
                exportVal: { isPortChannel: isPC, pcName: l.pc_name || '', color: emphasize ? '#FFB84D' : '#6A5FC1' }
            };
        });

        renderNetwork(nodes, edges, classicMapOptions());
    }

    // ===== Selettore vista mappa (Classica / Nuova minimalista) =====
    // La scelta è ricordata in localStorage. Entrambe le viste condividono dati,
    // filtri, interruttori, selettore Sede/Categorie e istanza Vis.js.
    let mapViewMode = localStorage.getItem('mapViewMode') === 'minimal' ? 'minimal' : 'classic';
    function getMapView() { return mapViewMode; }
    function updateMapViewButtons() {
        const base = 'width:auto; margin:0; padding:5px 12px; border-radius:8px; border:1px solid; font-family:inherit; font-size:12px; font-weight:700; cursor:pointer;';
        const on  = base + 'background:var(--primary); color:#fff; border-color:var(--primary);';
        const off = base + 'background:var(--surface-2); color:var(--text-muted); border-color:var(--border);';
        const c = document.getElementById('mapViewClassicBtn');
        const m = document.getElementById('mapViewMinimalBtn');
        if (c) c.setAttribute('style', mapViewMode === 'classic' ? on : off);
        if (m) m.setAttribute('style', mapViewMode === 'minimal' ? on : off);
        // L'interruttore "Info al passaggio" riguarda solo la nuova mappa.
        const hw = document.getElementById('minimalHoverWrap');
        if (hw) hw.style.display = mapViewMode === 'minimal' ? 'inline-flex' : 'none';
        const hc = document.getElementById('toggleMinimalHover');
        if (hc) hc.checked = localStorage.getItem('minimalHoverInfo') === '1';
        // Color-picker/legenda dei tipi di link: visibile solo sulla nuova mappa.
        const lw = document.getElementById('minimalLegendWrap');
        if (lw) { lw.style.display = mapViewMode === 'minimal' ? 'inline-flex' : 'none'; if (mapViewMode === 'minimal') renderMinimalLegend(); }
        // Gestione categorie personalizzate: visibile solo sulla nuova mappa.
        const cm = document.getElementById('minimalCustomCatMenu');
        if (cm) { cm.style.display = mapViewMode === 'minimal' ? 'inline-block' : 'none'; if (mapViewMode === 'minimal') renderMinimalCustomCatPanel(); }
    }
    function setMapView(mode) {
        mapViewMode = (mode === 'minimal') ? 'minimal' : 'classic';
        localStorage.setItem('mapViewMode', mapViewMode);
        updateMapViewButtons();
        loadInteractiveMap();
    }

    // Fisica barnesHut condivisa da entrambe le viste (classica e minimalista).
    // Causa radice risolta QUI, non con toppe per-lato: valori tarati per nodi
    // grandi (riquadri SVG ~248px, vedi createNodeSvg) così i riquadri restano
    // compatti e non si sovrappongono ma nemmeno "volano via". La fisica serve
    // SOLO a calcolare un layout iniziale ben distanziato: viene spenta al
    // termine della stabilizzazione (freezeLayout), così i nodi non derivano e
    // restano dove l'utente li mette.
    function sharedMapPhysics() {
        return {
            enabled: true, solver: 'barnesHut',
            stabilization: { enabled: true, iterations: 300, updateInterval: 25, onlyDynamicEdges: false, fit: true },
            barnesHut: { gravitationalConstant: -3000, centralGravity: 0.4, springLength: 280, springConstant: 0.05, damping: 0.4, avoidOverlap: 1 },
            minVelocity: 0.75
        };
    }

    // Opzioni Vis.js della mappa classica.
    function classicMapOptions() {
        return {
            layout: { improvedLayout: true, randomSeed: 42 },
            physics: sharedMapPhysics(),
            interaction: { hover: true, hoverConnectedEdges: true, selectConnectedEdges: true, tooltipDelay: 150, dragNodes: true, dragView: true, zoomView: true, multiselect: true },
            nodes: { shadow: { enabled: true, color: "rgba(0,0,0,0.5)", size: 10, x: 0, y: 4 } },
            edges: { smooth: { type: 'cubicBezier', forceDirection: 'none', roundness: 0.5 }, shadow: { enabled: true, color: "rgba(0,0,0,0.4)", size: 4, x: 0, y: 2 } }
        };
    }

    // Crea/ricrea l'istanza Vis.js condivisa e congela il layout a stabilizzazione
    // completata (usata da entrambe le viste).
    function renderNetwork(nodes, edges, options, background, afterDraw) {
        const container = document.getElementById("networkGraphContainer");
        // Sfondo per-vista: la mappa minimalista usa il bianco, la classica torna
        // allo sfondo scuro definito nel CSS (#networkGraphContainer).
        container.style.background = background || '';

        // --- Conserva le posizioni tra un refresh e l'altro ---------------------
        // Ogni ricaricamento dati (polling triage/scan, cambio tab, toggle) ricrea
        // l'istanza Vis.js. Senza intervento la fisica riparte da zero e i nodi
        // "saltano", perdendo le posizioni trascinate dall'utente. Catturiamo le
        // posizioni correnti PRIMA di distruggere e le riapplichiamo ai nodi
        // omonimi; se TUTTI i nodi sono già noti spegniamo del tutto la fisica così
        // la mappa resta immobile (niente reset). I nodi nuovi mantengono la fisica.
        const prevPos = networkInstance ? networkInstance.getPositions() : null;
        if (prevPos) {
            nodes.forEach(nd => {
                const p = prevPos[nd.id];
                if (p) { nd.x = p.x; nd.y = p.y; }
            });
        }
        const allKnown = !!prevPos && nodes.length > 0 && nodes.every(nd => prevPos[nd.id]);
        if (allKnown) {
            // Clona per non mutare l'oggetto opzioni del chiamante e disattiva fisica.
            options = Object.assign({}, options, { physics: false });
        }

        const graphData = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
        if (networkInstance) networkInstance.destroy();
        networkInstance = new vis.Network(container, graphData, options);
        // Overlay disegnato in coordinate rete (ctx già trasformato da vis.js):
        // usato dalla vista minimalista per i fasci Port-Channel/vPC in stile Visio.
        if (typeof afterDraw === 'function') {
            networkInstance.on('afterDrawing', afterDraw);
        }
        // Nella nuova mappa i riquadri non possono MAI sovrapporsi: al termine
        // di ogni trascinamento il nodo mosso viene respinto fuori dai riquadri
        // che intersecherebbe (Fix no node overlapping).
        if (getMapView() === 'minimal') {
            networkInstance.on('dragEnd', p => {
                if (p.nodes && p.nodes.length) resolveNodeOverlaps(p.nodes);
            });
        }
        let mapFrozen = false;
        const isMinimal = getMapView() === 'minimal';
        const freezeLayout = () => {
            // Fix A: forma esplicita {enabled:false} (non solo lo shorthand booleano)
            // così vis.js disattiva anche il solver di stabilizzazione, non solo il
            // rendering della fisica: sulla mappa minimalista, con riquadri grandi e
            // avoidOverlap:1, il solver può non emettere mai 'stabilized' e restare
            // in animazione perenne se non forzato esplicitamente allo stop.
            if (networkInstance && !mapFrozen) { mapFrozen = true; networkInstance.setOptions({ physics: { enabled: false } }); }
        };
        networkInstance.once('stabilizationIterationsDone', freezeLayout);
        networkInstance.once('stabilized', freezeLayout);
        // Sulla mappa minimalista il solver barnesHut con riquadri grandi/avoidOverlap
        // può non stabilizzarsi mai: fallback più aggressivo (2.5s) per non lasciarla
        // in animazione percepibile "per sempre". La classica resta a 5s (invariata).
        networkInstance.once('afterDrawing', () => setTimeout(freezeLayout, isMinimal ? 2500 : 5000));
    }

    // Separazione AABB dei riquadri dopo un trascinamento: il nodo mosso viene
    // spinto fuori da ogni riquadro intersecato lungo l'asse di minima
    // penetrazione, iterando finché non restano sovrapposizioni.
    function resolveNodeOverlaps(movedIds) {
        if (!networkInstance) return;
        const margin = 14;
        const allIds = networkInstance.body.data.nodes.getIds();
        for (let iter = 0; iter < 15; iter++) {
            let pushed = false;
            movedIds.forEach(id => {
                let bb; try { bb = networkInstance.getBoundingBox(id); } catch (e) { return; }
                let pos = networkInstance.getPosition(id);
                allIds.forEach(oid => {
                    if (oid === id || movedIds.includes(oid) && oid < id) return;
                    let ob; try { ob = networkInstance.getBoundingBox(oid); } catch (e) { return; }
                    const overlapX = Math.min(bb.right, ob.right) - Math.max(bb.left, ob.left) + margin;
                    const overlapY = Math.min(bb.bottom, ob.bottom) - Math.max(bb.top, ob.top) + margin;
                    if (overlapX <= 0 || overlapY <= 0) return;
                    const op = networkInstance.getPosition(oid);
                    if (overlapX < overlapY) {
                        const dir = pos.x >= op.x ? 1 : -1;
                        networkInstance.moveNode(id, pos.x + dir * overlapX, pos.y);
                    } else {
                        const dir = pos.y >= op.y ? 1 : -1;
                        networkInstance.moveNode(id, pos.x, pos.y + dir * overlapY);
                    }
                    pushed = true;
                    bb = networkInstance.getBoundingBox(id);
                    pos = networkInstance.getPosition(id);
                });
            });
            if (!pushed) break;
        }
        // moveNode() qui è un salto diretto (nessuna fisica coinvolta): ribadiamo
        // comunque physics disattivata per difesa, nel caso una regressione futura
        // la riattivasse durante il drag (Fix A: la mappa non deve mai tornare ad
        // animarsi da sola dopo la stabilizzazione iniziale).
        networkInstance.setOptions({ physics: { enabled: false } });
        networkInstance.redraw();
    }

    // ===== Nuova mappa minimalista (stile diagramma Visio) =====
    // Stili centralizzati: modificare QUI per ritoccare la resa (nodi, colori,
    // spessori, font). Ispirata all'immagine di esempio fornita dall'utente.
    const MINIMAL_MAP_STYLE = {
        background: '#ffffff',                     // sfondo bianco/neutro, alta leggibilità
        node: {
            shape: 'box',                          // riquadri rettangolari a spigoli vivi
            borderRadius: 0,
            borderWidth: 1,
            borderColor: '#37474f',                // bordo scuro sottile
            margin: { top: 8, right: 12, bottom: 8, left: 12 },
            font: { multi: 'html', color: '#1a2430', size: 12, face: 'Arial, Helvetica, sans-serif', strokeWidth: 0,
                    // <i> = riga di management attenuata e più piccola; <b> = nome host.
                    ital: { color: '#6b7a8a', size: 10, face: 'Arial, Helvetica, sans-serif' },
                    bold: { color: '#1a2430', size: 12, face: 'Arial, Helvetica, sans-serif' } },
            offlineOpacity: 0.45,
            // Riempimenti pastello per categoria di apparato (varianti ciano/giallo pallido)
            fill: {
                switch:   '#d8f0f7',
                router:   '#def0dc',
                firewall: '#fbe4e2',
                wlc:      '#ebe2f7',
                ap:       '#e0ecfb',
                server:   '#fdf3d5',
                phone:    '#dcf5ef',
                pc:       '#ededed',
                other:    '#f4f4f4'
            }
        },
        edge: {
            color:   '#78909c',                    // link semplice: pieno, tonalità sobria
            width:   1.5,
            pcColor: '#8B4513',                    // aggregato Port-Channel/vPC: rame/marrone (stile Cisco)
            pcWidth: 2,
            emphWidth: 3,                          // con "Evidenzia Port-Channel"
            peerColor: '#2e7d32',                  // peer-link / peer-keepalive vPC: verde
            font: { multi: 'html', color: '#455a64', size: 10, face: 'Arial, Helvetica, sans-serif', strokeWidth: 0, background: '#ffffff' },
            pcFontColor: '#8B4513',
            // Contenitore tratteggiato di raggruppamento per Sede/Gruppo
            group: { stroke: '#90a4ae', fill: 'rgba(120,144,156,0.05)', font: '#607d8b' }
        }
    };

    // ponytail: unica fonte tipo→colore per render + legenda + color-picker.
    // I default ricalcano i colori di MINIMAL_MAP_STYLE; l'utente li può cambiare
    // e la scelta è ricordata in localStorage e applicata a ogni ridisegno.
    const MINIMAL_LINK_TYPES = [
        { key: 'pc',        it: 'Port-Channel',      en: 'Port-Channel',      def: MINIMAL_MAP_STYLE.edge.pcColor },
        { key: 'peer',      it: 'Peer-link / vPC',   en: 'Peer-link / vPC',   def: MINIMAL_MAP_STYLE.edge.peerColor },
        { key: 'keepalive', it: 'Peer-keepalive',    en: 'Peer-keepalive',    def: MINIMAL_MAP_STYLE.edge.peerColor },
        { key: 'link',      it: 'Link semplice',     en: 'Simple link',       def: MINIMAL_MAP_STYLE.edge.color }
    ];
    let minimalLinkColors = {};
    try { minimalLinkColors = JSON.parse(localStorage.getItem('minimalLinkColors') || '{}'); } catch (e) { minimalLinkColors = {}; }
    function linkColor(key) {
        if (minimalLinkColors[key]) return minimalLinkColors[key];
        const t = MINIMAL_LINK_TYPES.find(x => x.key === key);
        return t ? t.def : MINIMAL_MAP_STYLE.edge.color;
    }
    // Converte un colore #rrggbb nel corrispondente rgba() con alpha (per i
    // riempimenti traslucidi della pillola aggregata).
    function hexToRgba(hex, a) {
        const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex || '');
        if (!m) return hex;
        return `rgba(${parseInt(m[1],16)},${parseInt(m[2],16)},${parseInt(m[3],16)},${a})`;
    }
    // Color-picker + legenda della nuova mappa: righe generate dalla stessa
    // tabella tipo→colore usata dal renderer (fonte unica).
    function renderMinimalLegend() {
        const box = document.getElementById('minimalLegendWrap');
        if (!box) return;
        box.innerHTML = MINIMAL_LINK_TYPES.map(t => `
            <label style="display:inline-flex; align-items:center; gap:5px; font-size:11px; font-weight:700; color:var(--text-muted); cursor:pointer; user-select:none;" title="${currentLang==='en'?t.en:t.it}">
                <input type="color" value="${linkColor(t.key)}" onchange="setMinimalLinkColor('${t.key}', this.value)" style="width:22px; height:18px; padding:0; border:1px solid var(--border); border-radius:4px; background:none; cursor:pointer;">
                <span>${currentLang==='en'?t.en:t.it}</span>
            </label>`).join('')
            // Categorie personalizzate (sola visualizzazione: gestione nel pannello
            // dedicato "Categorie link"), stessa tabella tipo→colore mostrata come
            // fonte unica di legenda.
            + Object.keys(minimalCustomCats.categories).map(nm => {
                const c = minimalCustomCats.categories[nm];
                return `<span style="display:inline-flex; align-items:center; gap:5px; font-size:11px; font-weight:700; color:var(--text-muted);" title="${escapeHtml(nm)}">
                    <span style="width:18px; height:0; border-top:2px ${c.dash==='dashed'?'dashed':(c.dash==='dotted'?'dotted':'solid')} ${c.color}; display:inline-block;"></span>
                    <span>${escapeHtml(nm)}</span>
                </span>`;
            }).join('');
    }
    function setMinimalLinkColor(key, val) {
        minimalLinkColors[key] = val;
        localStorage.setItem('minimalLinkColors', JSON.stringify(minimalLinkColors));
        renderMinimalLegend();
        loadInteractiveMap();
    }

    // ===== Categorie personalizzate per i link (assegnazione manuale) =====
    // ponytail: stessa idea della tabella tipo→colore sopra, ma per categorie
    // create dall'utente e assegnate a SINGOLI collegamenti (non per tipo).
    // Storage minimale in localStorage: { categories: {nome:{color,dash}},
    // assignments: {edgeKey:nome} }. edgeKey = stessa chiave stabile from~to~pcTag
    // già usata per le pillole Port-Channel spostabili (pillKey), così un solo
    // formato di chiave copre entrambe le feature.
    let minimalCustomCats = { categories: {}, assignments: {} };
    try {
        const parsed = JSON.parse(localStorage.getItem('minimalCustomCats') || '{}');
        minimalCustomCats.categories = parsed.categories || {};
        minimalCustomCats.assignments = parsed.assignments || {};
    } catch (e) { /* mantiene i default vuoti */ }
    function saveMinimalCustomCats() { localStorage.setItem('minimalCustomCats', JSON.stringify(minimalCustomCats)); }
    function dashArrFor(style) { return style === 'dashed' ? [6, 4] : style === 'dotted' ? [2, 3] : null; }
    // Stile di una categoria personalizzata assegnata a un arco (se presente):
    // vince sempre sullo stile per-tipo standard in styleFor().
    function customStyleForEdge(edgeKey) {
        const nm = minimalCustomCats.assignments[edgeKey];
        const c = nm && minimalCustomCats.categories[nm];
        return c ? { color: c.color, dash: dashArrFor(c.dash) } : null;
    }
    function addMinimalCustomCat() {
        const nameInput = document.getElementById('minimalCatNameInput');
        const colorInput = document.getElementById('minimalCatColorInput');
        const dashInput = document.getElementById('minimalCatDashInput');
        const name = (nameInput?.value || '').trim();
        if (!name) return;
        minimalCustomCats.categories[name] = { color: colorInput?.value || '#607d8b', dash: dashInput?.value || 'solid' };
        saveMinimalCustomCats();
        if (nameInput) nameInput.value = '';
        renderMinimalCustomCatPanel();
        loadInteractiveMap();
    }
    function deleteMinimalCustomCat(name) {
        delete minimalCustomCats.categories[name];
        Object.keys(minimalCustomCats.assignments).forEach(k => {
            if (minimalCustomCats.assignments[k] === name) delete minimalCustomCats.assignments[k];
        });
        saveMinimalCustomCats();
        renderMinimalCustomCatPanel();
        loadInteractiveMap();
    }
    // Piccola UI di gestione accanto a legenda/color-picker: elenco categorie
    // (pallino colore + stile tratteggio + elimina) e form nativo per crearne una.
    function renderMinimalCustomCatPanel() {
        const box = document.getElementById('minimalCustomCatList');
        if (!box) return;
        const names = Object.keys(minimalCustomCats.categories);
        const dashLabel = d => d === 'dashed' ? (currentLang==='en'?'Dashed':'Tratteggiata')
                              : d === 'dotted' ? (currentLang==='en'?'Dotted':'Punteggiata')
                              : (currentLang==='en'?'Solid':'Continua');
        const rows = names.map(nm => {
            const c = minimalCustomCats.categories[nm];
            return `<div style="display:flex; align-items:center; gap:6px; padding:3px 0;">
                <span style="width:14px; height:14px; border-radius:4px; background:${c.color}; border:1px solid var(--border); display:inline-block;"></span>
                <span style="flex:1; font-size:12px; color:var(--text);">${escapeHtml(nm)}</span>
                <span style="font-size:10px; color:var(--text-muted);">${dashLabel(c.dash)}</span>
                <button onclick="deleteMinimalCustomCat('${attrEsc(nm)}')" title="${currentLang==='en'?'Delete':'Elimina'}" style="background:none; border:none; color:#e05656; cursor:pointer; font-size:12px; padding:2px;"><i class="fa-solid fa-trash-can"></i></button>
            </div>`;
        }).join('') || `<div style="font-size:12px; color:var(--text-muted); padding:4px 0;">${currentLang==='en'?'No categories yet':'Nessuna categoria'}</div>`;
        box.innerHTML = rows + `
            <div style="display:flex; align-items:center; gap:6px; margin-top:8px; padding-top:8px; border-top:1px solid var(--border);">
                <input id="minimalCatNameInput" type="text" placeholder="${currentLang==='en'?'Name':'Nome'}" style="flex:1; min-width:0; padding:4px 6px; border-radius:5px; border:1px solid var(--border); background:var(--surface-1); color:var(--text); font-size:12px;">
                <input id="minimalCatColorInput" type="color" value="#607d8b" style="width:24px; height:24px; padding:0; border:1px solid var(--border); border-radius:4px; background:none; cursor:pointer;">
                <select id="minimalCatDashInput" style="padding:3px; border-radius:5px; border:1px solid var(--border); background:var(--surface-1); color:var(--text); font-size:11px;">
                    <option value="solid">${currentLang==='en'?'Solid':'Continua'}</option>
                    <option value="dashed">${currentLang==='en'?'Dashed':'Tratteggiata'}</option>
                    <option value="dotted">${currentLang==='en'?'Dotted':'Punteggiata'}</option>
                </select>
                <button onclick="addMinimalCustomCat()" title="${currentLang==='en'?'Add category':'Aggiungi categoria'}" style="background:var(--primary); color:#fff; border:none; border-radius:5px; padding:4px 8px; cursor:pointer; font-size:12px;"><i class="fa-solid fa-plus"></i></button>
            </div>`;
    }
    // Menu contestuale (click destro su un cavo nella mappa minimalista) per
    // assegnare/rimuovere la categoria personalizzata di un singolo collegamento.
    function closeEdgeCatMenu() {
        const m = document.getElementById('edgeCatMenu');
        if (m) m.remove();
        document.removeEventListener('mousedown', closeEdgeCatMenuOutside, true);
    }
    function closeEdgeCatMenuOutside(ev) {
        const m = document.getElementById('edgeCatMenu');
        if (m && !m.contains(ev.target)) closeEdgeCatMenu();
    }
    function showEdgeCatMenu(x, y, edgeKey) {
        closeEdgeCatMenu();
        const names = Object.keys(minimalCustomCats.categories);
        const cur = minimalCustomCats.assignments[edgeKey];
        const div = document.createElement('div');
        div.id = 'edgeCatMenu';
        div.style.cssText = `position:fixed; left:${x}px; top:${y}px; z-index:9999; background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:6px; box-shadow:0 10px 30px rgba(0,0,0,0.5); font-family:inherit; font-size:12px; min-width:170px;`;
        const rowsHtml = names.length ? names.map(nm => `
            <div class="edgeCatRow" data-nm="${attrEsc(nm)}" style="display:flex; align-items:center; gap:6px; padding:4px 6px; border-radius:5px; cursor:pointer; color:var(--text); ${nm===cur?'background:rgba(120,144,156,0.25);':''}">
                <span style="width:10px; height:10px; border-radius:50%; background:${minimalCustomCats.categories[nm].color}; display:inline-block;"></span>
                <span>${escapeHtml(nm)}</span>
            </div>`).join('')
            : `<div style="padding:4px 6px; color:var(--text-muted);">${currentLang==='en'?'No custom categories yet':'Nessuna categoria personalizzata'}</div>`;
        const noneRow = `<div class="edgeCatRow" data-nm="" style="display:flex; align-items:center; gap:6px; padding:4px 6px; border-radius:5px; cursor:pointer; color:var(--text-muted);">${currentLang==='en'?'None (default style)':'Nessuna (stile predefinito)'}</div>`;
        div.innerHTML = rowsHtml + `<div style="border-top:1px solid var(--border); margin:4px 0;"></div>` + noneRow;
        document.body.appendChild(div);
        div.querySelectorAll('.edgeCatRow').forEach(row => {
            row.addEventListener('click', () => {
                const nm = row.getAttribute('data-nm');
                if (nm) minimalCustomCats.assignments[edgeKey] = nm;
                else delete minimalCustomCats.assignments[edgeKey];
                saveMinimalCustomCats();
                closeEdgeCatMenu();
                if (networkInstance) networkInstance.redraw();
            });
        });
        setTimeout(() => document.addEventListener('mousedown', closeEdgeCatMenuOutside, true), 0);
    }

    // Costruisce nodi/archi/opzioni per la vista minimalista dai medesimi dati già
    // filtrati della mappa classica. Nodi = riquadri con nome in grassetto e
    // vendor/modello sulla seconda riga; i Port-Channel sono SEMPRE visibili come
    // un arco aggregato con etichetta "Po1" + coppie di interfacce membro sotto.
    function buildMinimalGraph(nodeData, linkData, opts) {
        const S = MINIMAL_MAP_STYLE;
        const showVtpDomain = !!(opts && opts.showVtpDomain);
        const highlightPC   = !!(opts && opts.highlightPC);
        // Tooltip al passaggio del mouse: opt-in tramite l'interruttore dedicato.
        // Le informazioni Port-Channel restano comunque SEMPRE visibili come
        // etichette permanenti sul disegno.
        const hoverInfo     = !!(opts && opts.hoverInfo);

        // Raggruppamento spaziale per Sede: ogni gruppo riceve un "centro" su una
        // circonferenza e i suoi nodi partono da lì (la fisica mantiene i cluster).
        // vis.js non supporta i riquadri tratteggiati di raggruppamento: si
        // approssima con la sola vicinanza spaziale.
        const groups = [...new Set(nodeData.map(n => n.group || 'Generale'))];
        const groupCenter = {};
        groups.forEach((g, i) => {
            const angle = (2 * Math.PI * i) / groups.length;
            const radius = groups.length > 1 ? 600 : 0;
            groupCenter[g] = { x: Math.cos(angle) * radius, y: Math.sin(angle) * radius };
        });

        const nodes = nodeData.map((n, idx) => {
            const scan = globalVersions[n.id] || { version: currentLang === 'en' ? "Not detected" : "Non rilevato", status: n.status };
            const matchedDev = globalDevices.find(d => d.IP === n.id);
            const resolvedVendor = (n.vendor && n.vendor !== 'discovered')
                ? n.vendor : (matchedDev && matchedDev.Vendor ? matchedDev.Vendor : 'discovered');

            // Seconda riga del riquadro: vendor + modello (es. "Cisco N9K-C93180YC-EX")
            const vendorTxt = (resolvedVendor && resolvedVendor !== 'discovered')
                ? resolvedVendor.charAt(0).toUpperCase() + resolvedVendor.slice(1) : '';
            const modelLine = [vendorTxt, n.model || n.platform || ''].filter(Boolean).join(' ').trim();
            // Riga di management (piccola, in corsivo/attenuata): VLAN + IP di
            // gestione mostrati DENTRO il riquadro. La VLAN arriva dal backend
            // (SVI con l'IP di management); se assente si mostra solo l'IP.
            const mgmtIp = n.mgmt_ip || (n.status === 'discovered' ? n.reported_ip : n.id) || '';
            const mgmtBits = [];
            if (n.mgmt_vlan) mgmtBits.push((currentLang === 'en' ? 'VLAN ' : 'VLAN ') + n.mgmt_vlan);
            if (mgmtIp) mgmtBits.push(mgmtIp);
            const mgmtLine = mgmtBits.join('  ·  ');
            let label = `<b>${n.label}</b>`;
            if (modelLine) label += `\n${modelLine}`;
            if (mgmtLine)  label += `\n<i>${mgmtLine}</i>`;

            // Riempimento pastello per categoria; col toggle VTP il bordo assume il
            // colore del dominio VTP (il riempimento resta neutro e leggibile).
            const fill = S.node.fill[n.device_type] || S.node.fill.other;
            const border = showVtpDomain && n.vtp_domain ? vtpDomainColor(n.vtp_domain) : S.node.borderColor;

            // Posizione iniziale: attorno al centro del proprio gruppo/Sede.
            const c = groupCenter[n.group || 'Generale'] || { x: 0, y: 0 };
            const jitter = 180;

            return {
                id: n.id,
                shape: S.node.shape,
                shapeProperties: { borderRadius: S.node.borderRadius },
                margin: S.node.margin,
                label,
                title: hoverInfo ? createNodeTooltip(n, scan, resolvedVendor) : undefined,
                borderWidth: showVtpDomain && n.vtp_domain ? 2 : S.node.borderWidth,
                borderWidthSelected: S.node.borderWidth + 1,
                color: {
                    background: fill, border,
                    highlight: { background: fill, border: '#1a2430' },
                    hover: { background: fill, border: '#1a2430' }
                },
                opacity: (n.status === 'offline') ? S.node.offlineOpacity : 1,
                font: S.node.font,
                x: c.x + ((idx * 137) % (2 * jitter)) - jitter,
                y: c.y + ((idx * 89)  % (2 * jitter)) - jitter,
                nodeDataVal: n,
                // Testi della targhetta (nome + vendor/modello) usati dal
                // dimensionamento per garantire che le etichette di porta
                // disegnate ai bordi non collidano mai col nome centrale.
                _nameTexts: [n.label || '', modelLine, mgmtLine]
            };
        });

        // Fasci Port-Channel/vPC con ≥2 interfacce membro: disegnati come linee
        // parallele separate (una per cavo fisico) con etichette di porta a ciascun
        // estremo e un'ellisse "Po/vPC" che attraversa il gruppo (stile Cisco Visio).
        // Questi non producono un arco vis.js visibile: sono resi nell'overlay
        // afterDrawing. Un arco invisibile viene comunque creato per mantenere la
        // fisica (attrazione tra i due nodi) e il tooltip.
        // Mappa id→label per riconoscere coppie di peer vPC (es. EX_1/EX_2, Nexus-A/
        // Nexus-B) dagli hostname, e info di raggruppamento per i contenitori Sede.
        const labelById = {};
        nodeData.forEach(n => { labelById[n.id] = n.label || n.id; });
        // vPC esiste solo su NX-OS: la coppia peer va confermata dalla
        // piattaforma (modello/platform Nexus), altrimenti un normale
        // Port-channel tra "SW1"/"SW2" verrebbe etichettato a torto "poX/vpc"
        // (fix §9.7 del piano). Heuristica hostname mantenuta SOLO come
        // condizione aggiuntiva, mai da sola.
        const isNxos = {};
        nodeData.forEach(n => {
            isNxos[n.id] = /nexus|nx-?os|\bn[359]k\b/i.test(
                [n.model, n.platform, n.version].filter(Boolean).join(' '));
        });
        const isMgmtPort = p => /mgmt|ma\d|management/i.test(p || '');
        // Due nodi formano una coppia peer se gli hostname condividono lo stesso
        // prefisso e differiscono solo per il suffisso finale (1/2, A/B, _1/_2…).
        const looksLikePeerPair = (a, b) => {
            const na = String(a || '').split('.')[0], nb = String(b || '').split('.')[0];
            if (!na || !nb || na.toLowerCase() === nb.toLowerCase()) return false;
            const strip = s => s.replace(/[ _-]?([12]|[ab])$/i, '');
            const ra = strip(na), rb = strip(nb);
            return ra && ra.toLowerCase() === rb.toLowerCase() && ra !== na && rb !== nb;
        };

        // Info raggruppamento per Sede/Gruppo (contenitore tratteggiato nell'overlay).
        const groupsInfo = groups.map(g => ({
            group: g,
            ids: nodeData.filter(n => (n.group || 'Generale') === g).map(n => n.id)
        })).filter(gi => gi.ids.length > 0);

        const bundles = [];
        // Requisiti di dimensione per nodo: per far stare TUTTE le etichette di porta
        // disegnate dentro il riquadro (Fix dimensionamento dinamico). Per ciascun
        // nodo si tiene lo "spread" massimo (n. membri × spaziatura) e la larghezza
        // massima del testo di porta, misurata con lo stesso font dell'overlay.
        const _measCanvas = document.createElement('canvas');
        const _measCtx = _measCanvas.getContext('2d');
        _measCtx.font = '9px Arial, Helvetica, sans-serif';
        const measurePort = t => t ? _measCtx.measureText(t).width : 0;
        const nodeReq = {};   // id -> { spread, labelW, slots }
        const bumpReq = (id, spread, labelW, slots) => {
            const r = nodeReq[id] || (nodeReq[id] = { spread: 0, labelW: 0, slots: 0 });
            r.spread = Math.max(r.spread, spread);
            r.labelW = Math.max(r.labelW, labelW);
            r.slots += slots || 0;
        };
        const edges = linkData.map(l => {
            const isPC      = !!l.is_portchannel;
            const emphasize = isPC && highlightPC;
            // Peer vPC: mgmt0↔mgmt0 = peer-keepalive; PortChannel tra una coppia di
            // peer (hostname appaiati) = peer-link. Entrambi resi in verde.
            // Entrambi gli estremi devono essere NX-OS (o il backend deve
            // marcare esplicitamente l.is_vpc): mai vPC su piattaforme IOS.
            const bothNxos = !!(isNxos[l.source] && isNxos[l.target]);
            const isKeepalive = bothNxos && isMgmtPort(l.local_port) && isMgmtPort(l.remote_port);
            const isPeerLink  = isPC && (l.is_vpc === true ||
                (bothNxos && looksLikePeerPair(labelById[l.source], labelById[l.target])));

            const localPorts  = (Array.isArray(l.local_ports)  && l.local_ports.length)  ? l.local_ports  : [l.local_port];
            const remotePorts = (Array.isArray(l.remote_ports) && l.remote_ports.length) ? l.remote_ports : [l.remote_port];
            const members       = localPorts.map(shortIface).filter(Boolean).join(', ');
            const remoteMembers = remotePorts.map(shortIface).filter(Boolean).join(', ');
            const pcTag = l.pc_name ? shortIface(l.pc_name) : (l.member_count > 1 ? `LAG ×${l.member_count}` : 'LAG');
            // Nome aggregato per-lato: il Port-channel può avere id diverso sui due
            // estremi (es. Po1 su A, Po4 su B). Se differiscono si etichetta ciascun
            // estremo col proprio id; se coincidono si tiene la pillola centrale.
            const localPcTag  = l.local_pc  ? shortIface(l.local_pc)  : pcTag;
            const remotePcTag = l.remote_pc ? shortIface(l.remote_pc) : pcTag;
            const asymmetricPc = !!(localPcTag && remotePcTag && localPcTag !== remotePcTag);

            // OGNI collegamento è reso dall'overlay ortogonale con stile
            // UNIFORME (Fix rappresentazione standardizzata): i Port-Channel
            // come fascio di cavi paralleli attraversati dalla pillola ovale
            // (anche quando è nota una sola interfaccia membro), i link
            // semplici come cavo singolo ortogonale con le etichette di porta
            // sul bordo interno del riquadro (Fix porte non aggregate).
            // L'arco vis.js resta sempre invisibile: mantiene solo fisica,
            // selezione e tooltip.
            const clean = s => (s && s !== 'Vicino' && s !== 'Neighbor') ? s : '';
            const memberPairs = [];
            const maxMembers = Math.max(localPorts.length, remotePorts.length);
            if (isPC && maxMembers > 1) {
                for (let i = 0; i < maxMembers; i++) {
                    memberPairs.push({
                        local:  shortIface(localPorts[i]  || localPorts[localPorts.length - 1]   || ''),
                        remote: shortIface(remotePorts[i] || remotePorts[remotePorts.length - 1] || '')
                    });
                }
            } else {
                memberPairs.push({ local: clean(shortIface(l.local_port)),
                                   remote: clean(shortIface(l.remote_port)) });
            }
            const type = (isKeepalive && !isPC) ? 'keepalive'
                       : (isPeerLink ? 'peer' : (isPC ? 'pc' : 'link'));
            // ponytail: formato etichetta "poX/vpc" quando vPC, "poX" altrimenti,
            // con 'po' minuscolo (richiesta utente). lc() abbassa il prefisso Po→po.
            const lc = t => (t || '').replace(/^Po/i, 'po');
            bundles.push({
                from: l.source, to: l.target,
                pcTag, members: memberPairs, emphasize,
                // 'peer' = peer-link vPC (verde), 'pc' = aggregato dati (rame),
                // 'keepalive' = mgmt0↔mgmt0 (verde tratteggiato), 'link' = semplice.
                type,
                label: type === 'peer' ? `${lc(pcTag)}/vpc`
                     : (type === 'pc' ? lc(pcTag)
                     : (type === 'keepalive' ? 'peer-keepalive' : '')),
                localPcTag, remotePcTag, asymmetricPc: isPC && asymmetricPc,
                // Etichette per-estremo quando i nomi differiscono tra i due lati.
                localLabel:  isPeerLink ? `${lc(localPcTag)}/vpc`  : lc(localPcTag),
                remoteLabel: isPeerLink ? `${lc(remotePcTag)}/vpc` : lc(remotePcTag)
            });

            // Requisiti di spazio per i due nodi: lo spread dei cavi, la
            // larghezza del testo di porta più lungo su ciascun lato e il
            // numero di slot occupati sul perimetro del riquadro.
            const spread = (memberPairs.length - 1) * 11;
            const locW = Math.max(...memberPairs.map(m => measurePort(m.local)), 0);
            const remW = Math.max(...memberPairs.map(m => measurePort(m.remote)), 0);
            bumpReq(l.source, spread, locW, memberPairs.length);
            bumpReq(l.target, spread, remW, memberPairs.length);

            const tip = document.createElement('div');
            tip.innerHTML = `<div style="font-family:var(--font-main); min-width:180px; color:var(--text); font-size:11px;">
                <strong style="color:var(--primary);">${escapeHtml(l.source)} ⇄ ${escapeHtml(l.target)}</strong>
                ${isPC ? `<div style="margin-top:4px; color:var(--text-muted);">${currentLang==='en'?'Aggregate':'Aggregato'}: <span style="color:var(--warning);">${escapeHtml(pcTag)}</span>${l.member_count > 1 ? ` · ${l.member_count} ${currentLang==='en'?'members':'membri'}` : ''}</div>
                <div style="font-family:var(--font-code); font-size:10px; margin-top:2px;">${escapeHtml(members||'—')} ⇄ ${escapeHtml(remoteMembers||'—')}</div>`
                : `<div style="font-family:var(--font-code); font-size:10px; margin-top:4px;">${escapeHtml(shortIface(l.local_port)||'—')} ⇄ ${escapeHtml(shortIface(l.remote_port)||'—')}</div>`}
            </div>`;

            // Tutto il disegno visibile avviene nell'overlay: l'arco vis.js è
            // sempre trasparente e serve solo per fisica, selezione e tooltip.
            return {
                from: l.source, to: l.target,
                label: '',
                title: hoverInfo ? tip : undefined,
                color: { color: 'rgba(0,0,0,0)', highlight: 'rgba(0,0,0,0)', hover: 'rgba(0,0,0,0)' },
                width: 0.0001,
                arrows: { to: { enabled: false } },
                smooth: { type: 'continuous', roundness: 0.2 }
            };
        });

        // Dimensionamento dinamico dei riquadri (Fix auto-expanding + Fix
        // leggibilità etichette): larghezza e altezza minime tali che il blocco
        // di testo centrale (nome + vendor/modello + riga management) e TUTTE le
        // etichette di porta disegnate ai bordi dall'overlay convivano con un
        // buffer costante, senza mai sovrapporsi né toccare il bordo.
        //
        // Causa radice risolta QUI (layout condiviso, non toppe per-lato): sui
        // lati N/S l'overlay impila le etichette di porta a partire dal bordo
        // VERSO il centro (una per riga, LINE_H px); con molte porte finivano
        // sopra il nome. Riserviamo al centro una "fascia nome" e cresciamo il
        // riquadro così che la pila peggiore (tutti gli slot su un solo lato)
        // resti separata dalla fascia nome di almeno BUF px. Sui lati E/W le
        // etichette stanno sul bordo, già separate dal nome dalla larghezza.
        const INSET = 13;       // distanza etichetta↔bordo (buffer ampio, ≥ richiesto)
        const LINE_H = 11;      // passo di impilamento/etichetta (= 'spacing' overlay)
        const BUF = 6;          // buffer costante etichetta↔fascia-nome / ↔bordo
        const EDGE_INSET = 14;  // margine ancoraggi dagli angoli (= overlay)
        nodes.forEach(nd => {
            const r = nodeReq[nd.id];
            if (!r) return;
            _measCtx.font = 'bold 12px Arial, Helvetica, sans-serif';
            const nameW = _measCtx.measureText(nd._nameTexts[0] || '').width;
            _measCtx.font = '12px Arial, Helvetica, sans-serif';
            const modelW = _measCtx.measureText(nd._nameTexts[1] || '').width;
            _measCtx.font = 'italic 10px Arial, Helvetica, sans-serif';
            const mgmtW = _measCtx.measureText(nd._nameTexts[2] || '').width;
            const textW = Math.max(nameW, modelW, mgmtW);
            // Fascia verticale occupata dal blocco nome (righe non vuote × ~14px).
            const nameLines = nd._nameTexts.filter(Boolean).length || 1;
            const nameH = nameLines * 14;
            // Caso peggiore: tutti gli slot del nodo impilati su UN solo lato.
            const stack = r.slots * LINE_H;
            // Altezza: la pila peggiore su ciascun lato + buffer resta fuori dalla
            // fascia nome centrata → H/2 ≥ INSET + stack + BUF + nameH/2.
            const minH = Math.max(2 * (INSET + stack + BUF) + nameH, 46);
            // Larghezza: nome centrale + etichette porta E/W ai due bordi; e in
            // più lo spread orizzontale degli ancoraggi N/S con il testo porta.
            const minW = Math.max(textW + 2 * (r.labelW + INSET + BUF),
                                  stack + 2 * EDGE_INSET + r.labelW + BUF, 100);
            nd.widthConstraint  = { minimum: Math.round(minW) };
            nd.heightConstraint = { minimum: Math.round(minH) };
        });

        const options = {
            layout: { improvedLayout: true, randomSeed: 42 },
            physics: sharedMapPhysics(),
            interaction: { hover: hoverInfo, hoverConnectedEdges: hoverInfo, selectConnectedEdges: true, tooltipDelay: 150, dragNodes: true, dragView: true, zoomView: true, multiselect: true },
            nodes: { shadow: { enabled: false } },
            edges: { smooth: { type: 'continuous', roundness: 0.2 }, shadow: { enabled: false } }
        };

        return { nodes, edges, options, bundles, groupsInfo };
    }

    // ponytail: pillole Port-Channel spostabili/ridimensionabili direttamente su
    // canvas. Per ogni pillola si memorizza uno scostamento {dx,dy} e una scala
    // in una mappa persistita in localStorage, indicizzata da un id stabile del
    // Port-Channel (from~to~tag). Interazione più semplice possibile: hit-test in
    // coordinate rete (DOMtoCanvas) sui rettangoli disegnati; TRASCINA il corpo =
    // sposta, trascina la MANIGLIA all'angolo = ridimensiona. Niente dipendenze.
    let pillAdjust = {};
    try { pillAdjust = JSON.parse(localStorage.getItem('minimalPillAdjust') || '{}'); } catch (e) { pillAdjust = {}; }
    let pillHitboxes = [];     // ricostruiti a ogni disegno: {key, x,y,w,h, hx,hy,hr}
    let pillDrag = null;       // {key, mode:'move'|'resize'|'label', startM, orig, cx, cy}
    const pillKey = b => `${b.from}~${b.to}~${b.pcTag || ''}`;
    const pillAdj = key => pillAdjust[key] || { dx: 0, dy: 0, scale: 1 };
    // Scostamento delle ETICHETTE di testo (es. "po1"), indipendente dalla
    // pillola: ogni cartiglio è trascinabile per conto suo e viene persistito.
    let labelAdjust = {};
    try { labelAdjust = JSON.parse(localStorage.getItem('minimalLabelAdjust') || '{}'); } catch (e) { labelAdjust = {}; }
    let labelHitboxes = [];    // ricostruiti a ogni disegno: {key, x,y,w,h}
    const labelAdj = key => labelAdjust[key] || { dx: 0, dy: 0 };
    // ponytail: hit-test per l'assegnazione categoria via click destro sul cavo.
    // Stessa chiave stabile di pillKey; segmenti ricostruiti a ogni disegno.
    let edgeHitSegs = [];      // [{key, segs:[[x1,y1,x2,y2], ...]}]
    function distToSegment(px, py, x1, y1, x2, y2) {
        const dx = x2 - x1, dy = y2 - y1;
        const len2 = dx * dx + dy * dy;
        let t = len2 ? ((px - x1) * dx + (py - y1) * dy) / len2 : 0;
        t = Math.max(0, Math.min(1, t));
        return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
    }
    function hitEdgeAt(m, threshold) {
        threshold = threshold || 6;
        let best = null, bestD = threshold;
        edgeHitSegs.forEach(e => e.segs.forEach(s => {
            const d = distToSegment(m.x, m.y, s[0], s[1], s[2], s[3]);
            if (d < bestD) { bestD = d; best = e.key; }
        }));
        return best;
    }
    let pillInteractionReady = false;
    function initPillInteraction() {
        if (pillInteractionReady) return;
        const container = document.getElementById('networkGraphContainer');
        if (!container) return;
        pillInteractionReady = true;
        // Suggerimento d'uso (tooltip nativo del contenitore).
        container.title = currentLang === 'en'
            ? 'Port-Channel pill: drag to move, drag the corner handle to resize'
            : 'Pillola Port-Channel: trascina per spostare, angolo per ridimensionare';
        // Punto del mouse in coordinate RETE (le stesse dell'overlay).
        const toNet = ev => {
            const cv = container.querySelector('canvas');
            const rect = (cv || container).getBoundingClientRect();
            return networkInstance.DOMtoCanvas({ x: ev.clientX - rect.left, y: ev.clientY - rect.top });
        };
        const hitAt = m => {
            // Le etichette di testo hanno precedenza assoluta (sono piccole e
            // disegnate sopra tutto), poi la maniglia, poi il corpo della pillola;
            // scorro in ordine inverso (le ultime disegnate stanno "sopra").
            for (let i = labelHitboxes.length - 1; i >= 0; i--) {
                const p = labelHitboxes[i];
                if (m.x >= p.x && m.x <= p.x + p.w && m.y >= p.y && m.y <= p.y + p.h) return { p, mode: 'label' };
            }
            for (let i = pillHitboxes.length - 1; i >= 0; i--) {
                const p = pillHitboxes[i];
                if (Math.hypot(m.x - p.hx, m.y - p.hy) <= p.hr + 2) return { p, mode: 'resize' };
            }
            for (let i = pillHitboxes.length - 1; i >= 0; i--) {
                const p = pillHitboxes[i];
                if (m.x >= p.x && m.x <= p.x + p.w && m.y >= p.y && m.y <= p.y + p.h) return { p, mode: 'move' };
            }
            return null;
        };
        // Capture sul contenitore: intercetta PRIMA di vis.js così il trascinamento
        // della pillola non fa panning/selezione della vista. Vis.js (Hammer)
        // ascolta i POINTER event, non solo mousedown: vanno bloccati entrambi,
        // altrimenti trascinando la pillola si muove anche tutta la mappa.
        const beginPillDrag = ev => {
            if (getMapView() !== 'minimal' || !networkInstance) return;
            const hit = hitAt(toNet(ev));
            if (!hit) return;
            ev.preventDefault(); ev.stopPropagation();
            if (pillDrag) return; // già iniziato dall'altro tipo di evento
            const a = hit.mode === 'label' ? labelAdj(hit.p.key) : pillAdj(hit.p.key);
            pillDrag = { key: hit.p.key, mode: hit.mode, startM: toNet(ev),
                         orig: { dx: a.dx, dy: a.dy, scale: a.scale },
                         cx: hit.p.cx, cy: hit.p.cy };
            container.style.cursor = hit.mode === 'resize' ? 'nwse-resize' : 'move';
        };
        container.addEventListener('pointerdown', beginPillDrag, true);
        container.addEventListener('mousedown', beginPillDrag, true);
        container.addEventListener('touchstart', ev => {
            // Blocca anche il touch: Hammer altrimenti avvia il pan della mappa.
            if (pillDrag) { ev.preventDefault(); ev.stopPropagation(); }
        }, true);
        window.addEventListener('mousemove', ev => {
            if (!pillDrag || !networkInstance) return;
            const m = toNet(ev);
            if (pillDrag.mode === 'label') {
                const la = labelAdjust[pillDrag.key] || (labelAdjust[pillDrag.key] = {});
                la.dx = pillDrag.orig.dx + (m.x - pillDrag.startM.x);
                la.dy = pillDrag.orig.dy + (m.y - pillDrag.startM.y);
                networkInstance.redraw();
                return;
            }
            const a = pillAdjust[pillDrag.key] || (pillAdjust[pillDrag.key] = {});
            if (pillDrag.mode === 'move') {
                a.dx = pillDrag.orig.dx + (m.x - pillDrag.startM.x);
                a.dy = pillDrag.orig.dy + (m.y - pillDrag.startM.y);
                a.scale = pillDrag.orig.scale;
            } else {
                // Scala = rapporto tra distanza attuale dal centro e distanza iniziale.
                const d0 = Math.max(Math.hypot(pillDrag.startM.x - pillDrag.cx, pillDrag.startM.y - pillDrag.cy), 6);
                const d1 = Math.hypot(m.x - pillDrag.cx, m.y - pillDrag.cy);
                a.dx = pillDrag.orig.dx; a.dy = pillDrag.orig.dy;
                a.scale = Math.min(4, Math.max(0.5, pillDrag.orig.scale * (d1 / d0)));
            }
            networkInstance.redraw();
        });
        const endDrag = () => {
            if (!pillDrag) return;
            pillDrag = null;
            localStorage.setItem('minimalPillAdjust', JSON.stringify(pillAdjust));
            localStorage.setItem('minimalLabelAdjust', JSON.stringify(labelAdjust));
            if (pillInteractionReady) document.getElementById('networkGraphContainer').style.cursor = '';
        };
        window.addEventListener('mouseup', endDrag);
        window.addEventListener('pointerup', endDrag);
        // Click destro su un cavo: menu per assegnare/rimuovere una categoria
        // personalizzata al collegamento (Task categorie link).
        container.addEventListener('contextmenu', ev => {
            if (getMapView() !== 'minimal' || !networkInstance) return;
            const key = hitEdgeAt(toNet(ev));
            if (!key) return;
            ev.preventDefault();
            showEdgeCatMenu(ev.clientX, ev.clientY, key);
        });
    }

    // ===== Overlay Visio (contenitori Sede + fasci Port-Channel / vPC / peer) =====
    // Contesto già trasformato da vis.js nelle coordinate della rete. Disegna:
    //  1) contenitori tratteggiati per Sede/Gruppo con etichetta;
    //  2) per ogni fascio, un cavo ORTOGONALE (a gradino, no diagonali) per ogni
    //     interfaccia membro, spaziati così da non sovrapporsi nelle pieghe;
    //  3) le etichette di porta sul bordo INTERNO del riquadro, nel punto d'aggancio;
    //  4) una "pillola" traslucida verticale che attraversa i cavi paralleli con il
    //     nome dell'aggregato (es. "Po2 / vPC2"). Rame per i dati, verde per i peer.
    function drawMinimalOverlay(ctx, bundles, groupsInfo) {
        if (!networkInstance) return;
        const S = MINIMAL_MAP_STYLE;
        initPillInteraction();
        pillHitboxes = [];   // ricostruiti sotto per l'hit-test di drag/resize
        labelHitboxes = [];  // ricostruiti sotto per il drag delle etichette
        edgeHitSegs = [];    // ricostruiti sotto per l'hit-test del menu categorie

        // --- 1) Contenitori di raggruppamento per Sede/Gruppo ------------------
        if (Array.isArray(groupsInfo) && groupsInfo.length > 1) {
            ctx.save();
            ctx.setLineDash([8, 5]);
            ctx.lineWidth = 1.2;
            groupsInfo.forEach(gi => {
                let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity, found = 0;
                gi.ids.forEach(id => {
                    let bb; try { bb = networkInstance.getBoundingBox(id); } catch (e) { bb = null; }
                    if (!bb) return;
                    found++;
                    minX = Math.min(minX, bb.left);  minY = Math.min(minY, bb.top);
                    maxX = Math.max(maxX, bb.right); maxY = Math.max(maxY, bb.bottom);
                });
                if (!found) return;
                const pad = 28;
                minX -= pad; minY -= pad; maxX += pad; maxY += pad;
                ctx.strokeStyle = S.edge.group.stroke;
                ctx.fillStyle = S.edge.group.fill;
                ctx.beginPath();
                ctx.rect(minX, minY, maxX - minX, maxY - minY);
                ctx.fill();
                ctx.stroke();
                // Etichetta Sede in alto a sinistra del contenitore.
                ctx.setLineDash([]);
                ctx.font = 'bold 11px Arial, Helvetica, sans-serif';
                ctx.textAlign = 'left';
                ctx.textBaseline = 'bottom';
                ctx.fillStyle = S.edge.group.font;
                ctx.fillText(gi.group, minX + 4, minY - 3);
                ctx.setLineDash([8, 5]);
            });
            ctx.restore();
        }

        if (!Array.isArray(bundles) || !bundles.length) return;

        const spacing = 11;         // distanza tra cavi paralleli / slot di porta
        const EDGE_INSET = 14;      // margine degli ancoraggi dagli angoli del riquadro

        const bbox = id => { try { return networkInstance.getBoundingBox(id); } catch (e) { return null; } };
        // Stile UNIFORME per tipo di collegamento (Fix rappresentazione
        // standardizzata): stesso colore/spessore per ogni Port-Channel, verde
        // per peer-link/keepalive, tinta sobria per i link semplici.
        // ponytail: colore preso dalla tabella tipo→colore (fonte unica), così il
        // color-picker/legenda e il disegno restano sempre allineati.
        // ponytail: una categoria personalizzata assegnata manualmente (click
        // destro sul cavo) vince sempre sullo stile standard per-tipo.
        const styleFor = b => {
            const custom = customStyleForEdge(pillKey(b));
            if (custom) return { color: custom.color, lw: b.emphasize ? 2.4 : 1.8, dash: custom.dash };
            return b.type === 'peer'      ? { color: linkColor('peer'),      lw: b.emphasize ? 2.4 : 1.8, dash: null }
                 : b.type === 'keepalive' ? { color: linkColor('keepalive'), lw: 1.2, dash: [4, 3] }
                 : b.type === 'pc'        ? { color: linkColor('pc'),        lw: b.emphasize ? 2.4 : 1.8, dash: null }
                                          : { color: linkColor('link'),      lw: 1.4, dash: null };
        };

        // --- PASSO 1: ancoraggi per lato -----------------------------------
        // Ogni collegamento occupa 'members.length' slot sul lato del riquadro
        // rivolto verso il peer; gli slot di TUTTI i collegamenti (fasci e
        // porte singole) sono distribuiti lungo il lato ordinati per la
        // coordinata del peer, così nessun cavo o etichetta si sovrappone.
        const sideRegistry = {};   // nodeId -> { E|W|N|S: [entry] }
        const pre = bundles.map((b, bi) => {
            let p1, p2;
            try { p1 = networkInstance.getPosition(b.from); p2 = networkInstance.getPosition(b.to); }
            catch (e) { return null; }
            if (!p1 || !p2) return null;
            const dx = p2.x - p1.x, dy = p2.y - p1.y;
            const horizontal = Math.abs(dx) >= Math.abs(dy);
            const fromSide = horizontal ? (dx >= 0 ? 'E' : 'W') : (dy >= 0 ? 'S' : 'N');
            const toSide   = horizontal ? (dx >= 0 ? 'W' : 'E') : (dy >= 0 ? 'N' : 'S');
            const reg = (id, side, key) => {
                const sides = sideRegistry[id] || (sideRegistry[id] = {});
                const arr = sides[side] || (sides[side] = []);
                const entry = { count: b.members.length, key, slot: 0, step: 0, total: 1 };
                arr.push(entry);
                return entry;
            };
            return { b, bi, horizontal, fromSide, toSide,
                     fromEntry: reg(b.from, fromSide, horizontal ? p2.y : p2.x),
                     toEntry:   reg(b.to,   toSide,   horizontal ? p1.y : p1.x) };
        }).filter(Boolean);

        Object.keys(sideRegistry).forEach(id => {
            const bb = bbox(id); if (!bb) return;
            Object.keys(sideRegistry[id]).forEach(side => {
                const entries = sideRegistry[id][side].sort((a, c) => a.key - c.key);
                const total = entries.reduce((s, e) => s + e.count, 0);
                const sideLen = (side === 'E' || side === 'W') ? (bb.bottom - bb.top) : (bb.right - bb.left);
                const usable = Math.max(sideLen - 2 * EDGE_INSET, 0);
                const step = total > 1 ? Math.min(spacing, usable / (total - 1)) : 0;
                let slot = 0;
                entries.forEach(e => { e.slot = slot; e.step = step; e.total = total; slot += e.count; });
            });
        });

        // Punto di aggancio dello slot i-esimo di una entry sul lato del nodo.
        const anchorPoint = (id, side, entry, i) => {
            const bb = bbox(id);
            const p = networkInstance.getPosition(id);
            const off = ((entry.slot + i) - (entry.total - 1) / 2) * entry.step;
            if (side === 'E') return { x: bb ? bb.right : p.x, y: p.y + off };
            if (side === 'W') return { x: bb ? bb.left : p.x,  y: p.y + off };
            if (side === 'S') return { x: p.x + off, y: bb ? bb.bottom : p.y };
            return { x: p.x + off, y: bb ? bb.top : p.y };
        };

        // --- PASSO 2: geometria delle polilinee ortogonali ------------------
        // Calcolata PRIMA di disegnare, così da poter rilevare gli incroci tra
        // percorsi indipendenti e scavalcarli con un ponticello (Fix bridges).
        const geoms = pre.map(g => {
            const b = g.b;
            const n = b.members.length, half = (n - 1) / 2;
            const members = b.members.map((m, i) => {
                const A = anchorPoint(b.from, g.fromSide, g.fromEntry, i);
                const B = anchorPoint(b.to,   g.toSide,   g.toEntry,   i);
                let pts;
                if (g.horizontal) {
                    const mid = (A.x + B.x) / 2 + (i - half) * spacing;
                    pts = [A, { x: mid, y: A.y }, { x: mid, y: B.y }, B];
                } else {
                    const mid = (A.y + B.y) / 2 + (i - half) * spacing;
                    pts = [A, { x: A.x, y: mid }, { x: B.x, y: mid }, B];
                }
                return { m, A, B, pts };
            });
            return Object.assign({}, g, { members, style: styleFor(b) });
        });

        // Raccolta dei segmenti verticali (per membro) da tutti i fasci: sono gli
        // ostacoli che i tratti orizzontali dovranno scavalcare.
        const verticals = [];
        geoms.forEach(g => {
            if (!g) return;
            g.members.forEach(mm => {
                for (let k = 0; k < mm.pts.length - 1; k++) {
                    const p = mm.pts[k], q = mm.pts[k + 1];
                    if (Math.abs(p.x - q.x) < 0.5 && Math.abs(p.y - q.y) > 0.5) {
                        verticals.push({ x: p.x, ymin: Math.min(p.y, q.y), ymax: Math.max(p.y, q.y), bundle: g.bi });
                    }
                }
            });
        });

        const BR = 5;   // raggio del ponticello (semi-arco)
        // Disegna un tratto orizzontale scavalcando con un arco i segmenti verticali
        // di ALTRI fasci che lo attraversano (i membri dello stesso fascio, paralleli,
        // sono esclusi e non generano ponti).
        const drawHSeg = (x1, y, x2, bundleIdx) => {
            const dir = Math.sign(x2 - x1) || 1;
            const lo = Math.min(x1, x2), hi = Math.max(x1, x2);
            let hops = verticals
                .filter(v => v.bundle !== bundleIdx && v.x > lo + BR && v.x < hi - BR && y > v.ymin + 0.5 && y < v.ymax - 0.5)
                .map(v => v.x);
            hops = [...new Set(hops.map(x => Math.round(x)))].sort((a, b) => dir > 0 ? a - b : b - a);
            ctx.beginPath();
            ctx.moveTo(x1, y);
            hops.forEach(hx => {
                ctx.lineTo(hx - dir * BR, y);
                if (dir > 0) ctx.arc(hx, y, BR, Math.PI, 0, false);
                else         ctx.arc(hx, y, BR, 0, Math.PI, true);
            });
            ctx.lineTo(x2, y);
            ctx.stroke();
        };
        const drawVSeg = (x, y1, y2) => {
            ctx.beginPath(); ctx.moveTo(x, y1); ctx.lineTo(x, y2); ctx.stroke();
        };

        // --- PASSO 3: disegno cavi + etichette ------------------------------
        geoms.forEach(g => {
            const b = g.b, horizontal = g.horizontal, color = g.style.color;
            const sdx = horizontal ? (g.fromSide === 'E' ? 1 : -1) : 0;
            const sdy = horizontal ? 0 : (g.fromSide === 'S' ? 1 : -1);

            ctx.save();
            ctx.strokeStyle = color;
            ctx.lineWidth = g.style.lw;
            ctx.setLineDash(g.style.dash || []);
            ctx.lineJoin = 'round';
            ctx.lineCap = 'butt';
            ctx.font = '9px Arial, Helvetica, sans-serif';
            ctx.textBaseline = 'middle';

            // Etichetta di porta sul bordo INTERNO del riquadro, nel punto d'aggancio.
            // ponytail: sui lati alti/bassi (N/S) gli ancoraggi sono ravvicinati in
            // orizzontale, quindi le etichette centrate si accavallavano in un
            // groviglio illeggibile ("Te1/1d1t21/1"). Le impiliamo verticalmente una
            // per riga (slotIdx), allineate a sinistra, come già avviene sui lati E/W.
            const drawPortLabel = (text, pt, side, slotIdx) => {
                if (!text) return;
                ctx.fillStyle = color;
                if (side === 'E')      { ctx.textAlign = 'right';  ctx.fillText(text, pt.x - 13, pt.y - 5); }
                else if (side === 'W') { ctx.textAlign = 'left';   ctx.fillText(text, pt.x + 13, pt.y - 5); }
                else if (side === 'S') { ctx.textAlign = 'left';   ctx.fillText(text, pt.x + 4, pt.y - 13 - (slotIdx || 0) * 11); }
                else                   { ctx.textAlign = 'left';   ctx.fillText(text, pt.x + 4, pt.y + 13 + (slotIdx || 0) * 11); }
            };

            // ponytail: quadratino di terminazione appena DENTRO il bordo, colore del
            // cavo (stile drawio). ~5px a zoom base: non copre il testo di porta.
            const drawTermSquare = (pt, side) => {
                const s = 5, h = s / 2;
                let x = pt.x, y = pt.y;
                if (side === 'E')      x -= h + 1;
                else if (side === 'W') x += h + 1;
                else if (side === 'S') y -= h + 1;
                else                   y += h + 1;
                ctx.fillStyle = color;
                ctx.fillRect(x - h, y - h, s, s);
            };

            g.members.forEach((mm, i) => {
                // Export Visio attivo: il cavo NON viene rasterizzato come
                // segmenti sciolti ma consegnato come connettore STRUTTURATO
                // (polilinea continua + nodi di aggancio), che il backend
                // trasforma in una forma 1-D incollata ai connection point.
                if (visioConnectorSink) {
                    visioConnectorSink.push({
                        from: b.from, to: b.to,
                        points: mm.pts.map(p => [p.x, p.y]),
                        color: visioColor(color).hex,
                        width: g.style.lw,
                        dash: !!g.style.dash
                    });
                } else {
                    // Disegna i segmenti della polilinea: gli orizzontali scavalcano
                    // con un ponticello i segmenti verticali degli ALTRI percorsi.
                    for (let k = 0; k < mm.pts.length - 1; k++) {
                        const p = mm.pts[k], q = mm.pts[k + 1];
                        if (Math.abs(p.y - q.y) < 0.5) drawHSeg(p.x, p.y, q.x, g.bi);
                        else                           drawVSeg(p.x, p.y, q.y);
                    }
                    drawTermSquare(mm.A, g.fromSide);
                    drawTermSquare(mm.B, g.toSide);
                }
                // Indice di slot globale sul lato (entry.slot + i): garantisce che le
                // etichette N/S di fasci diversi si impilino su righe distinte.
                drawPortLabel(mm.m.local,  mm.A, g.fromSide, g.fromEntry.slot + i);
                drawPortLabel(mm.m.remote, mm.B, g.toSide,   g.toEntry.slot + i);
            });
            // Segmenti del fascio per l'hit-test del menu categorie (click destro).
            edgeHitSegs.push({ key: pillKey(b), segs: g.members.flatMap(mm =>
                mm.pts.slice(0, -1).map((p, k) => [p.x, p.y, mm.pts[k + 1].x, mm.pts[k + 1].y])) });
            ctx.setLineDash([]);

            // Centro del fascio e ampiezza (per pillola/etichette).
            const aC = { x: g.members.reduce((s, m) => s + m.A.x, 0) / g.members.length,
                         y: g.members.reduce((s, m) => s + m.A.y, 0) / g.members.length };
            const bC = { x: g.members.reduce((s, m) => s + m.B.x, 0) / g.members.length,
                         y: g.members.reduce((s, m) => s + m.B.y, 0) / g.members.length };
            const half = (b.members.length - 1) / 2;
            const spread = half * spacing;
            const cx = (aC.x + bC.x) / 2, cy = (aC.y + bC.y) / 2;

            // Cartiglio bianco riutilizzabile per i nomi aggregato. Se 'key' è
            // fornita, il cartiglio è trascinabile: applica lo scostamento
            // dell'utente e registra la propria hitbox per il drag.
            const drawTag = (text, lx, ly, key) => {
                if (key) { const la = labelAdj(key); lx += la.dx || 0; ly += la.dy || 0; }
                ctx.font = 'bold 10px Arial, Helvetica, sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                const tw = ctx.measureText(text).width;
                ctx.fillStyle = '#ffffff';
                ctx.fillRect(lx - tw / 2 - 3, ly - 7, tw + 6, 14);
                ctx.fillStyle = color;
                ctx.fillText(text, lx, ly);
                if (key) labelHitboxes.push({ key, x: lx - tw / 2 - 3, y: ly - 7, w: tw + 6, h: 14 });
            };

            if (b.type === 'keepalive') {
                drawTag(b.label || 'peer-keepalive', cx, cy - 10, pillKey(b) + '~ka');
                ctx.restore();
                return;
            }
            if (b.type === 'link') { ctx.restore(); return; }

            // --- Pillola ovale standard: SEMPRE presente su ogni Port-Channel
            // e peer-link, qualunque sia il numero di membri visibili.
            // ponytail: posizione e dimensione regolabili dall'utente (drag/resize);
            // lo scostamento {dx,dy} e la scala vengono dalla mappa persistita.
            const adj = pillAdj(pillKey(b));
            const sc  = adj.scale || 1;
            const pcx = cx + (adj.dx || 0), pcy = cy + (adj.dy || 0);
            const pillHalfW = 9 * sc;
            const pillHalfSpread = (spread + 12) * sc;
            let px, py, pw, ph;
            if (horizontal) { px = pcx - pillHalfW; py = pcy - pillHalfSpread; pw = pillHalfW * 2; ph = pillHalfSpread * 2; }
            else            { px = pcx - pillHalfSpread; py = pcy - pillHalfW; pw = pillHalfSpread * 2; ph = pillHalfW * 2; }
            const r = Math.min(pillHalfW, 8);
            ctx.beginPath();
            ctx.moveTo(px + r, py);
            ctx.arcTo(px + pw, py, px + pw, py + ph, r);
            ctx.arcTo(px + pw, py + ph, px, py + ph, r);
            ctx.arcTo(px, py + ph, px, py, r);
            ctx.arcTo(px, py, px + pw, py, r);
            ctx.closePath();
            ctx.fillStyle = hexToRgba(color, 0.16);
            ctx.fill();
            ctx.lineWidth = b.emphasize ? 2 : 1.4;
            ctx.strokeStyle = color;
            ctx.stroke();
            // Hitbox per il drag della pillola (niente maniglia visibile: il
            // ridimensionamento resta possibile trascinando l'angolo esterno).
            pillHitboxes.push({ key: pillKey(b), x: px, y: py, w: pw, h: ph,
                                hx: px + pw, hy: py + ph, hr: 6, cx: pcx, cy: pcy });

            if (b.asymmetricPc) {
                // Nomi Port-channel diversi sui due lati (es. Po1 ⇄ Po4): si
                // etichetta ciascun estremo accanto al dispositivo d'origine,
                // indicando la direzione da cui il nome proviene.
                if (horizontal) {
                    drawTag(b.localLabel  || b.localPcTag,  aC.x + sdx * 26, aC.y - spread - 10, pillKey(b) + '~a');
                    drawTag(b.remoteLabel || b.remotePcTag, bC.x - sdx * 26, bC.y - spread - 10, pillKey(b) + '~b');
                } else {
                    drawTag(b.localLabel  || b.localPcTag,  aC.x - spread - 14, aC.y + sdy * 22, pillKey(b) + '~a');
                    drawTag(b.remoteLabel || b.remotePcTag, bC.x - spread - 14, bC.y - sdy * 22, pillKey(b) + '~b');
                }
            } else {
                // ponytail: etichetta (es. "Po1", "Po1 / vPC") accostata alla pillola
                // e spostata LUNGO il cavo verso lo switch a cui il Port-channel
                // appartiene (lo switch 'from'), affiancata alla linea come in drawio.
                const towardX = Math.sign(aC.x - pcx) || 1;
                const towardY = Math.sign(aC.y - pcy) || 1;
                let lx, ly;
                if (horizontal) { lx = pcx + towardX * (pillHalfW + 20); ly = pcy - pillHalfSpread - 9; }
                else            { lx = pcx - pillHalfSpread - 16;        ly = pcy + towardY * (pillHalfW + 16); }
                drawTag(b.label || b.pcTag || 'po', lx, ly, pillKey(b) + '~tag');
            }
            ctx.restore();
        });
    }

    // ===== Pannello Dispositivi & Categorie (classificazione manuale) =====
    let categoriesData = { categories: {}, nodes: [], counts_by_category: {}, counts_by_group: {}, vendors: [], models: {} };

    // Colonne disponibili nella tabella Dispositivi & Categorie. 'fixed' = sempre visibile.
    const CAT_COLUMNS = [
        { key: 'hostname', it: 'Hostname',  en: 'Hostname', fixed: true },
        { key: 'ip',       it: 'IP',        en: 'IP' },
        { key: 'source',   it: 'Origine',   en: 'Source' },
        { key: 'vendor',   it: 'Vendor',    en: 'Vendor' },
        { key: 'model',    it: 'Modello',   en: 'Model' },
        { key: 'version',  it: 'Versione',  en: 'Version' },
        { key: 'vtp',      it: 'VTP',       en: 'VTP' },
        { key: 'ha',       it: 'HA',        en: 'HA' },
        { key: 'category', it: 'Categoria', en: 'Category', fixed: true },
    ];
    function colLabel(c) { return currentLang === 'en' ? c.en : c.it; }
    let catColVis = {};
    try { catColVis = JSON.parse(localStorage.getItem('catColVis') || '{}'); } catch (e) { catColVis = {}; }
    function isColVisible(key) {
        const c = CAT_COLUMNS.find(x => x.key === key);
        if (c && c.fixed) return true;
        return catColVis[key] !== false;
    }
    function attrEsc(s) { return escapeHtml(String(s == null ? '' : s)).replace(/"/g, '&quot;'); }

    async function loadCategoriesData() {
        const res = await apiFetch("/api/device-classification");
        if (!res || !res.ok) return;
        categoriesData = await res.json();
        categoriesData.vendors = categoriesData.vendors || [];
        categoriesData.models = categoriesData.models || {};

        // Filtro sedi
        const gsel = document.getElementById("categoriesGroupSelect");
        if (gsel) {
            const cur = gsel.value;
            const groups = Object.keys(categoriesData.counts_by_group).sort();
            gsel.innerHTML = `<option value="all">${currentLang==='en'?'Filter by Tenant: All':'Filtra per Tenant: Tutti'}</option>` +
                groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join("");
            gsel.value = groups.includes(cur) ? cur : "all";
        }
        // Filtro categorie + datalist di creazione
        const csel = document.getElementById("categoriesCatFilter");
        const dl = document.getElementById("catKeyList");
        const catKeys = Object.keys(categoriesData.categories);
        if (csel) {
            const cur = csel.value;
            csel.innerHTML = `<option value="all">${currentLang==='en'?'All categories':'Tutte le categorie'}</option>` +
                catKeys.map(k => `<option value="${escapeHtml(k)}">${escapeHtml(categoriesData.categories[k].label)}</option>`).join("");
            csel.value = catKeys.includes(cur) ? cur : "all";
        }
        if (dl) dl.innerHTML = catKeys.map(k => `<option value="${escapeHtml(k)}">`).join("");

        renderColumnsMenu();
        renderCategoriesPanel();
        updateSaveBar();
    }

    function renderColumnsMenu() {
        const box = document.getElementById("categoryColumnsList");
        if (!box) return;
        box.innerHTML = CAT_COLUMNS.map(c => `
            <label style="display:flex; align-items:center; gap:8px; font-size:12px; padding:3px 0; cursor:${c.fixed?'default':'pointer'}; color:${c.fixed?'var(--text-muted)':'var(--text)'};">
                <input type="checkbox" ${isColVisible(c.key)?'checked':''} ${c.fixed?'disabled':''} onchange="toggleCatColumn('${c.key}', this.checked)" style="accent-color:var(--primary);">
                ${colLabel(c)}
            </label>`).join("");
    }
    function toggleCatColumn(key, on) {
        catColVis[key] = on;
        localStorage.setItem('catColVis', JSON.stringify(catColVis));
        renderCategoriesPanel();
    }

    function categoryOptions(selected) {
        return Object.keys(categoriesData.categories).map(k =>
            `<option value="${escapeHtml(k)}"${k===selected?' selected':''}>${escapeHtml(categoriesData.categories[k].label)}</option>`
        ).join("");
    }

    function getFilteredCategoryNodes() {
        const groupFilter = document.getElementById("categoriesGroupSelect")?.value || "all";
        const catFilter = document.getElementById("categoriesCatFilter")?.value || "all";
        let nodes = categoriesData.nodes.slice();
        if (groupFilter !== "all") nodes = nodes.filter(n => n.group === groupFilter);
        if (catFilter !== "all") nodes = nodes.filter(n => n.device_type === catFilter);
        return nodes;
    }

    // Modifiche in sospeso non ancora salvate: { node_id: { field: value } }.
    // Le modifiche alla tabella NON vengono salvate in automatico: si applicano
    // solo col pulsante "Salva Modifiche" (admin/operator).
    let pendingEdits = {};

    // Valore effettivo di un attributo: lo staged se presente, altrimenti il nodo.
    function effVal(n, field) {
        const p = pendingEdits[n.id];
        if (p && Object.prototype.hasOwnProperty.call(p, field)) return p[field];
        switch (field) {
            case 'category': return n.device_type;
            default: return n[field];
        }
    }
    function stageEdit(nodeId, field, value) {
        pendingEdits[nodeId] = pendingEdits[nodeId] || {};
        pendingEdits[nodeId][field] = value;
        const row = document.querySelector(`tr[data-node="${nodeId}"]`);
        if (row) row.classList.add('row-dirty');
        updateSaveBar();
    }
    function updateSaveBar() {
        const n = Object.keys(pendingEdits).length;
        const save = document.getElementById('btnSaveCatEdits');
        const disc = document.getElementById('btnDiscardCatEdits');
        [save, disc].forEach(b => { if (b) { b.disabled = !n; b.style.opacity = n ? '1' : '0.5'; } });
        if (save) save.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> ${currentLang==='en'?'Save changes':'Salva Modifiche'}${n?` (${n})`:''}`;
    }

    // Valore testuale di una cella (usato anche per l'export CSV) — usa i valori salvati.
    function catCellValue(key, n) {
        switch (key) {
            case 'hostname': return n.label || '';
            case 'ip':       return n.display_ip || '';
            case 'source':   return n.discovered ? (currentLang==='en'?'discovered':'scoperto') : (currentLang==='en'?'managed':'gestito');
            case 'vendor':   return n.vendor && n.vendor !== 'discovered' ? n.vendor : '';
            case 'model':    return n.model || '';
            case 'version':  return n.version || '';
            case 'vtp':      return [n.vtp_domain, n.vtp_mode].filter(Boolean).join(' / ');
            case 'ha':       return n.ha_group || '';
            case 'category': return deviceTypeLabel(n.device_type) + (n.subcategory ? ' / ' + n.subcategory : '');
            default: return '';
        }
    }

    function renderCategoriesPanel() {
        const cats = categoriesData.categories;
        const canWrite = (currentRole === 'admin' || currentRole === 'operator');
        const cols = CAT_COLUMNS.filter(c => isColVisible(c.key));

        // Conteggi per categoria RELATIVI alla sede selezionata (non al totale).
        const groupFilterForCounts = document.getElementById("categoriesGroupSelect")?.value || "all";
        const counts = {};
        categoriesData.nodes
            .filter(n => groupFilterForCounts === "all" || n.group === groupFilterForCounts)
            .forEach(n => { counts[n.device_type] = (counts[n.device_type] || 0) + 1; });

        // Riquadri di conteggio per categoria
        const cardBox = document.getElementById("categoryCountCards");
        if (cardBox) {
            cardBox.innerHTML = Object.keys(cats).map(k => {
                const c = cats[k];
                const color = deviceTypeMeta(k).color;
                const n = counts[k] || 0;
                const delBtn = (!c.builtin && canWrite)
                    ? `<i class="fa-solid fa-trash" title="${currentLang==='en'?'Delete category':'Elimina categoria'}" style="position:absolute; top:8px; right:8px; font-size:11px; color:var(--text-muted); cursor:pointer;" onclick="deleteCategory('${escapeHtml(k)}')"></i>` : '';
                const subChips = c.subcategories.length
                    ? `<div style="display:flex; flex-wrap:wrap; gap:4px; margin-top:6px;">${c.subcategories.map(s => `<span style="display:inline-flex; align-items:center; gap:4px; font-size:10px; color:var(--text-muted); background:var(--surface); border:1px solid var(--border); border-radius:5px; padding:1px 6px;">${escapeHtml(s)}${canWrite?`<i class="fa-solid fa-xmark" title="${currentLang==='en'?'Remove subcategory':'Rimuovi sottocategoria'}" onclick="deleteSubcategory('${escapeHtml(k)}','${escapeHtml(s)}')" style="cursor:pointer; color:var(--danger);"></i>`:''}</span>`).join('')}</div>` : '';
                return `<div style="position:relative; background:var(--surface-2); border:1px solid var(--border); border-left:4px solid ${color}; border-radius:10px; padding:14px;">
                    ${delBtn}
                    <div style="font-size:26px; font-weight:900; color:${color};">${n}</div>
                    <div style="font-size:12px; font-weight:700; color:var(--text); margin-top:2px;">${escapeHtml(c.label)}</div>
                    ${subChips}
                </div>`;
            }).join("");
        }

        const nodes = getFilteredCategoryNodes();
        const byGroup = {};
        nodes.forEach(n => { (byGroup[n.group] = byGroup[n.group] || []).push(n); });

        const listBox = document.getElementById("categoriesDeviceList");
        if (!listBox) return;
        if (!nodes.length) { listBox.innerHTML = `<p style="color:var(--text-muted); font-size:13px;">${currentLang==='en'?'No devices.':'Nessun dispositivo.'}</p>`; return; }

        // Datalist condivise per vendor e modelli (per editing inline).
        const vendorDL = `<datalist id="catVendorDL">${(categoriesData.vendors||[]).map(v=>`<option value="${attrEsc(v)}">`).join('')}</datalist>`;
        const modelDLs = Object.keys(categoriesData.models||{}).map(vk =>
            `<datalist id="catModelDL_${attrEsc(vk)}">${(categoriesData.models[vk]||[]).map(m=>`<option value="${attrEsc(m)}">`).join('')}</datalist>`
        ).join('');

        const cellHtml = (col, n) => {
            const meta = deviceTypeMeta(effVal(n, 'category'));
            const td = (inner, extra='') => `<td style="padding:6px 8px; ${extra}">${inner}</td>`;
            switch (col.key) {
                case 'hostname': {
                    const conflictIcon = (canWrite && n.name_options && n.name_options.length > 1)
                        ? ` <i class="fa-solid fa-triangle-exclamation" title="${currentLang==='en'?'CDP/LLDP name conflict — click to resolve':'Conflitto nome CDP/LLDP — clicca per risolvere'}" onclick="openConflictModal('${escapeHtml(n.id)}')" style="cursor:pointer; color:var(--warning); font-size:11px;"></i>` : '';
                    const dot = `<span style="display:inline-block; width:9px; height:9px; border-radius:2px; background:${meta.color}; margin-right:6px;"></span>`;
                    // Rinomina inline: modifica il nome mostrato (stage 'name', salvato col pulsante).
                    if (canWrite) {
                        const p = pendingEdits[n.id];
                        const curName = (p && Object.prototype.hasOwnProperty.call(p, 'name')) ? p.name : (n.label || '');
                        return td(`${dot}<input value="${attrEsc(curName)}" onchange="stageEdit('${escapeHtml(n.id)}','name',this.value.trim())" title="${currentLang==='en'?'Rename device':'Rinomina dispositivo'}" placeholder="${currentLang==='en'?'name':'nome'}" style="width:150px; padding:4px 6px; border-radius:6px; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:12px;">${conflictIcon}`);
                    }
                    return td(`${dot}${escapeHtml(n.label)} ${n.is_manual?'<i class="fa-solid fa-user-pen" title="'+(currentLang==='en'?'Manually classified':'Classificato manualmente')+'" style="font-size:10px; color:var(--warning);"></i>':''}${conflictIcon}`);
                }
                case 'ip':
                    return td(escapeHtml(n.display_ip || '—'), 'font-family:var(--font-code); font-size:12px; color:var(--text-muted);');
                case 'source': {
                    const badge = n.discovered
                        ? `<span style="font-size:10px; color:#a3a3a3; border:1px solid #a3a3a3; border-radius:4px; padding:1px 5px;">${currentLang==='en'?'DISCOVERED':'SCOPERTO'}</span>`
                        : `<span style="font-size:10px; color:var(--primary); border:1px solid var(--primary); border-radius:4px; padding:1px 5px;">${currentLang==='en'?'MANAGED':'GESTITO'}</span>`;
                    // Promozione di un dispositivo scoperto a gestito (operator/admin).
                    const promote = (n.discovered && canWrite && n.display_ip)
                        ? ` <button onclick="promoteDevice('${escapeHtml(n.id)}')" title="${currentLang==='en'?'Add to managed (triage)':'Aggiungi ai gestiti (triage)'}" style="font-size:10px; cursor:pointer; border:1px solid var(--success); color:var(--success); background:transparent; border-radius:4px; padding:1px 5px;"><i class="fa-solid fa-arrow-up-from-bracket"></i> ${currentLang==='en'?'Promote':'Promuovi'}</button>` : '';
                    return td(badge + promote);
                }
                case 'vendor': {
                    const v = (function(){ const e = effVal(n,'vendor'); return (e && e !== 'discovered') ? e : ''; })();
                    return td(canWrite
                        ? `<input list="catVendorDL" value="${attrEsc(v)}" onchange="stageEdit('${escapeHtml(n.id)}','vendor',this.value.trim())" placeholder="—" style="width:110px; padding:4px 6px; border-radius:6px; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:12px;">`
                        : `<span style="font-size:12px; color:var(--text-muted);">${escapeHtml(v||'—')}</span>`);
                }
                case 'model': {
                    const vk = String(effVal(n,'vendor')||'').toLowerCase();
                    return td(canWrite
                        ? `<input list="catModelDL_${attrEsc(vk)}" value="${attrEsc(effVal(n,'model')||'')}" onchange="stageModel('${escapeHtml(n.id)}', this.value.trim())" placeholder="—" style="width:140px; padding:4px 6px; border-radius:6px; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:12px;">`
                        : `<span style="font-size:12px; color:var(--text-muted);">${escapeHtml(effVal(n,'model')||'—')}</span>`);
                }
                case 'version':
                    return td(escapeHtml(n.version||'-'), 'font-size:12px; color:var(--text-muted);');
                case 'vtp': {
                    const v = [n.vtp_domain, n.vtp_mode].filter(Boolean).join(' · ');
                    return td(v ? `<span style="font-size:12px; color:${vtpDomainColor(n.vtp_domain)};">${escapeHtml(v)}</span>` : '<span style="color:var(--text-muted);">—</span>');
                }
                case 'ha': {
                    const hg = effVal(n,'ha_group') || '';
                    const badge = hg ? `<span title="HA" style="font-size:9px; font-weight:900; color:#ff8c42; border:1px solid #ff8c42; border-radius:4px; padding:1px 4px; margin-right:4px;">HA</span>` : '';
                    return td(canWrite
                        ? `${badge}<input value="${attrEsc(hg)}" onchange="stageEdit('${escapeHtml(n.id)}','ha_group',this.value.trim())" placeholder="${currentLang==='en'?'HA group':'gruppo HA'}" style="width:110px; padding:4px 6px; border-radius:6px; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:12px;">`
                        : (hg ? `${badge}<span style="font-size:12px; color:#ff8c42;">${escapeHtml(hg)}</span>` : '<span style="color:var(--text-muted);">—</span>'));
                }
                case 'category': {
                    const curCat = effVal(n, 'category');
                    const curSub = effVal(n, 'subcategory') || '';
                    const subs = (cats[curCat]?.subcategories) || [];
                    // Il menù sottocategoria viene reso SOLO se la categoria ne ha:
                    // così, rimuovendo l'ultima sottocategoria, non resta spazio vuoto.
                    const subSel = (canWrite && subs.length)
                        ? `<select class="subcat-sel" onchange="stageEdit('${escapeHtml(n.id)}','subcategory',this.value)" style="padding:4px 6px; border-radius:6px; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:12px;">
                            <option value="">${currentLang==='en'?'— subcat —':'— sottocat —'}</option>
                            ${subs.map(s => `<option value="${escapeHtml(s)}"${s===curSub?' selected':''}>${escapeHtml(s)}</option>`).join('')}
                        </select>` : '';
                    const ctrl = canWrite
                        ? `<select onchange="stageCategory('${escapeHtml(n.id)}', this.value)" style="padding:4px 6px; border-radius:6px; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:12px;">
                            ${categoryOptions(curCat)}
                        </select>${subSel}`
                        : `<span style="font-size:12px; color:${meta.color}; font-weight:700;">${escapeHtml(deviceTypeLabel(curCat))}</span>${curSub?` <span style="font-size:11px; color:var(--text-muted);">/ ${escapeHtml(curSub)}</span>`:''}`;
                    return td(`<div style="display:flex; gap:6px; align-items:center;">${ctrl}</div>`);
                }
                default: return td('');
            }
        };

        const headHtml = cols.map(c => `<th style="padding:8px;">${colLabel(c)}</th>`).join('');
        listBox.innerHTML = vendorDL + modelDLs + Object.keys(byGroup).sort().map(g => {
            const rows = byGroup[g].map(n => `<tr data-node="${attrEsc(n.id)}" class="${pendingEdits[n.id]?'row-dirty':''}">${cols.map(c => cellHtml(c, n)).join('')}</tr>`).join("");
            return `<div style="margin-bottom:18px;">
                <h4 style="font-size:14px; margin-bottom:8px;"><i class="fa-solid fa-location-dot" style="color:var(--primary);"></i> ${escapeHtml(g)} <span style="color:var(--text-muted); font-weight:400;">(${byGroup[g].length})</span></h4>
                <div class="table-wrap" style="margin-top:0;">
                <table>
                    <thead><tr>${headHtml}</tr></thead>
                    <tbody>${rows}</tbody>
                </table>
                </div>
            </div>`;
        }).join("");
    }

    function exportCategoriesCsv() {
        const cols = CAT_COLUMNS.filter(c => isColVisible(c.key));
        const nodes = getFilteredCategoryNodes();
        const esc = (v) => {
            v = String(v == null ? '' : v);
            return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
        };
        const lines = [['Group', ...cols.map(colLabel)].map(esc).join(',')];
        nodes.forEach(n => {
            lines.push([n.group, ...cols.map(c => catCellValue(c.key, n))].map(esc).join(','));
        });
        const blob = new Blob(["﻿" + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'sentinelnet-devices-categories.csv';
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
    }

    // Cambio categoria: azzera la sottocategoria (cambiano le opzioni) e ridisegna
    // così il menù sottocategoria si aggiorna alla nuova categoria.
    function stageCategory(nodeId, category) {
        pendingEdits[nodeId] = pendingEdits[nodeId] || {};
        pendingEdits[nodeId].category = category;
        pendingEdits[nodeId].subcategory = "";
        updateSaveBar();
        renderCategoriesPanel();
    }
    // Modello: registra anche il vendor effettivo, così alla salvataggio il modello
    // viene catalogato sotto il vendor corretto.
    function stageModel(nodeId, model) {
        const n = categoriesData.nodes.find(x => x.id === nodeId);
        pendingEdits[nodeId] = pendingEdits[nodeId] || {};
        pendingEdits[nodeId].model = model;
        const v = effVal(n, 'vendor');
        if (v && v !== 'discovered') pendingEdits[nodeId].vendor = v;
        const row = document.querySelector(`tr[data-node="${nodeId}"]`);
        if (row) row.classList.add('row-dirty');
        updateSaveBar();
    }

    async function saveCategoryEdits() {
        const ids = Object.keys(pendingEdits);
        if (!ids.length) return;
        let failed = 0;
        for (const id of ids) {
            const res = await apiFetch("/api/device-categories/assign", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(Object.assign({ node_id: id }, pendingEdits[id]))
            });
            if (!(res && res.ok)) failed++;
        }
        pendingEdits = {};
        if (failed) alert((currentLang==='en'?'Some changes failed: ':'Alcune modifiche non salvate: ') + failed);
        await loadCategoriesData();
        updateSaveBar();
    }
    function discardCategoryEdits() {
        pendingEdits = {};
        renderCategoriesPanel();
        updateSaveBar();
    }

    async function promoteDevice(nodeId) {
        const n = categoriesData.nodes.find(x => x.id === nodeId);
        if (!n || !n.display_ip) { alert(currentLang==='en'?'No announced IP available.':'Nessun IP annunciato disponibile.'); return; }
        const vendor = (effVal(n,'vendor') && effVal(n,'vendor') !== 'discovered') ? effVal(n,'vendor') : 'cisco';
        const msg = currentLang==='en'
            ? `Promote "${n.label}" (${n.display_ip}) to managed in tenant "${n.group}"? You can set credentials afterwards in Inventory.`
            : `Promuovere "${n.label}" (${n.display_ip}) a gestito nel tenant "${n.group}"? Le credenziali si impostano dopo, in Inventario.`;
        if (!confirm(msg)) return;
        const res = await apiFetch("/api/promote-device", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                node_id: nodeId, ip: n.display_ip, vendor, group: n.group,
                // Eredita ciò che è già stato scoperto via CDP/LLDP, incluso il
                // nome eventualmente rinominato (staged o salvato).
                model: effVal(n,'model') || '',
                version: n.version || '',
                device_type: n.device_type || '',
                hostname: (effVal(n,'name') || n.label || '')
            })
        });
        if (res && res.ok) {
            delete pendingEdits[nodeId];
            await loadCategoriesData();
            // Aggiorna la cache inventario così il nuovo gestito appare nel triage.
            try {
                const dres = await apiFetch('/api/local-devices');
                if (dres && dres.ok) {
                    const d = await dres.json();
                    globalDevices = d.devices; globalGroups = d.groups; globalVersions = d.detected_versions;
                }
            } catch (e) {}
        } else {
            const e = res ? await res.json().catch(()=>({})) : {};
            alert(e.detail || (currentLang==='en'?'Promotion failed.':'Promozione non riuscita.'));
        }
    }

    // ===== Risoluzione conflitti CDP/LLDP (stesso device, nomi diversi) =====
    function closeConflictModal() {
        const m = document.getElementById('conflictModal');
        if (m) m.remove();
    }
    function openConflictModal(nodeId) {
        const n = categoriesData.nodes.find(x => x.id === nodeId);
        if (!n || !n.name_options || n.name_options.length < 2) return;
        const cur = n.label;
        const rows = n.name_options.map(o => `
            <label style="display:flex; gap:10px; align-items:center; padding:9px 10px; border:1px solid var(--border); border-radius:8px; margin-bottom:6px; cursor:pointer;">
                <input type="radio" name="confName" value="${attrEsc(o.name)}" data-ver="${attrEsc(o.version||'')}" ${o.name===cur?'checked':''} style="accent-color:var(--primary);">
                <span style="font-weight:700;">${escapeHtml(o.name)}</span>
                <span style="margin-left:auto; font-family:var(--font-code); font-size:12px; color:var(--text-muted);">${o.version?escapeHtml(o.version):'—'}</span>
            </label>`).join('');
        const ov = document.createElement('div');
        ov.id = 'conflictModal';
        ov.style.cssText = 'position:fixed; inset:0; z-index:10050; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; backdrop-filter:blur(4px);';
        ov.innerHTML = `
            <div style="background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:22px; width:min(480px,92vw); box-shadow:0 20px 60px rgba(0,0,0,0.6);">
                <h3 style="font-size:16px; margin-bottom:6px;"><i class="fa-solid fa-code-branch" style="color:var(--warning);"></i> ${currentLang==='en'?'Resolve CDP/LLDP conflict':'Risolvi conflitto CDP/LLDP'}</h3>
                <p style="font-size:13px; color:var(--text-muted); margin-bottom:14px;">${currentLang==='en'?'The same device was discovered with different names. Choose the name and version to keep.':'Lo stesso dispositivo è stato rilevato con nomi diversi. Scegli nome e versione da mantenere.'}</p>
                ${rows}
                <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                    <button onclick="closeConflictModal()" class="btn btn-secondary btn-small" style="width:auto; margin:0;">${currentLang==='en'?'Cancel':'Annulla'}</button>
                    <button onclick="confirmConflict('${escapeHtml(nodeId)}')" class="btn btn-primary btn-small" style="width:auto; margin:0; background:var(--cta); color:var(--cta-text);">${currentLang==='en'?'Apply':'Applica'}</button>
                </div>
            </div>`;
        ov.addEventListener('click', e => { if (e.target === ov) closeConflictModal(); });
        document.body.appendChild(ov);
    }
    async function confirmConflict(nodeId) {
        const sel = document.querySelector('#conflictModal input[name="confName"]:checked');
        if (!sel) { closeConflictModal(); return; }
        const name = sel.value;
        const version = sel.getAttribute('data-ver') || '';
        closeConflictModal();
        const res = await apiFetch("/api/device-categories/assign", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ node_id: nodeId, name, version })
        });
        if (res && res.ok) loadCategoriesData();
        else alert(currentLang==='en'?'Failed to resolve conflict.':'Risoluzione conflitto non riuscita.');
    }

    async function createCategory() {
        const key = document.getElementById("newCatKey").value.trim();
        const label = document.getElementById("newCatLabel").value.trim();
        const sub = document.getElementById("newSubcat").value.trim();
        if (!key) { alert(currentLang==='en'?'Category key required.':'Chiave categoria obbligatoria.'); return; }
        const res = await apiFetch("/api/device-categories", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key, label, subcategory: sub })
        });
        if (res && res.ok) {
            document.getElementById("newCatKey").value = "";
            document.getElementById("newCatLabel").value = "";
            document.getElementById("newSubcat").value = "";
            loadCategoriesData();
        } else {
            alert(currentLang==='en'?'Failed to create category.':'Creazione categoria non riuscita.');
        }
    }

    async function deleteCategory(key) {
        if (!confirm(currentLang==='en'?`Delete category "${key}"?`:`Eliminare la categoria "${key}"?`)) return;
        const res = await apiFetch("/api/device-categories/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key })
        });
        if (res && res.ok) loadCategoriesData();
        else alert(currentLang==='en'?'Cannot delete this category.':'Categoria non eliminabile.');
    }

    async function deleteSubcategory(key, sub) {
        if (!confirm(currentLang==='en'?`Remove subcategory "${sub}"?`:`Rimuovere la sottocategoria "${sub}"?`)) return;
        const res = await apiFetch("/api/device-categories/delete-subcategory", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key, subcategory: sub })
        });
        if (res && res.ok) loadCategoriesData();
        else alert(currentLang==='en'?'Cannot remove subcategory.':'Impossibile rimuovere la sottocategoria.');
    }

    function updateTopologyMapNodeStatus(ip, newStatus) {
        if (networkInstance && networkInstance.body && networkInstance.body.data && networkInstance.body.data.nodes) {
            const nodesDataSet = networkInstance.body.data.nodes;
            const node = nodesDataSet.get(ip);
            if (node) {
                node.nodeDataVal.status = newStatus;

                const scan = globalVersions[ip] || { version: currentLang === 'en' ? "Not detected" : "Non rilevato", status: newStatus };

                node.image = createNodeSvg(node.labelVal, ip, node.deviceTypeVal, newStatus, node.isBoundaryVal, node.vendorVal, node.vtpVal);
                node.title = createNodeTooltip(node.nodeDataVal, scan, node.vendorVal);

                nodesDataSet.update(node);
            }
        }
    }

    // Cattura la mappa corrente su un canvas ad alta risoluzione (fit su tutta
    // la topologia, sfondo opaco) e lo passa a cb; poi ripristina la vista.
    // Usata sia dall'export PNG che da quello PDF.
    function captureMapCanvas(cb) {
        if (!networkInstance) {
            alert(i18n[currentLang].alertNoTopology);
            return;
        }

        const container = document.getElementById("networkGraphContainer");
        // Salva dimensioni e vista correnti per ripristinarle dopo l'export
        const prevW     = container.style.width;
        const prevH     = container.style.height;
        const prevPos   = networkInstance.getViewPosition();
        const prevScale = networkInstance.getScale();

        // Esporta su un canvas molto più grande della finestra: più pixel = più
        // risoluzione. Con fit() l'inquadratura comprende TUTTI i dispositivi.
        const EXPORT_W = 3200, EXPORT_H = 2000;
        container.style.width  = EXPORT_W + "px";
        container.style.height = EXPORT_H + "px";
        networkInstance.setSize(EXPORT_W + "px", EXPORT_H + "px");
        networkInstance.fit({ animation: false });   // racchiude l'intera topologia
        networkInstance.redraw();

        const restore = () => {
            container.style.width  = prevW;
            container.style.height = prevH;
            networkInstance.setSize(prevW || "100%", prevH || "600px");
            networkInstance.redraw();
            networkInstance.moveTo({ position: prevPos, scale: prevScale, animation: false });
        };

        // Due frame per essere certi che il ridisegno alla nuova dimensione sia completo
        requestAnimationFrame(() => requestAnimationFrame(() => {
            try {
                const src = networkInstance.canvas.frame.canvas;
                // Componi su uno sfondo opaco così il PNG non risulta trasparente
                const out = document.createElement("canvas");
                out.width  = src.width;
                out.height = src.height;
                const ctx = out.getContext("2d");
                // La nuova mappa minimalista ha sfondo bianco, la classica scuro.
                ctx.fillStyle = getMapView() === 'minimal' ? "#ffffff" : "#150f23";
                ctx.fillRect(0, 0, out.width, out.height);
                ctx.drawImage(src, 0, 0);
                cb(out);
            } catch (e) {
                console.error("Export mappa fallito:", e);
            } finally {
                restore();
            }
        }));
    }

    function downloadTopology() {
        captureMapCanvas(out => {
            const link = document.createElement("a");
            link.download = "sentinelnet-topology-" + new Date().toISOString().slice(0,10) + ".png";
            link.href = out.toDataURL("image/png");
            link.click();
        });
    }

    // Esporta la mappa come PDF a pagina singola, tutto lato client: il canvas
    // viene compresso in JPEG e incapsulato a mano in un PDF minimale (XObject
    // /DCTDecode). Nessuna libreria, nessuna chiamata al backend.
    function jpegToPdf(jpeg, w, h) {
        const pw = (w * 72 / 96).toFixed(2), ph = (h * 72 / 96).toFixed(2);
        const enc = new TextEncoder();
        const chunks = [], offsets = [];
        let len = 0;
        const push = b => { chunks.push(b); len += b.length; };
        const pushStr = s => push(enc.encode(s));
        const obj = (n, body) => { offsets[n] = len; pushStr(`${n} 0 obj\n${body}\nendobj\n`); };
        pushStr('%PDF-1.4\n');
        obj(1, '<< /Type /Catalog /Pages 2 0 R >>');
        obj(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
        obj(3, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pw} ${ph}] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>`);
        offsets[4] = len;
        pushStr(`4 0 obj\n<< /Type /XObject /Subtype /Image /Width ${w} /Height ${h} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${jpeg.length} >>\nstream\n`);
        push(jpeg);
        pushStr('\nendstream\nendobj\n');
        const content = `q ${pw} 0 0 ${ph} 0 0 cm /Im0 Do Q`;
        obj(5, `<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
        const xrefPos = len;
        let xref = 'xref\n0 6\n0000000000 65535 f \n';
        for (let i = 1; i <= 5; i++) xref += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
        pushStr(xref + `trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF`);
        const bytes = new Uint8Array(len);
        let o = 0;
        chunks.forEach(c => { bytes.set(c, o); o += c.length; });
        return bytes;
    }

    function exportPdfMap() {
        captureMapCanvas(out => {
            const b64 = out.toDataURL("image/jpeg", 0.92).split(',')[1];
            const bin = atob(b64);
            const jpeg = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) jpeg[i] = bin.charCodeAt(i);
            const pdf = jpegToPdf(jpeg, out.width, out.height);
            const link = document.createElement("a");
            link.download = "sentinelnet-topology-" + new Date().toISOString().slice(0,10) + ".pdf";
            link.href = URL.createObjectURL(new Blob([pdf], { type: "application/pdf" }));
            link.click();
            URL.revokeObjectURL(link.href);
        });
    }

    // Esporta la mappa interattiva corrente come file Visio (.vsdx) nativo ed
    // editabile. Riusa posizioni/dati già presenti nell'istanza vis.js: nessuna
    // nuova chiamata all'API della topologia, solo un POST al backend che
    // costruisce il pacchetto OPC.
    // Dati dell'ultima mappa minimalista renderizzata (bundles + gruppi):
    // servono all'export Visio per riprodurre fedelmente l'overlay canvas.
    let minimalOverlayData = null;
    // Quando valorizzato (solo durante l'export Visio), drawMinimalOverlay vi
    // deposita i cavi come connettori strutturati invece di rasterizzarli.
    let visioConnectorSink = null;

    // Normalizza un colore canvas ('#rrggbb' o 'rgba(r,g,b,a)') in {hex, alpha}.
    function visioColor(c) {
        c = String(c || '#000000');
        let m = /^rgba?\((\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*([\d.]+))?\)$/.exec(c);
        if (m) {
            const hex = '#' + [m[1], m[2], m[3]].map(v => (+v).toString(16).padStart(2, '0')).join('');
            return { hex: hex.toUpperCase(), alpha: m[4] !== undefined ? +m[4] : 1 };
        }
        m = /^#([0-9a-f]{6})$/i.exec(c);
        return { hex: m ? ('#' + m[1]).toUpperCase() : '#000000', alpha: 1 };
    }

    // Contesto canvas "registratore": espone la stessa API 2D usata da
    // drawMinimalOverlay ma, invece di disegnare, accumula primitive
    // (polilinee, poligoni, rettangoli, testi) in coordinate rete. L'export
    // Visio riesegue l'overlay su questo contesto e spedisce le primitive al
    // backend: il .vsdx contiene ESATTAMENTE ciò che si vede sulla mappa.
    function makeRecordingCtx(prims) {
        const meas = document.createElement('canvas').getContext('2d');
        const stack = [];
        let subpaths = [], cur = null;
        const ctx = {
            strokeStyle: '#000', fillStyle: '#000', lineWidth: 1,
            font: '10px Arial', textAlign: 'left', textBaseline: 'alphabetic',
            lineJoin: 'round', lineCap: 'butt', _dash: [],
            save() { stack.push({ s: this.strokeStyle, f: this.fillStyle, w: this.lineWidth, fo: this.font, a: this.textAlign, b: this.textBaseline, d: this._dash }); },
            restore() { const p = stack.pop(); if (p) { this.strokeStyle = p.s; this.fillStyle = p.f; this.lineWidth = p.w; this.font = p.fo; this.textAlign = p.a; this.textBaseline = p.b; this._dash = p.d; } },
            setLineDash(d) { this._dash = d || []; },
            beginPath() { subpaths = []; cur = null; },
            moveTo(x, y) { cur = [[x, y]]; subpaths.push(cur); },
            lineTo(x, y) { if (!cur) this.moveTo(x, y); else cur.push([x, y]); },
            arc(x, y, r, a0, a1, ccw) {
                // Approssimazione poligonale (8 segmenti): sufficiente per i
                // ponticelli di scavalcamento e gli angoli arrotondati.
                const steps = 8;
                let d = a1 - a0;
                if (ccw && d > 0) d -= 2 * Math.PI;
                if (!ccw && d < 0) d += 2 * Math.PI;
                for (let i = 0; i <= steps; i++) {
                    const a = a0 + d * i / steps;
                    this.lineTo(x + r * Math.cos(a), y + r * Math.sin(a));
                }
            },
            arcTo(x1, y1) { this.lineTo(x1, y1); },  // angolo vivo: fedeltà sufficiente
            rect(x, y, w, h) { subpaths.push([[x, y], [x + w, y], [x + w, y + h], [x, y + h], [x, y]]); cur = null; },
            closePath() { if (cur && cur.length > 1) cur.push([...cur[0]]); },
            stroke() {
                const c = visioColor(this.strokeStyle);
                subpaths.forEach(sp => { if (sp.length > 1) prims.lines.push({ points: sp.map(p => [p[0], p[1]]), color: c.hex, alpha: c.alpha, width: this.lineWidth, dash: this._dash && this._dash.length ? true : false }); });
            },
            fill() {
                const c = visioColor(this.fillStyle);
                subpaths.forEach(sp => { if (sp.length > 2) prims.polys.push({ points: sp.map(p => [p[0], p[1]]), fill: c.hex, alpha: c.alpha }); });
            },
            fillRect(x, y, w, h) {
                const c = visioColor(this.fillStyle);
                prims.rects.push({ x, y, w, h, fill: c.hex, alpha: c.alpha });
            },
            measureText(t) { meas.font = this.font; return meas.measureText(t || ''); },
            fillText(text, x, y) {
                if (!text) return;
                meas.font = this.font;
                const w = meas.measureText(text).width;
                const size = parseFloat(/(\d+(?:\.\d+)?)px/.exec(this.font)?.[1] || '10');
                const bold = /bold/.test(this.font);
                // Converte allineamento/baseline in un punto CENTRALE del testo.
                let cx = x, cy = y;
                if (this.textAlign === 'left') cx = x + w / 2;
                else if (this.textAlign === 'right') cx = x - w / 2;
                if (this.textBaseline === 'bottom') cy = y - size / 2;
                else if (this.textBaseline === 'top') cy = y + size / 2;
                const c = visioColor(this.fillStyle);
                prims.texts.push({ x: cx, y: cy, text, color: c.hex, size, bold, w });
            }
        };
        return ctx;
    }

    async function exportVisioMap() {
        if (!networkInstance) {
            alert(i18n[currentLang].alertNoTopology);
            return;
        }
        const positions = networkInstance.getPositions();
        const nodesDs = networkInstance.body.data.nodes;
        const edgesDs = networkInstance.body.data.edges;

        const stripTags = s => String(s || '').replace(/<\/?[bi]>/g, '');
        const nodes = nodesDs.get().map(n => {
            const p = positions[n.id] || { x: 0, y: 0 };
            const raw = n.nodeDataVal || {};
            let bb = null;
            try { bb = networkInstance.getBoundingBox(n.id); } catch (e) { bb = null; }
            const out = {
                id:    n.id,
                label: stripTags(n.labelVal || raw.label || String(n.id)),
                model: raw.model || raw.platform || '',
                ip:    n.id,
                x: p.x, y: p.y
            };
            if (bb) { out.w = bb.right - bb.left; out.h = bb.bottom - bb.top; }
            if (n.color && typeof n.color === 'object') {
                if (typeof n.color.background === 'string') out.fill = visioColor(n.color.background).hex;
                if (typeof n.color.border === 'string') out.border = visioColor(n.color.border).hex;
            }
            // Nella mappa minimalista la label multiriga (nome/modello/mgmt) è
            // già dentro n.label: si esporta così com'è, senza tag HTML.
            if (getMapView() === 'minimal' && typeof n.label === 'string') {
                out.label = stripTags(n.label);
                out.model = ''; out.ip = '';
            }
            return out;
        });

        let edges = [];
        let primitives = null;
        let connectors = null;
        if (getMapView() === 'minimal' && minimalOverlayData) {
            // Riesegue l'overlay sul contesto registratore: etichette di porta,
            // pillole Po/vPC e contenitori Sede finiscono nelle primitive; i
            // cavi vengono invece raccolti come connettori strutturati, che il
            // backend incolla ai connection point dei riquadri dispositivo.
            primitives = { lines: [], polys: [], rects: [], texts: [] };
            connectors = [];
            visioConnectorSink = connectors;
            try {
                drawMinimalOverlay(makeRecordingCtx(primitives), minimalOverlayData.bundles, minimalOverlayData.groupsInfo);
            } finally {
                visioConnectorSink = null;
            }
        } else {
            edges = edgesDs.get().map(e => {
                const ex = e.exportVal || {};
                return {
                    source: e.from, target: e.to,
                    label: ex.isPortChannel ? (ex.pcName || 'Port-Channel') : '',
                    color: ex.color || '#6A5FC1'
                };
            });
        }

        const res = await apiFetch('/api/map/export/vsdx', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nodes, edges, primitives, connectors })
        });
        if (!res || !res.ok) {
            alert(i18n[currentLang].alertVisioExportError);
            return;
        }
        const blob = await res.blob();
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'sentinelnet-map.vsdx';
        link.click();
        URL.revokeObjectURL(link.href);
    }

    async function resetTopology() {
        if (!confirm(i18n[currentLang].confirmReset)) return;

        const res = await apiFetch('/api/topology/reset', { method: 'POST' });
        if (!res || !res.ok) {
            alert(i18n[currentLang].alertTopologyResetError);
            return;
        }

        // 1. Distruggi istanza vis.js e pulisci il container
        if (networkInstance) {
            networkInstance.destroy();
            networkInstance = null;
        }
        const graphContainer = document.getElementById('networkGraphContainer');
        if (graphContainer) graphContainer.innerHTML = '';

        // 2. Ricarica inventario (aggiorna stati LED nella tabella)
        await appInit();

        // 3. Forza reload di ENTRAMBE le viste indipendentemente dalla tab attiva
        await loadTopology();
        await loadInteractiveMap();

        const data = await res.json();
        console.info(`[Reset] Eliminati ${data.deleted} file cache.`);
    }
