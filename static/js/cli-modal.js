// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// --- TERMINAL CLI INTERACTIVE (WebSockets + Xterm.js) ---
// Estratto dal blocco inline di templates/dashboard.html (CSP senza
// 'unsafe-inline'). xterm viene iniettato lazy da loadAssetOnce (core.js).

let termInstance = null;
let wsSocket = null;

async function openCliModal(ip) {
    // One session at a time. Opening a second terminal used to leave the first
    // WebSocket alive, and its handlers wrote into whatever termInstance was
    // current: two devices' output interleaved in one window.
    if (wsSocket || termInstance) closeCliModal();

    // xterm non sta piu' in <head>: si inietta al primo avvio della CLI
    // (loader in static/js/core.js). ~280KB in meno al primo paint.
    await Promise.all([
        loadAssetOnce('/static/vendor/xterm/xterm.css'),
        loadAssetOnce('/static/vendor/xterm/xterm.js'),
    ]);
    document.getElementById("cliTargetIp").innerText = ip;
    // Dismissing from the backdrop minimizes instead of killing the SSH
    // session: a stray click outside the window must not drop the work.
    openModal('cliModalOverlay', minimizeCliModal);

    const container = document.getElementById("terminal-container");
    container.innerHTML = "";

    const term = new Terminal({
        cursorBlink: true,
        theme: {
            background: cssVar('--surface-2', '#181e23'),
            foreground: cssVar('--text', '#e8ebe6'),
            cursor: cssVar('--lamp-up', '#56c07a'),
            selection: cssVar('--surface-3', '#2a333a')
        },
        fontFamily: "'Azeret Mono', Menlo, monospace",
        fontSize: 14,
        rows: 24,
        cols: 80
    });
    termInstance = term;
    term.registerLinkProvider({
        provideLinks: (y, cb) => {
            const line = term.buffer.active.getLine(y - 1);
            if (!line) { cb([]); return; }
            const text = line.translateToString(true);
            const rx = /(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}/g;
            const links = [];
            let m;
            while ((m = rx.exec(text)) !== null) {
                links.push({
                    range: { start: { x: m.index + 1, y }, end: { x: m.index + m[0].length, y } },
                    text: m[0],
                    activate: (e, t) => macLocate(t)
                });
            }
            cb(links);
        }
    });
    term.open(container);
    term.write(tr('cliInitializingTerminalSessionR'));

    // Fetch a single-use OTP before opening the WebSocket
    const otpRes = await apiFetch("/api/ws-token", { method: "POST" });
    // Closed (or replaced) while waiting for the token.
    if (termInstance !== term) return;
    if (!otpRes || !otpRes.ok) {
        term.write(tr('cliErrorUnableToObtain'));
        return;
    }
    const { ws_token } = await otpRes.json();

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/ws-terminal/${ip}`;

    // Handlers bind this session's socket and terminal, never the globals.
    const socket = new WebSocket(wsUrl);
    wsSocket = socket;

    socket.onopen = () => {
        // The OTP travels as the first frame, never in the URL: a query string
        // ends up in the server access log and the browser history. onopen runs
        // before any keystroke can reach onData, so it is always frame #1.
        socket.send(ws_token);
        term.write(tr('cliWebsocketConnectionEstablishedR'));
    };
    socket.onmessage = (event) => {
        term.write(event.data);
    };
    socket.onclose = (event) => {
        const noReason = tr('cliNoReasonProvided');
        term.write(`\r\n[${tr('cliTerminalConnectionClosed')}: ${event.reason || noReason}]\r\n`);
    };
    socket.onerror = () => {
        term.write(tr('cliRNWebsocketError'));
    };
    term.onData((data) => {
        if (socket.readyState === WebSocket.OPEN) {
            socket.send(data);
        }
    });
}

// Hide the window, keep the session: the dock in the corner brings it back.
function minimizeCliModal() {
    if (!termInstance) return;
    closeModal('cliModalOverlay');
    const dockIp = document.getElementById('cliDockIp');
    if (dockIp) dockIp.textContent = document.getElementById('cliTargetIp')?.innerText || '';
    const dock = document.getElementById('cliDock');
    if (dock) dock.hidden = false;
}

function restoreCliModal() {
    const dock = document.getElementById('cliDock');
    if (dock) dock.hidden = true;
    openModal('cliModalOverlay', minimizeCliModal);
    termInstance?.focus();
}

function closeCliModal() {
    closeModal('cliModalOverlay');
    const dock = document.getElementById('cliDock');
    if (dock) dock.hidden = true;

    // Rilascio pulito delle risorse per evitare memory leak e connessioni orfane
    if (wsSocket) {
        try {
            // Its close event would write into the terminal disposed below.
            wsSocket.onclose = null;
            wsSocket.onmessage = null;
            wsSocket.close();
        } catch (e) {
            console.error("Errore durante la chiusura del WebSocket:", e);
        }
        wsSocket = null;
    }

    if (termInstance) {
        try {
            termInstance.dispose();
        } catch (e) {
            console.error("Errore durante il dispose di Xterm.js:", e);
        }
        termInstance = null;
    }
}

document.getElementById('btnCloseCliModal')?.addEventListener('click', closeCliModal);
document.getElementById('btnMinimizeCliModal')?.addEventListener('click', minimizeCliModal);
document.getElementById('btnRestoreCliModal')?.addEventListener('click', restoreCliModal);
document.getElementById('btnDockCloseCli')?.addEventListener('click', closeCliModal);
