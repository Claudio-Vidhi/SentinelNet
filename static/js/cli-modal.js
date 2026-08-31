// --- TERMINAL CLI INTERACTIVE (WebSockets + Xterm.js) ---
// Estratto dal blocco inline di templates/dashboard.html (CSP senza
// 'unsafe-inline'). xterm viene iniettato lazy da loadAssetOnce (core.js).

let termInstance = null;
let wsSocket = null;

async function openCliModal(ip) {
    // xterm non sta piu' in <head>: si inietta al primo avvio della CLI
    // (loader in static/js/core.js). ~280KB in meno al primo paint.
    await Promise.all([
        loadAssetOnce('/static/vendor/xterm/xterm.css'),
        loadAssetOnce('/static/vendor/xterm/xterm.js'),
    ]);
    document.getElementById("cliTargetIp").innerText = ip;
    openModal('cliModalOverlay', closeCliModal);

    const container = document.getElementById("terminal-container");
    container.innerHTML = "";

    termInstance = new Terminal({
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
    termInstance.registerLinkProvider({
        provideLinks: (y, cb) => {
            const line = termInstance.buffer.active.getLine(y - 1);
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
    termInstance.open(container);
    termInstance.write(tr('cliInitializingTerminalSessionR'));

    // Fetch a single-use OTP before opening the WebSocket
    const otpRes = await apiFetch("/api/ws-token", { method: "POST" });
    if (!otpRes || !otpRes.ok) {
        termInstance.write(tr('cliErrorUnableToObtain'));
        return;
    }
    const { ws_token } = await otpRes.json();

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/ws-terminal/${ip}`;

    wsSocket = new WebSocket(wsUrl);

    wsSocket.onopen = () => {
        // The OTP travels as the first frame, never in the URL: a query string
        // ends up in the server access log and the browser history. onopen runs
        // before any keystroke can reach onData, so it is always frame #1.
        wsSocket.send(ws_token);
        termInstance.write(tr('cliWebsocketConnectionEstablishedR'));
    };
    wsSocket.onmessage = (event) => {
        termInstance.write(event.data);
    };
    wsSocket.onclose = (event) => {
        const noReason = tr('cliNoReasonProvided');
        termInstance.write(`\r\n[${tr('cliTerminalConnectionClosed')}: ${event.reason || noReason}]\r\n`);
    };
    wsSocket.onerror = () => {
        termInstance.write(tr('cliRNWebsocketError'));
    };
    termInstance.onData((data) => {
        if (wsSocket && wsSocket.readyState === WebSocket.OPEN) {
            wsSocket.send(data);
        }
    });
}

function closeCliModal() {
    closeModal('cliModalOverlay');

    // Rilascio pulito delle risorse per evitare memory leak e connessioni orfane
    if (wsSocket) {
        try {
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
document.getElementById('cliModalOverlay')?.addEventListener('click', (e) => {
    if (e.target.id === 'cliModalOverlay') {
        closeCliModal();
    }
});

