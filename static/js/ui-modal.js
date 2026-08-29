// Gestore unico delle finestre modali.
//
// Prima ogni tab apriva la sua con `style.display = 'flex'` e la chiudeva con
// 'none': 35 overlay, nessun role="dialog", nessun aria-modal, nessuna
// trappola del focus e nessun Esc. Con la tastiera il focus restava dietro il
// velo, sull'interfaccia che la modale copre — e per chi usa uno screen reader
// la finestra non esisteva proprio (obiettivo dichiarato: WCAG 2.1 AA).
//
// L'aspetto non cambia: il markup e il CSS restano quelli, cambia solo chi
// accende e spegne il display. Due marcature convivono nel template
// (.modal-overlay con display dal CSS, .modal-backdrop con display inline) e
// entrambe si aprono in flex, quindi il gestore non deve distinguerle.

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]),' +
    ' select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Stack: una modale puo' aprirne un'altra (es. export -> conferma). Esc e il
// ripristino del focus riguardano sempre e solo quella in cima.
const _modalStack = [];

function _focusable(el) {
    return Array.from(el.querySelectorAll(FOCUSABLE))
        .filter(n => n.offsetParent !== null || n === document.activeElement);
}

function _onModalKeydown(e) {
    const top = _modalStack[_modalStack.length - 1];
    if (!top) return;
    if (e.key === 'Escape') {
        // Il terminale CLI si marca data-esc-close="off": dentro una sessione
        // SSH Esc appartiene al programma remoto (vi, i menu), non alla
        // finestra che lo contiene.
        if (top.el.dataset.escClose === 'off') return;
        e.preventDefault();
        _dismiss(top);
        return;
    }
    if (e.key !== 'Tab') return;
    // Trappola: il Tab non deve poter uscire dalla finestra, altrimenti il
    // focus finisce sui controlli coperti dal velo.
    const items = _focusable(top.el);
    if (!items.length) { e.preventDefault(); return; }
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
        e.preventDefault(); last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault(); first.focus();
    }
}

// Chiusura richiesta dall'utente (Esc o velo), non dal codice della tab.
function _dismiss(entry) {
    if (entry.onClose) entry.onClose();
    else closeModal(entry.el);
}


function _dialogSemantics(el) {
    // Il nodo con role="dialog" e' la finestra, non il velo: il velo e' solo
    // lo sfondo oscurato.
    const dialog = el.querySelector('.modal') || el;
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    if (!dialog.hasAttribute('aria-label') && !dialog.hasAttribute('aria-labelledby')) {
        const heading = dialog.querySelector('.modal-header h3, h3, h4');
        if (heading) {
            if (!heading.id) heading.id = (el.id || 'modal') + 'Title';
            dialog.setAttribute('aria-labelledby', heading.id);
        }
    }
    return dialog;
}

// Apre la modale. `id` e' l'id del contenitore nel template (velo o backdrop).
//
// `onClose` serve alle finestre che alla chiusura fanno altro oltre a sparire
// (il terminale CLI chiude il WebSocket, la scansione subnet aggiorna il suo
// widget): Esc e il click sul velo passano da li', non dal solo nascondimento,
// altrimenti la finestra si chiude lasciando la risorsa aperta.
function openModal(id, onClose) {
    const el = typeof id === 'string' ? document.getElementById(id) : id;
    if (!el) {
        // Un id sbagliato qui e' un bottone morto: va detto, non ingoiato.
        console.error('openModal: nessun elemento con id', id);
        return null;
    }
    if (_modalStack.some(m => m.el === el)) return el;
    const dialog = _dialogSemantics(el);
    el.style.display = 'flex';
    _modalStack.push({ el, opener: document.activeElement, onClose });
    if (_modalStack.length === 1) document.addEventListener('keydown', _onModalKeydown, true);
    const items = _focusable(dialog);
    (items[0] || dialog).focus({ preventScroll: true });
    return el;
}

// Chiude la modale e riporta il focus sul controllo che l'aveva aperta.
function closeModal(id) {
    const el = typeof id === 'string' ? document.getElementById(id) : id;
    if (!el) return;
    el.style.display = 'none';
    const i = _modalStack.findIndex(m => m.el === el);
    if (i === -1) return;
    const [entry] = _modalStack.splice(i, 1);
    if (!_modalStack.length) document.removeEventListener('keydown', _onModalKeydown, true);
    if (entry.opener && document.contains(entry.opener)) {
        entry.opener.focus({ preventScroll: true });
    }
}

function isModalOpen(id) {
    const el = typeof id === 'string' ? document.getElementById(id) : id;
    return !!el && _modalStack.some(m => m.el === el);
}

// Click sul velo = chiusura, ma solo se il click nasce sul velo stesso: un
// drag che finisce fuori dalla finestra non deve chiuderla.
document.addEventListener('mousedown', (e) => {
    const top = _modalStack[_modalStack.length - 1];
    if (top && e.target === top.el) _dismiss(top);
});
