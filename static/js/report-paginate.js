// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// Audit report pagination and preview buttons. A constant file: the server
// appends it verbatim under a nonce to the report it prints, and the client
// inlines the same text into the preview. Per-report values come from data-*
// attributes on <html>, never from template interpolation.

// Impagina misurando: una scheda entra nella pagina finche' il piede resta
// dentro il box di padding. Nessuna stima di altezza, quindi ne' pagine mezze
// vuote ne' schede tagliate dall'overflow.
function paginateReport() {
    var container = document.querySelector('.report-pages-container');
    if (!container) return;
    var pageTpl = container.querySelector('[data-tpl="page"]');
    var noteTpl = container.querySelector('[data-tpl="note"]');
    if (!pageTpl) return;
    container.removeChild(pageTpl);
    if (noteTpl) container.removeChild(noteTpl);
    pageTpl.classList.remove('pdf-tpl');
    pageTpl.removeAttribute('data-tpl');
    if (noteTpl) {
        noteTpl.classList.remove('pdf-tpl');
        noteTpl.removeAttribute('data-tpl');
    }

    function overflows(page) {
        var foot = page.querySelector('.pdf-page-footer');
        var pad = parseFloat(getComputedStyle(page).paddingBottom) || 0;
        return foot.getBoundingClientRect().bottom
             > page.getBoundingClientRect().bottom - pad + 0.5;
    }

    function addPage() {
        var p = /** @type {HTMLElement} */ (pageTpl.cloneNode(true));
        container.appendChild(p);
        return p;
    }

    var page = container.querySelector('.pdf-page');
    var list = page.querySelector('.findings-list');
    var cards = Array.prototype.slice.call(list.querySelectorAll('.finding-card'));
    cards.forEach(function(c) { list.removeChild(c); });

    // Una pagina cresciuta non va piu' in overflow: senza questo, tutte le
    // schede successive le finirebbero dentro.
    var startNewPage = false;

    for (var i = 0; i < cards.length; i++) {
        if (startNewPage) {
            page = addPage();
            list = page.querySelector('.findings-list');
            startNewPage = false;
        }
        list.appendChild(cards[i]);
        if (!overflows(page)) continue;
        if (list.querySelectorAll('.finding-card').length > 1) {
            list.removeChild(cards[i]);
            page = addPage();
            list = page.querySelector('.findings-list');
            list.appendChild(cards[i]);
        }
        // Le evidenze sono una riga per policy: non hanno un tetto, quindi una
        // scheda puo' superare l'altezza di una pagina. Su una pagina di
        // altezza fissa «overflow: hidden» la taglierebbe in silenzio, e un
        // report di conformita' che perde evidenze senza dirlo e' peggio di un
        // report con una pagina piu' lunga delle altre.
        if (overflows(page)) {
            page.classList.add('pdf-page-tall');
            startNewPage = true;
        }
    }

    if (noteTpl) {
        page.insertBefore(noteTpl, page.querySelector('.pdf-page-footer'));
        if (overflows(page)) {
            page.removeChild(noteTpl);
            page = addPage();
            page.insertBefore(noteTpl, page.querySelector('.pdf-page-footer'));
        }
    }

    var pages = container.querySelectorAll('.pdf-page');
    for (var j = 0; j < pages.length; j++) {
        pages[j].id = 'pdf-page-' + (j + 1);
        var num = pages[j].querySelector('.page-num');
        if (num) num.textContent = document.documentElement.dataset.pageLabel + ' ' + (j + 1) + ' / ' + pages.length;
    }
}

window.addEventListener('DOMContentLoaded', function() {
    if (window.self === window.top) {
        var bar = document.querySelector('.report-actions-bar');
        if (bar) bar.style.display = 'flex';
    }
    // I font monospace cambiano l'ingombro delle evidenze: misurare prima che
    // siano pronti sposterebbe i tagli di pagina.
    if (document.fonts && document.fonts.ready) {
        document.fonts.ready.then(paginateReport);
    } else {
        paginateReport();
    }
});

// Il PDF lo stampa il server con lo stesso motore che disegna questa pagina.
// html2canvas ridisegnava il documento in una tela sola e la affettava a passo
// fisso: bastava una scheda piu' alta di una pagina perche' ogni foglio
// successivo cadesse a un terzo di pagina dal taglio giusto.
function downloadPdf() {
    if (window.parent && typeof window.parent.downloadModalPdf === 'function') {
        return window.parent.downloadModalPdf();
    }
    window.print();
}

function downloadDocx() {
    if (window.parent && typeof window.parent.downloadModalDocx === 'function') {
        window.parent.downloadModalDocx();
    } else {
        alert('Esportazione DOCX disponibile dal pannello principale.');
    }
}

function downloadHtml() {
    var clone = /** @type {HTMLElement} */ (document.documentElement.cloneNode(true));
    var noPrints = clone.querySelectorAll('.no-print');
    noPrints.forEach(function(el) { el.remove(); });
    var blob = new Blob(['<!doctype html>\n' + clone.outerHTML], { type: 'text/html;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = document.documentElement.dataset.filename + '.html';
    a.click();
}
