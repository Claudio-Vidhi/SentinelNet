// Resa (chiara/scura) PRIMA del primo paint, come per la sidebar: applicarla
// dopo farebbe lampeggiare il quadro nella polarità sbagliata. Nessun valore
// salvato = si segue il sistema operativo (prefers-color-scheme).
// Estratto dal blocco inline di dashboard.html per la CSP senza 'unsafe-inline'.
try {
    // 'saved' e non 't': gli script classici condividono un solo scope e t()
    // e' la funzione di traduzione di i18n.js.
    var saved = localStorage.getItem('sentinelnet_theme');
    if (saved === 'light' || saved === 'dark') document.documentElement.setAttribute('data-theme', saved);
} catch (e) { /* localStorage non disponibile: si segue il sistema */ }
