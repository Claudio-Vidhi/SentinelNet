// Resa (chiara/scura) PRIMA del primo paint, come per la sidebar: applicarla
// dopo farebbe lampeggiare il quadro nella polarità sbagliata. Nessun valore
// salvato = si segue il sistema operativo (prefers-color-scheme).
// Estratto dal blocco inline di dashboard.html per la CSP senza 'unsafe-inline'.
try {
    var t = localStorage.getItem('sentinelnet_theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
} catch (e) { /* localStorage non disponibile: si segue il sistema */ }
