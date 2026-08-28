// Variante UI prima del primo paint (blocco body). Estratto dal blocco
// inline di dashboard.html per la CSP senza 'unsafe-inline'.
try {
    var v = localStorage.getItem('sentinelnet_ui_variant');
    if (v && v !== 'default') {
        document.documentElement.setAttribute('data-ui-variant', v);
        var link = document.createElement('link');
        link.id = 'theme-variant-stylesheet';
        link.rel = 'stylesheet';
        link.href = '/static/css/themes/' + v + '.css';
        document.head.appendChild(link);
    }
} catch (e) { }
