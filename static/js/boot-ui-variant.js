// Variante UI prima del primo paint (blocco head). Estratto dal blocco
// inline di dashboard.html per la CSP senza 'unsafe-inline'.
(function() {
    try {
        var v = localStorage.getItem('sentinelnet_ui_variant');
        if (v && v !== 'default' && ['design-1', 'design-2', 'design-3'].indexOf(v) !== -1) {
            document.documentElement.setAttribute('data-ui-variant', v);
            var l = document.createElement('link');
            l.id = 'theme-variant-stylesheet';
            l.rel = 'stylesheet';
            l.href = '/static/css/themes/' + v + '.css';
            document.head.appendChild(l);
        }
    } catch (e) {}
})();
