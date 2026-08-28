// Ripristina lo stato della sidebar PRIMA del primo paint: applicare la classe
// più tardi (a DOMContentLoaded) farebbe vedere la sidebar espansa che si
// richiude. Qui il valore iniziale è già 72px, quindi la transizione non parte.
// NB: questo script ha uno scope separato e non vede SIDEBAR_COLLAPSED_KEY,
// quindi la chiave è ripetuta come letterale: se la si rinomina va cambiata
// anche qui (TestSidebarRail fissa entrambe le occorrenze).
// Estratto dal blocco inline di dashboard.html per la CSP senza 'unsafe-inline'.
try {
    if (localStorage.getItem('sidebarCollapsed') === '1') {
        document.body.classList.add('sidebar-collapsed');
    }
} catch (e) { /* localStorage non disponibile: si resta espansi */ }
