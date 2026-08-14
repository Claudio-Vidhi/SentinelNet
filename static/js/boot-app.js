// Boot della dashboard: ultimo script del markup, gira dopo che tutti i
// moduli (eager) sono caricati. Estratto dal blocco inline di
// templates/dashboard.html (CSP senza 'unsafe-inline').
window.onload = () => {
    appInit();
};
