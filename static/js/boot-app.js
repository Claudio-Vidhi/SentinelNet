// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// Boot della dashboard: ultimo script del markup, gira dopo che tutti i
// moduli (eager) sono caricati. Estratto dal blocco inline di
// templates/dashboard.html (CSP senza 'unsafe-inline').
window.onload = () => {
    appInit();
};
