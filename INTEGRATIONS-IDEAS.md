# Integrazioni Server (Linux / Windows) — Proposte

Idee ordinate per rapporto valore/sforzo. Nessuna implementata ancora.

## Alto valore, sforzo basso

1. **Inventario server come device di rete**
   - Linux: SSH (già presente in core_engine) → hostname, OS, kernel, interfacce, IP, uptime, pacchetti critici.
   - Windows: WinRM (pywinrm) → stesse info via PowerShell remoto.
   - I server appaiono in inventario e in mappa come nodi endpoint, correlati alla porta switch via MAC history (già raccolta).

2. **Correlazione MAC → server**
   - Match automatico MAC dei server con `mac_history`: la mappa mostra "questo server è su SW-X Gi1/0/12". Zero nuovo collector, solo join.

3. **Syslog receiver centrale**
   - SentinelNet ascolta syslog UDP/514: switch + server Linux (rsyslog) + Windows (agent NXLog o forwarding nativo) inviano log. Ricerca/filtri in UI, alert su pattern (link down, login fail).

## Valore medio

4. **Health check servizi**
   - Ping/TCP check porte (SSH 22, RDP 3389, HTTP/S, DB) su server censiti; stato verde/rosso in dashboard e mappa. Riusa network_scanner.

5. **Vulnerabilità server via EUVD**
   - Già esiste lookup EUVD per vendor di rete (inventory_manager.resolve_euvd_term): estendere a OS server (versione da inventario SSH/WinRM).

6. **Backup config → anche server**
   - Come backup-config per switch: dump di file critici (/etc, export registry/GPO minimal) schedulato.

## Più impegnative (fase 2)

7. **Agent remoto unificato** — lo stesso agent dei site remoti (feature VPN in roadmap) raccoglie anche dati server locali: un solo deploy per site.
8. **Integrazione AD/LDAP** — login SentinelNet con credenziali di dominio; lista computer da AD come sorgente inventario.
9. **SNMP verso server** — Linux (net-snmp) e Windows (servizio SNMP) per metriche CPU/RAM/disk in dashboard.

## Consiglio

Partire da 1+2 (inventario SSH/WinRM + correlazione MAC): riusano quasi tutto il codice esistente e rendono la mappa subito più utile. Poi 3 (syslog) e 4 (health check).
