# Idee di espansione OT (ICS / SCADA) per SentinelNet

Raccolta di funzionalità per rendere **SentinelNet** adatto anche a contesti **Operational Technology (OT)** e **IT/OT convergence**, facendo leva sull'architettura esistente (multi-vendor, SNMP/syslog, probe remoti, blueprint/segmentazione, status report con mapping NIS2/IEC 62443).

---

## 1. Discovery passiva e "OT Safe Mode"

In ambiente OT le scansioni attive aggressive (SYN sweep, SSH/SNMP brute probe) possono bloccare PLC o RTU legacy.

- **Preset `OT Safe Mode` per tenant** (`services/tenant_telemetry.py`)
  - Disabilita scansioni ICMP/SSH/attive su un tenant o sito mantenendo attivo solo l'ascolto passivo (syslog, trap SNMP, import manuale/CSV, eventuale SPAN/TAP).
- **Fingerprinting passivo MAC/OUI + traffico SPAN/NetFlow/IPFIX** (`collectors/mac_collector.py`, `observability/ingesters/`)
  - Database OUI per vendor industriali (Siemens, Rockwell/Allen-Bradley, Schneider Electric, Beckhoff, Omron, Moxa, Hirschmann, Phoenix Contact, Wago, Fanuc, ABB). <!-- check-private-data: ok (public vendor list) -->
  - Rilevamento passivo di protocolli OT da mirror/flow (Modbus TCP, S7comm, EtherNet/IP, OPC-UA, PROFINET, BACnet, IEC 60870-5-104, DNP3) senza inviare pacchetti ai PLC.
- **Probe read-only opt-in** (`services/probe_agent.py`)
  - Interrogazioni sicure solo-lettura e rate-limited (es. EtherNet/IP `ListIdentity`, Modbus FC 43/14 *Read Device Identification*, OPC-UA `GetEndpoints`, BACnet `Who-Is`) per estrarre modello, firmware e seriale senza mai scrivere registri o coil.

---

## 2. Driver networking industriale & protocolli di ring

Le reti di fabbrica usano switch e firewall rugged non presenti nei profili IT standard.

- **Nuovi driver vendor** (backup, drift, interfacce, `collectors/iface_counters_cli.py`)
  - **Siemens SCALANCE** (X / XC / XR / W)
  - **Hirschmann (Belden)** (HiOS / Classic)
  - **Moxa** (serie EDS / EDR)
  - **Westermo**, **Phoenix Contact**, **Cisco IE** (estensioni/OID industriali)
- **Monitoraggio Ring / Ridondanza**
  - Raccolta stato e trap SNMP per **MRP** (*Media Redundancy Protocol*), **DLR** (*Device Level Ring*), **PRP/HSR** e **RSTP**.
  - Allarme immediato su apertura anello, perdita di ridondanza o cambio di *Ring Manager*.

---

## 3. Modello Purdue & Zone/Conduit (IEC 62443)

- **Attributo `Purdue Level` su device e subnet** (`services/inventory_manager.py`, `services/segment_manager.py`)
  - Livelli: `L0` (Campo/Sensori), `L1` (PLC/RTU), `L2` (SCADA/HMI), `L3` (Site Operations), `L3.5` (DMZ IT/OT), `L4` (Enterprise).
- **Vista Topologia Purdue** (Vis.js)
  - Affiancare alla vista schema/gerarchia switch una vista a fasce Purdue con evidenziazione di **Zone & Conduit**.
- **Controllo violazioni IT/OT** (`services/blueprint_checks.py`, `services/firewall_traffic.py`)
  - Allarme se traffico da `L1`/`L2` raggiunge `L4` o Internet saltando la DMZ `L3.5`, o se un PLC comunica verso IP esterni non autorizzati.
- **Rogue Device Detection su VLAN OT**
  - Le reti OT sono statiche: allarme critico immediato quando compare un nuovo MAC su una porta o VLAN di produzione.

---

## 4. Vulnerability Intelligence & Air-Gap

- **Feed CISA ICS Advisories + CISA KEV** (`services/cve_intel.py`, `services/nvd.py`)
  - Affiancare al feed NIST NVD gli advisory ICS specifici per firmware PLC, HMI, drive e switch industriali.
- **Modalità Air-Gapped / Offline**
  - Export su macchina connessa e import su istanza SentinelNet isolata di pacchetti firmati con database NVD/ICS-CERT aggiornato.
- **Finestre di manutenzione e criticità processo**
  - Metadato sull'asset per distinguere apparati patchabili a caldo da apparati aggiornabili solo durante fermo impianto pianificato (riduce rumore operativo nei report).

---

## 5. Backup Vault per artefatti OT & Compliance IEC 62443

- **Config / Project Vault** (`core/backup_store.py`)
  - Archivio versionato con verifica SHA-256 per file di progetto non-CLI associati all'asset (es. progetti TIA Portal `.zap*`, Studio 5000 `.acd`, file SCL/ICD IEC 61850, backup HMI).
- **Espansione `services/status_report/` (IEC 62443 & NIS2)**
  - Controlli automatici aggiuntivi:
    - Presenza di protocolli insicuri attivi (Telnet, HTTP non cifrato, SNMPv1/v2c, Modbus/S7 in chiaro su tratte non segregate).
    - Porte fisiche inutilizzate su switch di campo lasciate `admin up`.
    - Verifica segregazione/jump-host per accesso remoto fornitori e teleassistenza.
