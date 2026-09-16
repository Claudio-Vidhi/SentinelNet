# Third-Party Licenses & Notices

SentinelNet includes or depends on open source software components. This document provides notice and licensing information for bundled dependencies and static assets.

---

## 1. Bundled Static Assets & Frontend Libraries

### Vis Network
- **Source**: https://github.com/visjs/vis-network
- **License**: Apache-2.0 / MIT
- **Copyright**: (c) 2014-2019 Almende B.V., (c) 2019-2024 visjs community

### Xterm.js
- **Source**: https://github.com/xtermjs/xterm.js
- **License**: MIT
- **Copyright**: (c) 2017-2024 Microsoft Corporation

### FontAwesome Free
- **Source**: https://fontawesome.com
- **License**:
  - Icons: Creative Commons Attribution 4.0 International (CC BY 4.0)
  - Fonts: SIL Open Font License 1.1 (OFL-1.1)
  - Code: MIT License
- **Copyright**: (c) Fonticons, Inc.

### Azeret Mono Font
- **Source**: https://github.com/displaay/Azeret
- **License**: SIL Open Font License, Version 1.1 (OFL-1.1)
- **Copyright**: (c) 2021 The Azeret Project Authors

### Saira Condensed Font
- **Source**: https://github.com/Omnibus-Type/Saira
- **License**: SIL Open Font License, Version 1.1 (OFL-1.1)
- **Copyright**: (c) 2018 The Saira Project Authors

---

## 2. Windows Installer

### WinSW (Windows Service Wrapper)

- Version: 2.12.0 (`WinSW.NET461.exe`)
- License: MIT
- Source: https://github.com/winsw/winsw

Shipped inside `SentinelNet-Setup-<version>.exe` as `SentinelNet-service.exe`,
and only installed when the "run as a Windows service" task is selected. It is
not committed to this repository: `scripts/build_installer.ps1` downloads the
pinned version at build time and verifies its SHA-256 before packaging.

A PyInstaller one-file executable is not a Windows service (it never reports to
the Service Control Manager, which would kill it), so a wrapper is required.

## 3. Core Python Runtime Dependencies

| Package | License | Description |
| --- | --- | --- |
| **FastAPI** | MIT | Web framework & API router |
| **Uvicorn** | BSD-3-Clause | ASGI web server |
| **Pydantic** | MIT | Data validation & settings |
| **Cryptography** | Apache-2.0 / BSD-3-Clause | Cryptographic primitives & vault |
| **Bcrypt** | Apache-2.0 | Password hashing |
| **PyJWT** | MIT | JSON Web Token encoding/decoding |
| **Netmiko** | MIT | Multi-vendor network device SSH abstraction |
| **Paramiko** | LGPL-2.1 | SSH2 protocol library |
| **PySNMP** | BSD-2-Clause | SNMP v1/v2c/v3 engine |
| **WebSockets** | BSD-3-Clause | WebSocket protocol implementation |
| **Requests** | Apache-2.0 | HTTP client library |

---

## 4. Main License

SentinelNet source code is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE) from version 0.39.0 on;
versions up to 0.38.0 were released under the Apache License 2.0.

Every component listed above is under a license that permits inclusion in an
AGPL-3.0 work: MIT, BSD-2-Clause, BSD-3-Clause and Apache-2.0 are one-way
compatible with it, and Paramiko's LGPL-2.1-or-later converts to GPL-3.0, which
AGPL-3.0 section 13 accepts. The fonts under OFL-1.1 and the icons under
CC BY 4.0 are separate works bundled with the program, not linked into it.

A copy of the Apache License 2.0, required to travel with the components
released under it, is in [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).
