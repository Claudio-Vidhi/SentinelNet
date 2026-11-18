# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Cisco Industrial Ethernet (IE-2000 / IE-3x00 / IE-4000 / IE-5000) driver.

Extends CiscoIosDriver with IE model extraction and industrial MIB OID
constants (CISCO-DLR-MIB, CISCO-ENVMON-MIB, CISCO-REP-MIB).
"""

import re

from drivers.cisco_ios import CiscoIosDriver

CISCO_IE_OIDS = {
    "dlr_ring_state": "1.3.6.1.4.1.9.9.796.1.1.1.1.2",
    "dlr_node_state": "1.3.6.1.4.1.9.9.796.1.1.1.1.3",
    "dlr_supervisor": "1.3.6.1.4.1.9.9.796.1.1.1.1.4",
    "dlr_ring_faults": "1.3.6.1.4.1.9.9.796.1.1.1.1.7",
    "rep_segment_status": "1.3.6.1.4.1.9.9.601.1.2.1.1.4",
    "envmon_temp_value": "1.3.6.1.4.1.9.9.13.1.3.1.3",
    "envmon_temp_state": "1.3.6.1.4.1.9.9.13.1.3.1.6",
    "alarm_contact_state": "1.3.6.1.4.1.9.9.13.1.4.1.3",
}


class CiscoIeDriver(CiscoIosDriver):
    """CLI driver for Cisco Industrial Ethernet (IE) switches."""

    def get_model(self) -> str:
        output = str(self.connection.send_command("show version") or "")
        match = re.search(r"Model\s*(?:Number)?\s*:\s*(\S+)", output, re.IGNORECASE)
        if not match:
            match = re.search(
                r"\b(IE-[0-9]{4}[A-Za-z0-9\-]*|CGS-[0-9]{4}[A-Za-z0-9\-]*|ESS-[0-9]{4}[A-Za-z0-9\-]*)\b",
                output,
                re.IGNORECASE,
            )
        if not match:
            match = re.search(
                r"\b(WS-C[A-Za-z0-9\-]+|C[0-9]{4}[A-Za-z0-9\-]*)\b",
                output,
            )
        if not match:
            match = re.search(r"cisco\s+([A-Za-z0-9\-]+)", output, re.IGNORECASE)
        return match.group(1).strip() if match else "Non Rilevato"
