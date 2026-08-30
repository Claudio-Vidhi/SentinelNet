# -*- coding: utf-8 -*-
"""Vendor → driver → netmiko registry (plan Phase 3 items 12/15).

The mapping lived inside core/core_engine.py; the vendor logic it carries
belongs to the drivers layer. core_engine re-imports the three public names,
so every existing import site keeps working unchanged.

Adding a new driver: one entry in DRIVER_REGISTRY (plus, for vendors whose
registry entry may lack the 'driver' field, one in VENDOR_DRIVER_DEFAULTS)
is enough to make it selectable from the whole system.
"""

import re

from drivers.cisco_ios import CiscoIosDriver
from drivers.cisco_cbs import CiscoCbsDriver
from drivers.hp_procurve import HpProcurveDriver
from drivers.juniper_junos import JuniperJunosDriver
from drivers.aruba_os import ArubaOsDriver
from drivers.fortinet import FortinetDriver
from drivers.cisco_wlc import CiscoWlcDriver
from drivers.paloalto_panos import PaloAltoDriver
from drivers.linux import LinuxDriver

# Maps the driver-name (vendor registry 'driver' field) to the driver class
# and the corresponding netmiko device_type.
DRIVER_REGISTRY = {
    'cisco_ios':      (CiscoIosDriver,   'cisco_ios'),
    'cisco_s300':     (CiscoCbsDriver,   'cisco_s300'),
    'hp_procurve':    (HpProcurveDriver, 'hp_procurve'),
    'juniper_junos':  (JuniperJunosDriver, 'juniper_junos'),
    'aruba_os':       (ArubaOsDriver,    'aruba_os'),
    'fortinet':       (FortinetDriver,   'fortinet'),
    'paloalto_panos': (PaloAltoDriver,   'paloalto_panos'),
    'cisco_wlc':      (CiscoWlcDriver,   'cisco_wlc_ssh'),   # AireOS
    'cisco_9800':     (CiscoIosDriver,   'cisco_xe'),        # Catalyst 9800 (IOS-XE)
    'linux':          (LinuxDriver,      'linux'),
}

# Fallback vendor-name → driver-name, used when the vendor registry does not
# specify a driver (e.g. installations with legacy vendors.json or 'driver': null).
VENDOR_DRIVER_DEFAULTS = {
    'cisco':    'cisco_ios',
    'cisco_cbs': 'cisco_s300',
    'hpe':      'hp_procurve',
    'hp':       'hp_procurve',
    'juniper':  'juniper_junos',
    'aruba':    'aruba_os',
    'fortinet': 'fortinet',
    'paloalto': 'paloalto_panos',
    'cisco_wlc': 'cisco_wlc',
    'cisco_9800': 'cisco_9800',
    'linux':    'linux',
}


def resolve_driver(vendor):
    """Resolves a vendor into the (driver class, netmiko device_type) pair.

    Resolution order:
      1. 'driver' field of the vendor registry (get_all_vendors)
      2. fallback vendor-name → driver (VENDOR_DRIVER_DEFAULTS)
    Raises ValueError if no driver is associated with the vendor.
    """
    from services import inventory_manager
    from services.inventory_manager import get_all_vendors
    vendor = inventory_manager.normalize_vendor(vendor)

    driver_name = None
    try:
        vendors = get_all_vendors()
        entry = vendors.get(vendor)
        if entry:
            driver_name = entry.get('driver')
    except Exception:
        pass

    if not driver_name:
        driver_name = VENDOR_DRIVER_DEFAULTS.get(vendor)

    spec = DRIVER_REGISTRY.get(driver_name) if driver_name else None
    if not spec:
        raise ValueError(
            f"Vendor '{vendor}' non supportato: nessun driver associato "
            f"(driver='{driver_name}')."
        )
    return spec


# ARP command per driver (default 'show arp' if not listed). Vendor CLI
# knowledge belongs to the drivers layer (plan item 15); the ARP collector
# consumes this table instead of owning it.
ARP_COMMANDS = {
    'cisco_ios':      'show ip arp',
    'cisco_s300':     'show arp',
    'cisco_9800':     'show ip arp',
    'cisco_wlc':      'show arp switch',
    'hp_procurve':    'show arp',
    'juniper_junos':  'show arp no-resolve',
    'aruba_os':       'show arp',
    'paloalto_panos': 'show arp all',
}


def arp_command_for(driver_name: "str | None") -> str:
    return ARP_COMMANDS.get(driver_name or "", "show arp")


# --- CPE 2.3 identity, for the NVD vulnerability matcher --------------------
#
# NVD's keywordSearch is an AND over the words of the CVE *description*, so a
# query carrying a version ("cisco IOS Version 15.2 4 E10") matches nothing:
# CVE prose does not spell out build strings. The version-aware API is the CPE
# one (virtualMatchString), and it needs the product name NVD actually uses,
# which is neither the vendor label nor the driver name.
#
# Every product below was checked against the live API; the count in the
# comment is what it returned, as evidence the identity is real and not a
# plausible guess.
CPE_PRODUCTS = {
    'cisco_ios':      ('o', 'cisco', 'ios'),                              # 615
    'cisco_s300':     ('o', 'cisco', 'ios'),                              # 615
    'cisco_9800':     ('o', 'cisco', 'ios_xe'),                           # 546
    'cisco_wlc':      ('o', 'cisco', 'wireless_lan_controller_software'),  # 73
    'hp_procurve':    ('o', 'hp', 'procurve_switch_software'),              # 5
    'juniper_junos':  ('o', 'juniper', 'junos'),                          # 791
    'aruba_os':       ('o', 'arubanetworks', 'arubaos'),                  # 232
    'fortinet':       ('o', 'fortinet', 'fortios'),                       # 277
    'paloalto_panos': ('o', 'paloaltonetworks', 'pan-os'),                # 235
    'linux':          ('o', 'linux', 'linux_kernel'),                   # 19034
}

# CPE 2.3 formatted strings escape punctuation with a backslash. Cisco's
# "15.2(4)E10" is the case that matters: unescaped parentheses make NVD answer
# HTTP 404, which the caller would read as "no vulnerabilities".
_CPE_ESCAPE = set('!"#$%&\'()+,/:;<=>?@[]^`{|}~')


def cpe_quote(value: str) -> str:
    r"""Escapes a CPE 2.3 component ('15.2(4)E10' -> '15.2\(4\)e10')."""
    return "".join(("\\" + c if c in _CPE_ESCAPE else c) for c in value.lower())


# Cisco ships five operating systems under one vendor name, and NVD files them
# as five different products. Asking for the wrong one does not error: it
# answers zero, which reads on screen as "this device is fine".
# cisco:ios:17.9.4a -> 0 CVEs.  cisco:ios_xe:17.9.4a -> 52.
CISCO_OS_PRODUCTS = {
    "nx-os": "nx-os",
    "ios_xr": "ios_xr",
    "asa": "adaptive_security_appliance_software",
    "aireos": "wireless_lan_controller_software",
    "ios_xe": "ios_xe",
    "ios": "ios",
}


def cisco_os(text: str, version: str = "") -> str:
    """Which Cisco OS the description/version belongs to.

    The name is stated outright in most sysDescr strings; when it is not, the
    version shape decides. Classic IOS numbers its trains in parentheses
    ("15.2(4)E10"), IOS-XE is plain dotted from 16.x on ("17.9.4a") — the two
    never overlap.
    """
    hay = f"{text} {version}".lower()
    # Un WLC AireOS arriva dal frontend come vendor "cisco" come tutto il
    # resto: senza questo ramo finirebbe su ios, che per lui rende zero.
    if "aireos" in hay or "wireless lan controller" in hay:
        return "aireos"
    if "nx-os" in hay or "nexus" in hay:
        return "nx-os"
    if "ios-xr" in hay or "ios xr" in hay:
        return "ios_xr"
    if "adaptive security appliance" in hay or re.search(r"\basa\b", hay):
        return "asa"
    if "ios-xe" in hay or "ios xe" in hay:
        return "ios_xe"
    if re.search(r"\d+\.\d+\(\d+", version or ""):
        return "ios"
    if re.match(r"^1[6-9]\.\d+", version or ""):
        return "ios_xe"
    return "ios"


def cpe_match_string(vendor: "str | None", version: "str | None" = None,
                     text: str = "") -> "str | None":
    """CPE match string for a vendor (optionally pinned to a version).

    `text` is the raw description the version came from: for Cisco it decides
    WHICH operating system is being asked about. None when the vendor has no
    known CPE identity, so the caller falls back to the keyword search, coarse
    but better than a confidently wrong CPE.
    """
    from services import inventory_manager
    key = inventory_manager.normalize_vendor(vendor or "")
    driver = key if key in CPE_PRODUCTS else VENDOR_DRIVER_DEFAULTS.get(key)
    spec = CPE_PRODUCTS.get(driver or "")
    if not spec:
        return None
    part, cpe_vendor, product = spec
    if cpe_vendor == "cisco" and driver not in ("cisco_wlc",):
        product = CISCO_OS_PRODUCTS[cisco_os(text, version or "")]
    base = f"cpe:2.3:{part}:{cpe_vendor}:{product}"
    return f"{base}:{cpe_quote(version)}" if version else base


# --- Modello hardware, per capire se un CVE riguarda DAVVERO questo apparato ---
#
# Un CVE per IOS 15.2(4)E10 puo' riguardare solo gli ISR 1100: sullo stesso
# treno software gira anche un Catalyst 2960X, che non c'entra. NVD lo dice,
# quando lo dice: accanto al CPE del sistema operativo elenca i CPE hardware
# ('cpe:2.3:h:cisco:catalyst_2960x-24ts-l'). L'elenco pero' e' incompleto — ci
# sono CVE senza alcun hardware e modelli mai citati da nessun CVE — quindi il
# confronto serve a ORDINARE, mai a nascondere: un CVE che non combacia scende
# in fondo con un'etichetta, non sparisce.

# Parole di famiglia nei nomi NVD: tolte, resta il modello vero.
_HW_FAMILY_WORDS = (
    "integratedservicesrouter", "integratedservicerouter", "servicesrouter",
    "aggregationservicesrouter", "wirelesslancontroller", "industrialethernet",
    "catalyst", "nexus", "isr", "asr", "switch", "router", "series",
)


def _hw_core(name: str) -> str:
    """Nucleo confrontabile di un nome di modello (nostro o di NVD)."""
    core = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    for word in _HW_FAMILY_WORDS:
        core = core.replace(word, "")
    # 'WS-C2960X-24TS-L' e 'C9200-48P': la sigla di prefisso non e' il modello.
    core = re.sub(r"^(?:ws)?c(?=\d)", "", core)
    return core


def model_matches(model: str, cpe_hw_name: str) -> bool:
    """True se il modello dell'apparato e quello citato dal CVE sono lo stesso.

    Il confronto e' per prefisso in entrambi i versi: NVD cataloga sia la
    famiglia ('catalyst_9200') sia la singola referenza
    ('catalyst_9300-24p-a'), e un 'C9200-48P' deve riconoscersi in entrambe.
    """
    a, b = _hw_core(model), _hw_core(cpe_hw_name)
    if len(a) < 3 or len(b) < 3:
        return False
    return a.startswith(b) or b.startswith(a)
