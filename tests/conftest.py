# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Pin the shared-at-import paths before any test module can claim them.

Nineteen module-level constants resolve `data_config.get_path(...)` at import
(`USERS_JSON`, `KEY_FILE`, `DB_PATH`, `PROBES_JSON`, `TENANT_SNMP_JSON`,
`BACKUP_FOLDER`, ...). Eighty-one test modules each set their own
`SENTINELNET_DATA_DIR` at *their* import and reasonably believe they are
isolated. Only the first import of each production module wins, so in practice
those constants land wherever import order puts them -- and they do not even
land together. Measured, importing two modules in the two possible orders:

    first = test_snmp_defaults        first = test_snmp_poller
      USERS_JSON       -> .../snmp      USERS_JSON       -> .../snmpdef
      TENANT_SNMP_JSON -> .../snmpdef   TENANT_SNMP_JSON -> .../snmpdef
      DB_PATH          -> .../snmp      DB_PATH          -> .../snmpdef

Under `pytest -n 4` the order changes with how xdist splits the modules, so
which files two test modules share changes from run to run. That is how state
left by one module reaches another only sometimes -- a test that fails once
every few full runs and never in isolation. Two of those were found and fixed
by hand this way; the rest of the surface is the same shape.

This file does not make the modules isolated -- that would mean making all
nineteen resolve their path lazily, and the tests that patch those constants by
name depend on them being constants. It makes the sharing DETERMINISTIC: one
directory, chosen here, bound before any test module is imported. Leaked state
then reaches the same places on every run, so it fails the same way every time
instead of one run in ten.

A module that needs real isolation still gets it the way several already do:
its own `tempfile.mkdtemp()` plus `patch.object(mod, "CONST", path)`.
"""

import os
import tempfile

# Chosen before anything else imports: pytest loads conftest ahead of the test
# modules, so this is the one moment at which the winner can be decided.
SUITE_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_suite_")
os.environ["SENTINELNET_DATA_DIR"] = SUITE_DATA_DIR

from core import data_config  # noqa: E402

data_config.DATA_DIR = SUITE_DATA_DIR

# Importing each owner binds its constants NOW, under the directory above.
# Adding a new `X = data_config.get_path(...)` at module level means adding its
# module here too, otherwise it goes back to being decided by import order.
from collectors import mac_history          # noqa: E402,F401  DB_PATH
from core import backup_store               # noqa: E402,F401  BACKUP_FOLDER
from security import crypto_vault           # noqa: E402,F401  KEY_FILE
from security import identity_manager       # noqa: E402,F401  IDENTITIES_JSON
from security import security_manager       # noqa: E402,F401  JWT_KEY_FILE, AUDIT_LOG_FILE, ATTEMPTS_FILE
from security import snmp_defaults          # noqa: E402,F401  TENANT_SNMP_JSON
from security import user_manager           # noqa: E402,F401  USERS_JSON
from services import fortigate_service      # noqa: E402,F401  TOKENS_FILE
from services import inventory_manager      # noqa: E402,F401  hosts/groups/versions/vendors/categories/models
from services import location_manager       # noqa: E402,F401  isolates via HOSTS_CSV
from services import probe_manager           # noqa: E402,F401  PROBES_JSON, JOBS_DB
from services import vlan_routing           # noqa: E402,F401  VLAN_ROUTING_JSON


def make_location(org: str = "Generale", name: str = "Sede", probe: str = "central") -> str:
    """Helper for tests adding new devices: creates a location in the org."""
    if org not in inventory_manager.get_all_groups():
        inventory_manager.add_group(org)
    loc = location_manager.create_location(org, name, probe=probe)
    return loc["id"]



def seed_inventory(hosts=(), decommissioned=(), orgs=(), locations=None):
    """Write rows straight into the inventory database under the current
    get_hosts_csv() directory. Organizations named by rows or `orgs`, and
    locations named by rows, are created; `locations` overrides their data."""
    from services import inventory_store
    rows = [dict({f: "" for f in inventory_store.HOST_FIELDS}, **h) for h in hosts]
    dec = [dict({f: "" for f in inventory_store.HOST_FIELDS + inventory_store.DECOM_FIELDS}, **h)
           for h in decommissioned]
    with inventory_manager._db() as conn:
        groups = inventory_store.read_orgs(conn)
        for g in set(orgs) | {r["Group"] for r in rows + dec if r["Group"]} | \
                {v["org"] for v in (locations or {}).values()}:
            groups.setdefault(g, {"description": ""})
        inventory_store.write_orgs(conn, groups)
        locs = inventory_store.read_locations(conn)
        locs.update(locations or {})
        for r in rows + dec:
            if r["Location"] and r["Location"] not in locs:
                locs[r["Location"]] = {"org": r["Group"], "name": r["Location"],
                                       "role": "branch", "subnets": [], "probe": "central"}
        inventory_store.write_locations(conn, locs)
        inventory_store.write_hosts(conn, "hosts", inventory_store.read_hosts(conn, "hosts"), rows)
        inventory_store.write_hosts(conn, "decommissioned_hosts",
                                    inventory_store.read_hosts(conn, "decommissioned_hosts"), dec)
    inventory_manager._rows_cache.clear()
    inventory_manager.invalidate_device_ip_cache()
