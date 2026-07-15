# -*- coding: utf-8 -*-
"""Cattura lo schema OpenAPI corrente in tests_data/openapi_pre_destructure.json.

Snapshot di riferimento per il destructuring di app_server.py (fase 6.6):
va rigenerato SOLO quando si aggiungono endpoint nuovi in modo deliberato,
mai per far passare un test di parity fallito.

Uso: uv run python scripts/snapshot_openapi.py
"""

import json
import os
import sys
import tempfile

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_snapshot_"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app_server  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "tests_data", "openapi_pre_destructure.json")


def main():
    spec = app_server.app.openapi()
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(spec, fh, indent=2, sort_keys=True, ensure_ascii=False)
    print(f"Snapshot scritto: {OUT} ({len(spec['paths'])} percorsi)")


if __name__ == "__main__":
    main()
