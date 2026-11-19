# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Launch SentinelNet in demo mode on an isolated sandbox (docs/demo.md).

The sandbox ``data/demo-sandbox`` (gitignored with the rest of data/) plays
the real data directory: it holds only the demo marker, and the app runs on
``data/demo-sandbox/demo``, seeded by services/demo_seed.py. The real ./data
is never opened.

Usage::

    uv run python scripts/dev/run_demo.py
    uv run python scripts/dev/run_demo.py --reset --port 8931
    uv run python scripts/dev/run_demo.py --seed-only
"""

import argparse
import os
import shutil
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SANDBOX_DIR = os.path.join(REPO_ROOT, "data", "demo-sandbox")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SentinelNet in demo mode")
    parser.add_argument("--port", type=int, default=8931, help="HTTP port (default: 8931)")
    parser.add_argument("--reset", action="store_true", help="Reset demo workspace before starting")
    parser.add_argument("--seed-only", action="store_true", help="Seed demo workspace and exit")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args()

    # Before core.data_config is imported: it reads both at import.
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    if args.reset:
        shutil.rmtree(os.path.join(SANDBOX_DIR, "demo"), ignore_errors=True)
    with open(os.path.join(SANDBOX_DIR, "demo-mode"), "w", encoding="utf-8") as fh:
        fh.write("dev launcher\n")
    os.environ["SENTINELNET_DATA_DIR"] = SANDBOX_DIR
    os.environ["SENTINELNET_PORT"] = str(args.port)
    if args.no_browser:
        os.environ["SENTINELNET_NO_BROWSER"] = "true"

    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)

    from core import data_config
    from services import demo_seed

    demo_seed.seed()
    username, password = demo_seed.credentials()
    print(f"Demo workspace ready in: {data_config.DATA_DIR}")
    print(f"Login: {username} / {password}")
    if args.seed_only:
        return 0

    import app_server

    sys.argv = [sys.argv[0]] + (["--no-browser"] if args.no_browser else [])
    app_server.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
