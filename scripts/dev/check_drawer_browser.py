# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Endpoint drawer in a real browser: Esc and the 900px breakpoint.

The suite pins the drawer's code statically; key handling and media queries
only run in a browser. Same disposable instance as capture_screenshots.py
(empty data dir, test admin, headless Chrome over CDP), no real data.

    uv run python scripts/dev/check_drawer_browser.py

Exits non-zero if any check fails. Requires Chrome in the standard Windows
path.
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

import websockets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from scripts.dev import capture_screenshots as cs  # noqa: E402

PORT = 8932
DEBUG_PORT = 9334
cs.BASE = BASE = f"http://127.0.0.1:{PORT}"
MAC = "aa:bb:cc:dd:ee:01"

STATE = """({
  open: !document.getElementById('epDrawerHost').hidden,
  docked: document.getElementById('locBody').classList.contains('has-drawer'),
  sheet: isModalOpen('epDrawerHost'),
  popup: !!document.getElementById('portConfigModal'),
})"""

failures = []


def check(name, got, want):
    ok = got == want
    print(("  ok   " if ok else "  FAIL ") + name + ("" if ok else f": {got} != {want}"))
    if not ok:
        failures.append(name)


async def esc(cdp):
    for t in ("keyDown", "keyUp"):
        await cdp.send("Input.dispatchKeyEvent", type=t, key="Escape",
                       code="Escape", windowsVirtualKeyCode=27)
    await asyncio.sleep(0.3)


async def width(cdp, w):
    await cdp.send("Emulation.setDeviceMetricsOverride", width=w, height=900,
                   deviceScaleFactor=1, mobile=False)
    await asyncio.sleep(0.5)


async def open_drawer(cdp):
    await cdp.eval(f"openEpDrawer('{MAC}', '', null)")
    await asyncio.sleep(1.0)


async def run(cdp):
    await cdp.send("Page.enable")
    await cdp.send("Runtime.enable")
    await cdp.goto(BASE + "/", settle=3)
    cs.post("/api/auth/register", {"username": cs.USER, "password": cs.PASSWORD})
    await cdp.eval(
        "fetch('/api/auth/login', {method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        f"body: JSON.stringify({{username:'{cs.USER}',password:'{cs.PASSWORD}'}})"
        "}).then(r => r.status)")
    await cdp.goto(BASE + "/", settle=5)
    await cdp.eval("switchTab('tab-endpoint')")
    await asyncio.sleep(3)

    async def st():
        return await cdp.eval(STATE)

    print("wide: Esc closes the docked drawer")
    await width(cdp, 1400)
    await open_drawer(cdp)
    check("docked", await st(), {"open": True, "docked": True, "sheet": False, "popup": False})
    await esc(cdp)
    check("closed", (await st())["open"], False)

    print("wide: Esc over the port config popup closes only the popup")
    await open_drawer(cdp)
    await cdp.eval("showPortConfig('192.0.2.1', 'GigabitEthernet1/0/1', 'switch-01')")
    await asyncio.sleep(1.0)
    check("popup on top", (await st())["popup"], True)
    await esc(cdp)
    check("popup gone, drawer kept", await st(), {"open": True, "docked": True, "sheet": False, "popup": False})
    await esc(cdp)
    check("second Esc closes the drawer", (await st())["open"], False)

    print("narrow: Esc closes the sheet")
    await width(cdp, 800)
    await open_drawer(cdp)
    check("sheet", await st(), {"open": True, "docked": False, "sheet": True, "popup": False})
    await esc(cdp)
    check("closed", await st(), {"open": False, "docked": False, "sheet": False, "popup": False})

    print("resize with the drawer open")
    await width(cdp, 1400)
    await open_drawer(cdp)
    await width(cdp, 800)
    check("wide -> narrow becomes a sheet", await st(), {"open": True, "docked": False, "sheet": True, "popup": False})
    await width(cdp, 1400)
    check("narrow -> wide docks again", await st(), {"open": True, "docked": True, "sheet": False, "popup": False})
    await esc(cdp)
    check("closed", (await st())["open"], False)


async def main():
    if not os.path.exists(cs.CHROME):
        raise SystemExit(f"Chrome not found at {cs.CHROME}")
    data_dir = tempfile.mkdtemp(prefix="sn_drawer_")
    profile = tempfile.mkdtemp(prefix="sn_chrome_")
    env = dict(os.environ, SENTINELNET_DATA_DIR=data_dir,
               SENTINELNET_NO_BROWSER="true", SENTINELNET_PORT=str(PORT))
    server = subprocess.Popen([sys.executable, "app_server.py"], cwd=cs.REPO, env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    chrome = None
    try:
        if not cs.wait_for(BASE + "/api/version"):
            raise SystemExit("server did not come up")
        chrome = subprocess.Popen([
            cs.CHROME, "--headless=new", f"--remote-debugging-port={DEBUG_PORT}",
            f"--user-data-dir={profile}", "--window-size=1400,900",
            "--no-first-run", "--no-default-browser-check", "about:blank",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not cs.wait_for(f"http://127.0.0.1:{DEBUG_PORT}/json/version"):
            raise SystemExit("chrome debug port never opened")
        with urllib.request.urlopen(f"http://127.0.0.1:{DEBUG_PORT}/json") as r:
            ws_url = next(t["webSocketDebuggerUrl"] for t in json.load(r) if t["type"] == "page")
        async with websockets.connect(ws_url, max_size=64 * 1024 * 1024) as ws:
            await run(cs.CDP(ws))
    finally:
        for p in (chrome, server):
            if p:
                p.terminate()
                try:
                    p.wait(timeout=10)
                except Exception:
                    p.kill()
        for d in (data_dir, profile):
            shutil.rmtree(d, ignore_errors=True)
    if failures:
        raise SystemExit(f"{len(failures)} check(s) failed: {', '.join(failures)}")
    print("all checks passed")


if __name__ == "__main__":
    asyncio.run(main())
