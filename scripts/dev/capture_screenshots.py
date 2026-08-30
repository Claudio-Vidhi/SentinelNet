# -*- coding: utf-8 -*-
"""Rigenera gli screenshot del README da un'istanza usa-e-getta.

Avvia l'app su una data directory vuota, crea un admin di prova e pilota
Chrome headless via CDP per fotografare il wizard di primo accesso, la
dashboard e l'inventario. La data directory reale non viene mai toccata:
quello che finisce nelle immagini e' un'installazione pulita, senza un
singolo apparato, tenant o indirizzo veri.

    uv run python scripts/dev/capture_screenshots.py

Le immagini vanno in docs/images/ e il README le referenzia da li'. Va
rilanciato quando la UI cambia in modo visibile: gli screenshot invecchiano
in silenzio, nessun test se ne accorge.

Locale: la lingua della UI segue quella del browser, quindi su una macchina
italiana Chrome chiederebbe l'italiano. Il README pubblico e' in inglese e
la cattura forza en-US.

Richiede Chrome installato nel percorso standard di Windows.
"""
import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import websockets

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = sys.executable
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PORT = 8931
DEBUG_PORT = 9333
BASE = f"http://127.0.0.1:{PORT}"
OUT = os.path.join(REPO, "docs", "images")

USER = "admin"
PASSWORD = "Sentinel!Demo2026"

# tab id -> nome file. Solo le schede che il README usa davvero: a install
# pulita le altre sono vuote e una schermata vuota non racconta nulla.
TABS = [
    ("tab-home", "dashboard"),
    ("tab-devices", "inventory"),
]


def post(path, payload):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, r.read().decode()


def wait_for(url, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


class CDP:
    def __init__(self, ws):
        self.ws = ws
        self.n = 0

    async def send(self, method, **params):
        self.n += 1
        await self.ws.send(json.dumps({"id": self.n, "method": method,
                                       "params": params}))
        while True:
            msg = json.loads(await self.ws.recv())
            if msg.get("id") == self.n:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})

    async def eval(self, expr):
        r = await self.send("Runtime.evaluate", expression=expr,
                            awaitPromise=True, returnByValue=True)
        return r.get("result", {}).get("value")

    async def shot(self, name):
        r = await self.send("Page.captureScreenshot", format="png",
                            captureBeyondViewport=False)
        path = os.path.join(OUT, name + ".png")
        with open(path, "wb") as f:
            f.write(base64.b64decode(r["data"]))
        print(f"  shot {name}.png ({os.path.getsize(path) // 1024} KB)")

    async def goto(self, url, settle=3.0):
        await self.send("Page.navigate", url=url)
        await asyncio.sleep(settle)


async def run(cdp):
    await cdp.send("Page.enable")
    await cdp.send("Runtime.enable")
    # This machine's locale is it-IT, so Chrome reports navigator.language
    # 'it-IT' and the app correctly opens in Italian. The public README wants
    # the English UI, so force an English locale for the shoot.
    await cdp.send("Emulation.setLocaleOverride", locale="en-US")
    await cdp.send("Network.enable")
    await cdp.send("Network.setExtraHTTPHeaders",
                   headers={"Accept-Language": "en-US,en;q=0.9"})

    # 1. Primo contatto: il wizard, prima che esista un account.
    await cdp.goto(BASE + "/", settle=4)
    await cdp.shot("first-run")

    # 2. Si crea l'admin di prova.
    print("  register:", post("/api/auth/register",
                              {"username": USER, "password": PASSWORD}))

    # 3. Login dall'interno della pagina, cosi' il cookie di sessione
    #    HttpOnly finisce nel browser; poi si ricarica sulla dashboard.
    ok = await cdp.eval(
        "fetch('/api/auth/login', {method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        f"body: JSON.stringify({{username:'{USER}',password:'{PASSWORD}'}})"
        "}).then(r => r.status)")
    print("  login status:", ok)
    await cdp.goto(BASE + "/", settle=6)

    for tab_id, name in TABS:
        await cdp.eval(f"switchTab('{tab_id}')")
        await asyncio.sleep(3.0)
        await cdp.shot(name)


async def main():
    if not os.path.exists(CHROME):
        raise SystemExit(f"Chrome non trovato in {CHROME}: gli screenshot "
                         "si catturano con Chrome headless.")
    os.makedirs(OUT, exist_ok=True)
    data_dir = tempfile.mkdtemp(prefix="sn_shots_")
    profile = tempfile.mkdtemp(prefix="sn_chrome_")
    env = dict(os.environ,
               SENTINELNET_DATA_DIR=data_dir,
               SENTINELNET_NO_BROWSER="true",
               SENTINELNET_PORT=str(PORT))
    server = subprocess.Popen([PY, "app_server.py"], cwd=REPO, env=env,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    chrome = None
    try:
        if not wait_for(BASE + "/api/version"):
            raise SystemExit("server did not come up")
        print("server up on", BASE)

        chrome = subprocess.Popen([
            CHROME, "--headless=new", f"--remote-debugging-port={DEBUG_PORT}",
            f"--user-data-dir={profile}", "--window-size=1600,1000",
            "--hide-scrollbars", "--force-device-scale-factor=1",
            "--lang=en-US", "--accept-lang=en-US,en",
            "--no-first-run", "--no-default-browser-check", "about:blank",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if not wait_for(f"http://127.0.0.1:{DEBUG_PORT}/json/version"):
            raise SystemExit("chrome debug port never opened")
        with urllib.request.urlopen(
                f"http://127.0.0.1:{DEBUG_PORT}/json") as r:
            tabs = json.load(r)
        ws_url = next(t["webSocketDebuggerUrl"] for t in tabs
                      if t["type"] == "page")
        print("chrome attached")

        async with websockets.connect(ws_url, max_size=64 * 1024 * 1024) as ws:
            await run(CDP(ws))
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
    print("done ->", OUT)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
