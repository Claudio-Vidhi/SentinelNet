# -*- coding: utf-8 -*-
"""Che cosa e' uscito di nuovo per le dipendenze, ogni tot giorni.

`uv lock --upgrade --dry-run` sa gia' dire quali versioni esistono senza
toccare `uv.lock`: qui sopra ci si mette solo la cadenza e i link ai changelog,
perche' "fastapi 0.136 -> 0.140" da solo non dice se sono bugfix o una rottura.

    uv run python scripts/check_outdated_deps.py            # dimmelo adesso
    uv run python scripts/check_outdated_deps.py --if-stale # solo se e' ora
    uv run python scripts/check_outdated_deps.py --days 14  # altra cadenza

Non aggiorna niente. Cambiare versione resta una decisione, e passa da
`uv lock --upgrade-package <nome>` piu' i gate di AGENTS.md.
"""
import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
# data/ e' gitignorata come directory: uno stato nuovo qui non va aggiunto a
# mano al .gitignore e non puo' finire in un commit per distrazione.
_STAMP = _ROOT / "data" / "deps_last_check.json"
_DEFAULT_DAYS = 7

# "Update fastapi v0.136.3 -> v0.140.13", anche con piu' versioni per riga.
_LINE = re.compile(r"^Update\s+(\S+)\s+(.+?)\s+->\s+(.+?)\s*$")


def _direct_deps():
    """I nomi che questo repo chiede davvero, per distinguerli dalle transitive."""
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return {m.group(1).lower()
            for m in re.finditer(r'^\s*"([A-Za-z0-9._-]+)[><=~!\[]', text,
                                 re.MULTILINE)}


def _bump_kind(old, new):
    """major / minor / patch, guardando solo la prima versione della riga."""
    def parts(v):
        v = v.split(",")[0].strip().lstrip("v")
        return [int(x) for x in re.findall(r"\d+", v)[:3]]
    try:
        o, n = parts(old), parts(new)
    except ValueError:
        return "?"
    o += [0] * (3 - len(o))
    n += [0] * (3 - len(n))
    if n[0] != o[0]:
        return "major"
    if n[1] != o[1]:
        return "minor"
    return "patch"


def _check():
    proc = subprocess.run(
        ["uv", "lock", "--upgrade", "--dry-run"],
        capture_output=True, text=True, cwd=_ROOT)
    if proc.returncode != 0:
        print(proc.stderr or proc.stdout, file=sys.stderr)
        return None
    updates = []
    for line in (proc.stdout + proc.stderr).splitlines():
        m = _LINE.match(line.strip())
        if m:
            name, old, new = m.groups()
            updates.append({"name": name, "old": old, "new": new,
                            "kind": _bump_kind(old, new)})
    return updates


def _report(updates):
    if not updates:
        print("Dipendenze aggiornate: niente di nuovo.")
        return
    direct = _direct_deps()
    mine = [u for u in updates if u["name"].lower() in direct]
    other = [u for u in updates if u["name"].lower() not in direct]

    order = {"major": 0, "minor": 1, "patch": 2, "?": 3}
    print(f"{len(updates)} pacchetti hanno una versione piu' recente "
          f"({len(mine)} dichiarati in pyproject.toml).\n")
    for title, group in (("Dichiarati qui", mine), ("Transitivi", other)):
        if not group:
            continue
        print(f"--- {title} ---")
        for u in sorted(group, key=lambda x: (order[x["kind"]], x["name"])):
            mark = "!" if u["kind"] == "major" else " "
            print(f" {mark} {u['name']:<24} {u['old']} -> {u['new']}"
                  f"  [{u['kind']}]")
            if u["kind"] in ("major", "minor") and title == "Dichiarati qui":
                print(f"     https://pypi.org/project/{u['name']}/#history")
        print()
    print("Niente e' stato aggiornato. Per uno solo:\n"
          "  uv lock --upgrade-package <nome> && uv sync\n"
          "poi i gate di AGENTS.md prima di committare.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--days", type=int, default=_DEFAULT_DAYS,
                    help=f"cadenza in giorni (default {_DEFAULT_DAYS})")
    ap.add_argument("--if-stale", action="store_true",
                    help="non fare niente se il controllo e' recente")
    args = ap.parse_args()

    today = dt.date.today()
    if args.if_stale and _STAMP.exists():
        last = dt.date.fromisoformat(json.loads(_STAMP.read_text())["date"])
        if (today - last).days < args.days:
            return 0

    updates = _check()
    if updates is None:
        return 1
    _report(updates)
    _STAMP.parent.mkdir(parents=True, exist_ok=True)
    _STAMP.write_text(json.dumps({"date": today.isoformat(),
                                  "pending": len(updates)}, indent=2),
                      encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
