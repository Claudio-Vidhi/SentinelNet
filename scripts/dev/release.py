# -*- coding: utf-8 -*-
"""Prepara una release: versione, CHANGELOG, commit, tag. NON pubblica.

Ogni release finora ha ripetuto a mano gli stessi sei passi, e ne bastava uno
dimenticato per lasciare l'albero incoerente: la 0.26.0 e' rimasta senza tag
finche' qualcuno non se n'e' accorto, e le Release su GitHub sono ferme a
0.25.0 perche' un tag spinto non ne crea una.

Quello che fa, in ordine, fermandosi al primo errore:

  1. verifica di essere su Dev con l'albero pulito;
  2. verifica che [Unreleased] nel CHANGELOG abbia davvero qualcosa;
  3. esegue il gate (pyrefly, controllo dati privati, suite);
  4. aggiorna core/version.py, pyproject.toml e uv.lock;
  5. promuove [Unreleased] a [X.Y.Z] con la data di oggi;
  6. committa, crea il tag annotato e allinea master a Dev.

Quello che NON fa: spingere. Stampa i comandi e si ferma. Una release
sbagliata che non ha lasciato la macchina non costa niente; una gia' pubblica
si corregge solo con un'altra release. Il push di master e' per giunta
forzato, e quello non si automatizza a cuor leggero.

    uv run python scripts/dev/release.py patch     # 0.27.1 -> 0.27.2
    uv run python scripts/dev/release.py minor     # 0.27.1 -> 0.28.0
    uv run python scripts/dev/release.py major     # 0.27.1 -> 1.0.0
    uv run python scripts/dev/release.py patch --dry-run   # solo diagnosi

Regola di riferimento: AGENTS.md, "Software Versioning" e "Branches".
"""

import argparse
import datetime
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
VERSION_PY = ROOT / "core" / "version.py"
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"


def bump_version(current: str, part: str) -> str:
    """0.27.1 + 'minor' -> 0.28.0. Minor e major azzerano cio' che sta sotto."""
    major, minor, patch = (int(x) for x in current.split("."))
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    if part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"parte di versione sconosciuta: {part}")


def unreleased_body(text: str) -> str:
    """Il contenuto della sezione [Unreleased], senza la sua intestazione."""
    match = re.search(r"^## \[Unreleased\]\n(.*?)(?=^## \[)", text,
                      re.MULTILINE | re.DOTALL)
    return match.group(1).strip() if match else ""


def promote_changelog(text: str, version: str, today: str) -> str:
    """Sposta [Unreleased] sotto [X.Y.Z] - data, lasciando [Unreleased] vuota.

    L'intestazione [Unreleased] resta: la prossima modifica deve avere dove
    atterrare, e una sezione assente e' come una dimenticata."""
    body = unreleased_body(text)
    if not body:
        raise ValueError("[Unreleased] e' vuota: non c'e' niente da rilasciare.")
    return re.sub(
        r"^## \[Unreleased\]\n.*?(?=^## \[)",
        f"## [Unreleased]\n\n## [{version}] - {today}\n\n{body}\n\n",
        text, count=1, flags=re.MULTILINE | re.DOTALL)


def run(args, check=True, capture=True):
    r = subprocess.run(args, cwd=ROOT, capture_output=capture, text=True)
    if check and r.returncode != 0:
        out = ((r.stdout or "") + (r.stderr or "")) if capture else ""
        sys.exit(f"FALLITO: {' '.join(args)}\n{out}")
    return r


def current_version() -> str:
    match = re.search(r'__version__ = "([^"]+)"',
                      VERSION_PY.read_text(encoding="utf-8"))
    if not match:
        sys.exit("core/version.py: __version__ non trovato.")
    return match.group(1)


def preflight():
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    if branch != "Dev":
        sys.exit(f"Si rilascia da Dev, non da '{branch}'. Vedi AGENTS.md, Branches.")
    if run(["git", "status", "--porcelain"]).stdout.strip():
        sys.exit("Albero sporco: committa o scarta prima di rilasciare.")


def gate():
    print("== gate ==")
    for label, args in (
            ("pyrefly", ["uv", "run", "pyrefly", "check"]),
            ("dati privati", ["uv", "run", "python",
                              "scripts/check_no_private_data.py"]),
            ("suite", ["uv", "run", "pytest", "tests", "-n", "4", "-q"])):
        print(f"-- {label}")
        run(args, capture=False)


def main():
    ap = argparse.ArgumentParser(description="Prepara una release (non pubblica).")
    ap.add_argument("part", choices=("major", "minor", "patch"))
    ap.add_argument("--dry-run", action="store_true",
                    help="Dice cosa farebbe e si ferma, senza toccare nulla.")
    ap.add_argument("--skip-gate", action="store_true",
                    help="Salta i controlli. Solo per riprendere una release "
                         "interrotta dopo averli gia' eseguiti.")
    args = ap.parse_args()

    preflight()
    old = current_version()
    new = bump_version(old, args.part)
    body = unreleased_body(CHANGELOG.read_text(encoding="utf-8"))
    if not body:
        sys.exit("[Unreleased] e' vuota nel CHANGELOG: niente da rilasciare.")

    print(f"{old} -> {new}\n\n{body[:400]}{'...' if len(body) > 400 else ''}\n")
    if args.dry_run:
        print("--dry-run: nulla e' stato modificato.")
        return 0

    if not args.skip_gate:
        gate()

    VERSION_PY.write_text(
        VERSION_PY.read_text(encoding="utf-8").replace(
            f'__version__ = "{old}"', f'__version__ = "{new}"', 1),
        encoding="utf-8")
    PYPROJECT.write_text(
        PYPROJECT.read_text(encoding="utf-8").replace(
            f'version = "{old}"', f'version = "{new}"', 1),
        encoding="utf-8")
    today = datetime.date.today().isoformat()
    CHANGELOG.write_text(
        promote_changelog(CHANGELOG.read_text(encoding="utf-8"), new, today),
        encoding="utf-8")
    run(["uv", "lock"])

    run(["git", "add", "core/version.py", "pyproject.toml", "uv.lock",
         "CHANGELOG.md"])
    run(["git", "commit", "-m", f"chore(release): {new}"])
    run(["git", "tag", "-a", f"v{new}", "-m", f"SentinelNet {new}"])
    run(["git", "branch", "-f", "master", "Dev"])

    notes = pathlib.Path(tempfile.gettempdir()) / f"sentinelnet-{new}-notes.md"
    notes.write_text(body + "\n", encoding="utf-8")

    print(f"""
Release {new} pronta in locale. Niente e' stato pubblicato.

Per pubblicarla:

  git push origin Dev
  git push --force-with-lease origin master
  git push origin v{new}
  gh release create v{new} --title "SentinelNet {new}" \\
      --notes-file "{notes}" --latest

Per annullarla, finche' non hai spinto:

  git tag -d v{new} && git reset --hard HEAD~1 && git branch -f master Dev
""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
