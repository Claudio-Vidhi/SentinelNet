# -*- coding: utf-8 -*-
"""Pubblica Dev su master applicando lo strip: master e' un OUTPUT, non un merge.

master resta il ramo di produzione, con lo stesso codice di Dev e i file
dev-only tolti. Cambia solo come ci arriva: non piu' un merge di Dev, ma un
commit costruito, il cui albero e' "Dev meno lo strip" e il cui genitore e'
la pubblicazione precedente. Dev non e' suo genitore.

Perche' non un merge. Il merge dichiarava "il commit X di Dev e' contenuto in
master", e il lato master di quel merge conteneva le cancellazioni dello
strip: bastava un merge nel verso opposto per riportarle su Dev e cancellare
i test -- il motivo per cui AGENTS.md doveva vietare `git merge --ff-only
master`. In piu' il commit di merge veniva coniato daccapo a ogni esecuzione,
quindi due cloni che pubblicavano lo stesso stato di Dev producevano due
commit diversi con lo stesso albero, e il push veniva rifiutato per
divergenza senza un solo conflitto di codice a spiegarla.

Senza merge nessuna delle due cose esiste. Non c'e' niente che possa tornare
indietro su Dev, e il contenuto di master e' interamente derivato da Dev:
perdere una pubblicazione non perde nulla, quindi il push forzato e' sicuro e
la divergenza smette di essere un problema da risolvere.

L'albero di lavoro non viene mai toccato: si costruisce tutto in un indice
temporaneo. Niente checkout, niente conflitti modify/delete, niente file
cancellati dal disco.

    uv run python scripts/dev/port_to_master.py          # pubblica
    uv run python scripts/dev/port_to_master.py --check  # solo diagnosi

Regola di riferimento: AGENTS.md, sezione "Branches".
"""

import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

# Lo strip, come elencato in AGENTS.md. Aggiungere qui una voce nuova
# significa aggiungerla anche li': questo script e' l'applicazione di quella
# regola, non una seconda copia che puo' divergere in silenzio.
STRIP = (
    "tests",
    "tests_data",
    "AGENTS.md",
    ".claude",
    ".agents",
    ".impeccable",
    ".clinerules",
    ".clineignore",
    ".github",
    "CHANGELOG.md",
    "scripts/dev",
    "scripts/pyrefly_adversarial_analyzer.py",
    "scripts/snapshot_openapi.py",
    "scripts/vm_agent_test_helper.py",
    "docs/GO_PORT_PLAN.md",
    "docs/Improvements",
    "docs/app-review-fix-plan.md",
    "docs/console-rethink-plan-review.md",
    "docs/console-rethink-plan.md",
    "docs/fortigate-management-plan.md",
    "docs/linux-server-management-plan.md",
    "docs/netsec_troubleshooting_qa_v3.md",
    "docs/superpowers",
    "docs/test_optimization_findings.md",
    "docs/ui_tab_overlap_analysis.md",
)


def git(*args, check=True, env=None):
    r = subprocess.run(("git",) + args, capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        sys.exit(f"git {' '.join(args)} ha fallito:\n{r.stdout}{r.stderr}")
    return r.stdout.strip()


def tracked(ref, path):
    """I file tracciati sotto `path` in `ref` (vuoto se il path non esiste)."""
    out = git("ls-tree", "-r", "--name-only", ref, "--", path, check=False)
    return [l for l in out.splitlines() if l]


def stripped_paths():
    """Lo strip espanso ai file che esistono davvero su Dev."""
    files = []
    for p in STRIP:
        files.extend(tracked("Dev", p))
    return files


def check():
    """Le due cose che devono valere dopo una pubblicazione corretta."""
    expected = set(stripped_paths())
    on_master = set(git("ls-tree", "-r", "--name-only", "master").splitlines())
    leaked = sorted(expected & on_master)
    if leaked:
        print(f"STRIP VIOLATO: {len(leaked)} file dello strip sono su master:")
        for f in leaked[:20]:
            print("   ", f)
        if len(leaked) > 20:
            print(f"    ... e altri {len(leaked) - 20}")

    diff = [l for l in git("diff", "--name-only", "Dev", "master").splitlines()
            if l and l not in expected]
    if diff:
        print(f"DIVERGENZA APP: {len(diff)} file differiscono fuori dallo strip:")
        for f in diff[:20]:
            print("   ", f)

    if not leaked and not diff:
        print("OK: master e' Dev meno lo strip, ne' piu' ne' meno.")
    return 1 if (leaked or diff) else 0


def build_tree(files):
    """L'albero di Dev senza i file dello strip, senza toccare il disco.

    Si lavora su un indice temporaneo (GIT_INDEX_FILE): `git rm --cached` li'
    dentro non ha nessun effetto sull'albero di lavoro ne' sull'indice vero,
    quindi lo script si puo' lanciare da Dev senza checkout e senza rischiare
    di lasciare il repo a meta'."""
    tmp = ROOT / ".git" / "port-to-master.index"
    tmp.unlink(missing_ok=True)
    env = {**os.environ, "GIT_INDEX_FILE": str(tmp)}
    try:
        git("read-tree", "Dev", env=env)
        for i in range(0, len(files), 200):
            git("rm", "-q", "-r", "--cached", "--ignore-unmatch", "--",
                *files[i:i + 200], env=env)
        return git("write-tree", env=env)
    finally:
        tmp.unlink(missing_ok=True)


def main():
    if "--check" in sys.argv:
        return check()

    if git("status", "--porcelain"):
        sys.exit("Albero di lavoro sporco: committa o metti da parte prima.")

    # Si pubblica sopra a cio' che e' gia' pubblicato, non sopra al master
    # locale: se un altro clone ha pubblicato nel frattempo, la sua
    # pubblicazione e' il genitore giusto. Offline si ripiega sul locale e lo
    # si dice -- il push chiedera' comunque un --force-with-lease consapevole.
    parent = "master"
    if git("rev-parse", "--verify", "-q", "origin/master", check=False):
        if subprocess.run(["git", "fetch", "-q", "origin", "master"],
                          capture_output=True).returncode == 0:
            parent = "origin/master"
        else:
            print("ATTENZIONE: fetch fallito (offline?), si pubblica sopra al "
                  "master locale.")

    files = stripped_paths()
    tree = build_tree(files)

    if tree == git("rev-parse", f"{parent}^{{tree}}"):
        print(f"Niente da pubblicare: {parent} ha gia' questo albero.")
        return 0

    dev = git("rev-parse", "--short", "Dev")
    subject = git("log", "-1", "--format=%s", "Dev")
    msg = (f"publish: Dev {dev} ({subject})\n\n"
           f"Albero = Dev {dev} meno i file dev-only.\n"
           f"Vedi AGENTS.md, sezione \"Branches\".\n")
    commit = git("commit-tree", tree, "-p", git("rev-parse", parent), "-m", msg)
    git("branch", "-f", "master", commit)

    print(f"master -> {commit[:9]} (albero di Dev {dev} meno {len(files)} "
          f"file dello strip), genitore {parent}.")
    print("\nRileggi con 'git show --stat master' e 'git diff Dev master --stat',")
    print("poi pubblica:  git push --force-with-lease origin master")
    return check()


if __name__ == "__main__":
    sys.exit(main())
