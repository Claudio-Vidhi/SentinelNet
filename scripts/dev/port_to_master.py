# -*- coding: utf-8 -*-
"""Porta Dev su master applicando lo strip, in un colpo solo.

Il merge Dev -> master non e' mai pulito da solo: ogni file dello strip che
cambia su Dev arriva come conflitto modify/delete (modificato su Dev,
cancellato su master), e i file dello strip che *non* cambiano vanno tolti a
mano dall'indice. Farlo a mano ogni volta e' il modo piu' semplice di
rimettere per sbaglio i test o AGENTS.md sul ramo pubblico.

Questo script fa il merge, risolve quei conflitti nell'unico modo ammesso
(sul ramo pubblico il file non esiste) e toglie tutto lo strip dall'indice e
dal disco. Lascia il merge STAGED e non committa: il messaggio lo scrive chi
porta.

Dopo il porting l'albero e' davvero "Dev meno lo strip", e `git checkout Dev`
rimette ogni file al suo posto. Cancellare e' necessario, non cosmetico: un
file dello strip NUOVO su Dev resterebbe li' non tracciato, e git si rifiuta
di sovrascrivere un file non tracciato quando il contenuto non coincide con
quello che sta per scrivere -- un fine riga normalizzato diverso basta a
bloccare il ritorno su Dev.

    uv run python scripts/dev/port_to_master.py          # esegue
    uv run python scripts/dev/port_to_master.py --check  # solo diagnosi

Regola di riferimento: AGENTS.md, sezione "Branches".
"""

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


def _prune_empty_dirs(files):
    """Toglie le cartelle rimaste vuote dopo la cancellazione, dalla piu'
    profonda in su. Una cartella con dentro solo __pycache__ resta: non e'
    tracciata su Dev, quindi cancellarla non e' compito di questo script."""
    dirs = {ROOT / f for f in files}
    dirs = sorted({d.parent for d in dirs}, key=lambda d: len(d.parts), reverse=True)
    for d in dirs:
        try:
            d.rmdir()
        except OSError:
            pass


def git(*args, check=True):
    r = subprocess.run(("git",) + args, capture_output=True, text=True)
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
    """Le due cose che devono valere dopo un porting corretto."""
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


def main():
    if "--check" in sys.argv:
        return check()

    if git("status", "--porcelain"):
        sys.exit("Albero di lavoro sporco: committa o metti da parte prima.")

    git("checkout", "master")
    print("su master; merge di Dev...")

    # Il merge fallisce sui modify/delete dello strip: e' previsto, si
    # prosegue e si risolvono sotto.
    subprocess.run(["git", "merge", "--no-ff", "--no-commit", "Dev"],
                   capture_output=True, text=True)

    unmerged = [l for l in git("diff", "--name-only",
                               "--diff-filter=U").splitlines() if l]
    files = stripped_paths()

    # Un conflitto fuori dallo strip e' vero conflitto di codice: si ferma.
    real = [f for f in unmerged if f not in files]
    if real:
        sys.exit("Conflitti veri, da risolvere a mano:\n  " + "\n  ".join(real))

    # I file dello strip in conflitto sono modify/delete: su master non esistono.
    for f in unmerged:
        git("rm", "-q", "-f", "--", f)

    # E tutto il resto dello strip esce dall'indice.
    present = [f for f in files
               if f not in unmerged
               and git("ls-files", "--", f, check=False)]
    if present:
        for i in range(0, len(present), 200):
            git("rm", "-q", "-r", "--cached", "--", *present[i:i + 200])

    # ...e anche dal disco. Lasciarli li' era gia' incoerente -- il ramo dei
    # modify/delete qui sopra li cancella eccome -- e per i file NUOVI su Dev
    # era una trappola: restavano non tracciati, e `git checkout Dev` si
    # rifiuta di sovrascrivere un file non tracciato il cui contenuto non
    # coincide con quello che sta per scrivere. Basta un fine riga
    # normalizzato diverso e il ritorno su Dev si blocca, con un elenco di
    # file che sembrano modifiche non salvate e non lo sono.
    #
    # Si cancella SOLO cio' che e' tracciato su Dev (`files` viene da li'):
    # `git checkout Dev` li riscrive tutti, quindi non si perde niente.
    removed = 0
    for f in present:
        path = ROOT / f
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    _prune_empty_dirs(files)

    print(f"strip applicato: {len(unmerged)} conflitti modify/delete risolti, "
          f"{len(present)} file tolti dall'indice, {removed} tolti dal disco.")

    staged = git("diff", "--cached", "--name-only", "Dev")
    extra = [l for l in staged.splitlines() if l and l not in files]
    if extra:
        sys.exit("Lo staged differisce da Dev fuori dallo strip:\n  "
                 + "\n  ".join(extra))

    print("\nmaster staged = Dev meno lo strip. Nessuna differenza di codice.")
    print("Rileggi con 'git diff --cached --stat' e poi committa il merge.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
