#!/usr/bin/env bash
# Nudge verso graphify prima di grep/read sul sorgente grezzo.
#
# Perche' un file e non due catene dentro settings.json: le catene erano
# illeggibili e, soprattutto, mute. Su questa macchina `python3` e' lo stub
# del Microsoft Store — sta nel PATH ma non e' Python — quindi entrambi gli
# hook fallivano ad ogni chiamata e `2>/dev/null || true` lo nascondeva:
# l'enforcement sembrava attivo e non lo era. Qui l'interprete si sceglie
# provandolo, e se non ce n'e' uno lo si dice una volta su stderr.
#
# Uso: graphify-nudge.sh bash|read     (il JSON dell'hook arriva su stdin)

set -u
MODE="${1:-read}"

# Un interprete che ESEGUE, non uno che esiste: lo stub del Store supera
# `command -v` e poi esce con errore.
PY=""
for c in python3 python; do
    if printf '' | "$c" -c '' 2>/dev/null; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
    echo "graphify-nudge: nessun interprete Python utilizzabile, hook inattivo" >&2
    exit 0
fi

[ -f graphify-out/graph.json ] || exit 0

PAYLOAD=$(cat)

if [ "$MODE" = "bash" ]; then
    CMD=$(printf '%s' "$PAYLOAD" | "$PY" -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('tool_input',d).get('command',''))" 2>/dev/null) || exit 0
    case "$CMD" in
        *grep*|*rg\ *|*ripgrep*|*find\ *|*fd\ *|*ack\ *|*ag\ *) ;;
        *) exit 0 ;;
    esac
    MSG='MANDATORY: graphify-out/graph.json exists. You MUST run `graphify query \"<question>\"` before grepping raw files. Only grep after graphify has oriented you, or to modify/debug specific lines.'
else
    HIT=$(printf '%s' "$PAYLOAD" | "$PY" -c \
        "import json,sys
d=json.load(sys.stdin); t=d.get('tool_input',d)
exts=('.py','.js','.ts','.tsx','.jsx','.astro','.vue','.svelte','.go','.rs','.java','.rb','.c','.h','.cpp','.hpp','.cc','.cs','.kt','.swift','.php','.scala','.lua','.sh','.md','.rst','.txt','.mdx')
vals=[str(t.get('file_path') or ''), str(t.get('pattern') or ''), str(t.get('path') or '')]
joined=' '.join(vals).lower().replace(chr(92),'/')
tails=['.'+x.rsplit('.',1)[-1] for v in vals if v for x in [v.lower().replace(chr(92),'/').rsplit('/',1)[-1]] if '.' in x]
sys.stdout.write('1' if 'graphify-out/' not in joined and any(t in exts for t in tails) else '')" 2>/dev/null) || exit 0
    [ "$HIT" = 1 ] || exit 0
    MSG='MANDATORY: graphify-out/graph.json exists. You MUST run graphify before reading source files. Use: `graphify query \"<question>\"` (scoped subgraph), `graphify explain \"<concept>\"`, or `graphify path \"<A>\" \"<B>\"`. Only read raw files after graphify has oriented you, or to modify/debug specific lines. This rule applies to subagents too — include it in every subagent prompt involving code exploration.'
fi

printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"%s"}}\n' "$MSG"
