import glob, os

def frontend_source() -> str:
    """Sorgente frontend completo: dashboard.html + tutti i file static/.
    I test 'grep-style' devono usare questo, non il solo dashboard.html."""
    base = os.path.dirname(__file__)
    parts = [open(os.path.join(base, "templates", "dashboard.html"),
                  encoding="utf-8").read()]
    for p in glob.glob(os.path.join(base, "static", "**", "*.*"), recursive=True):
        if p.endswith((".js", ".css")):
            parts.append(open(p, encoding="utf-8").read())
    return "\n".join(parts)
