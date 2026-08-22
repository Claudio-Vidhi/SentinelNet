# -*- coding: utf-8 -*-
"""The two language dictionaries must stay the same shape.

Every other i18n test in this tree pins a hardcoded list of keys for one
feature, so a key added to `it` and forgotten in `en` is invisible until an
English user opens that panel and reads Italian. Nothing fails, nothing logs:
applyI18n simply leaves the element's literal text alone. These two checks are
the whole-file version, so the next forgotten key fails here instead.
"""

import glob
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
I18N_JS = os.path.join(ROOT, "static", "js", "i18n.js")

# Strip JS string literals before looking for keys: a ':' inside a translated
# sentence is not a key, and several keys share one line.
_STR = re.compile(r"""'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`""")
_KEY = re.compile(r"(?:^|[{,])[ ]*([A-Za-z_][A-Za-z0-9_]*)[ ]*:")

_REFS = [
    re.compile(r'data-i18n(?:-placeholder|-title|-aria-label)?="([A-Za-z0-9_]+)"'),
    re.compile(r"i18n\[[A-Za-z_][A-Za-z0-9_]*\]\.([A-Za-z0-9_]+)"),
    re.compile(r"""i18n\[[A-Za-z_][A-Za-z0-9_]*\]\[['"]([A-Za-z0-9_]+)"""),
]


def _lang_keys():
    """Return ({key: line} for `it`, {key: line} for `en`) from i18n.js."""
    lines = open(I18N_JS, encoding="utf-8").read().split("\n")
    starts = {}
    for n, line in enumerate(lines, 1):
        if line.strip() in ("it: {", "en: {"):
            starts[line.strip()[:2]] = n
    end = next(n for n, line in enumerate(lines, 1)
               if n > starts["en"] and line.rstrip() == "    }")

    def block(first, last):
        found = {}
        for n in range(first, last + 1):
            for key in _KEY.findall(_STR.sub("''", lines[n - 1])):
                found.setdefault(key, n)
        return found

    return (block(starts["it"] + 1, starts["en"] - 2),
            block(starts["en"] + 1, end - 1))


class LanguagesStayInSync(unittest.TestCase):
    def test_every_key_exists_in_both_languages(self):
        it, en = _lang_keys()
        self.assertGreater(len(it), 1000, "the it block was not parsed")
        only_it = sorted(k for k in it if k not in en)
        only_en = sorted(k for k in en if k not in it)
        self.assertEqual([], only_it, "keys missing from en: %s" % only_it)
        self.assertEqual([], only_en, "keys missing from it: %s" % only_en)

    def test_every_referenced_key_is_defined(self):
        """A data-i18n pointing at nothing leaves the element in whichever
        language the template happened to be written in, in both languages."""
        it, en = _lang_keys()
        files = (glob.glob(os.path.join(ROOT, "static", "js", "*.js"))
                 + glob.glob(os.path.join(ROOT, "templates", "*.html")))
        dangling = {}
        for path in files:
            if path.endswith("i18n.js"):
                continue
            rel = os.path.relpath(path, ROOT).replace("\\", "/")
            for n, line in enumerate(open(path, encoding="utf-8").read().split("\n"), 1):
                for pattern in _REFS:
                    for key in pattern.findall(line):
                        if key not in it and key not in en:
                            dangling.setdefault(key, "%s:%d" % (rel, n))
        self.assertEqual({}, dangling, "keys referenced but never defined: %s" % dangling)


if __name__ == "__main__":
    unittest.main()
