# -*- coding: utf-8 -*-
"""Le due funzioni pure di scripts/dev/release.py.

Il resto dello script sono comandi git, che si verificano eseguendolo. Queste
due invece decidono che numero porta la release e cosa finisce nelle note:
sbagliarle significa pubblicare una versione con il changelog di un'altra.
"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "dev"))

import release  # noqa: E402

CHANGELOG = """# Changelog

Bla bla.

## [Unreleased]

### Added

- Una cosa nuova.

## [0.27.1] - 2026-09-02

### Fixed

- Una cosa rotta.
"""


class BumpVersion(unittest.TestCase):
    def test_patch_minor_major(self):
        self.assertEqual(release.bump_version("0.27.1", "patch"), "0.27.2")
        self.assertEqual(release.bump_version("0.27.1", "minor"), "0.28.0")
        self.assertEqual(release.bump_version("0.27.1", "major"), "1.0.0")

    def test_minor_and_major_reset_what_is_below(self):
        # 0.27.1 -> 0.28.1 sarebbe un numero che in SemVer non vuol dire nulla.
        self.assertEqual(release.bump_version("1.9.9", "minor"), "1.10.0")
        self.assertEqual(release.bump_version("1.9.9", "major"), "2.0.0")

    def test_an_unknown_part_is_refused(self):
        with self.assertRaises(ValueError):
            release.bump_version("0.27.1", "revision")


class PromoteChangelog(unittest.TestCase):
    def test_the_unreleased_body_becomes_the_new_section(self):
        out = release.promote_changelog(CHANGELOG, "0.28.0", "2026-09-03")
        self.assertIn("## [0.28.0] - 2026-09-03", out)
        self.assertIn("- Una cosa nuova.", out.split("## [0.27.1]")[0])

    def test_unreleased_survives_empty_for_the_next_change(self):
        # Senza l'intestazione, la modifica successiva non ha dove atterrare.
        out = release.promote_changelog(CHANGELOG, "0.28.0", "2026-09-03")
        self.assertIn("## [Unreleased]", out)
        self.assertEqual(release.unreleased_body(out), "")

    def test_the_previous_release_is_left_alone(self):
        out = release.promote_changelog(CHANGELOG, "0.28.0", "2026-09-03")
        self.assertIn("## [0.27.1] - 2026-09-02", out)
        self.assertIn("- Una cosa rotta.", out)

    def test_an_empty_unreleased_is_refused(self):
        # Rilasciare senza note produce una Release GitHub vuota, che e' peggio
        # di non averla: dice che non e' cambiato niente.
        empty = CHANGELOG.replace("### Added\n\n- Una cosa nuova.\n\n", "")
        with self.assertRaises(ValueError):
            release.promote_changelog(empty, "0.28.0", "2026-09-03")

    def test_the_real_changelog_still_matches_the_expected_shape(self):
        # Il formato vero, non solo la fixture: se il CHANGELOG cambia stile
        # lo script deve fallire qui, non a meta' di una release.
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [Unreleased]", text)
        if release.unreleased_body(text):
            out = release.promote_changelog(text, "9.9.9", "2026-01-01")
            self.assertIn("## [9.9.9] - 2026-01-01", out)


if __name__ == "__main__":
    unittest.main()
