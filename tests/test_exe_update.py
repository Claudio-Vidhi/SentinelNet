# -*- coding: utf-8 -*-
"""Aggiornamento da release GitHub: qui si scarica ed ESEGUE un binario.

I test che contano sono quelli che dicono quando NON si esegue: impronta
sbagliata, impronta assente, privilegi assenti. Il caso felice e' il meno
interessante dei tre.
"""
import hashlib
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from services import exe_update


def _release(version="9.9.9", digest="", url=None):
    return {"version": version,
            "asset_name": f"SentinelNet-Setup-{version}.exe",
            "url": url or f"https://github.com/x/y/releases/download/v{version}/s.exe",
            "digest": digest,
            "size": 10}


class _FakeResponse:
    """Risposta streaming minima, col context manager che usa requests."""

    def __init__(self, chunks):
        self._chunks = chunks

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=None):
        return iter(self._chunks)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestVersionCompare(unittest.TestCase):
    def test_newer_older_equal(self):
        self.assertTrue(exe_update.is_newer("0.34.0", "0.33.1"))
        self.assertTrue(exe_update.is_newer("1.0.0", "0.99.99"))
        self.assertFalse(exe_update.is_newer("0.33.1", "0.33.1"))
        self.assertFalse(exe_update.is_newer("0.33.0", "0.33.1"))

    def test_rubbish_is_not_newer(self):
        # Un tag che non si sa leggere non deve MAI far partire un
        # aggiornamento: nel dubbio si resta fermi.
        self.assertFalse(exe_update.is_newer("boh", "0.33.1"))
        self.assertFalse(exe_update.is_newer(None, "0.33.1"))


class TestDownloadVerification(unittest.TestCase):
    def test_matching_digest_is_kept(self):
        payload = b"installer bytes"
        rel = _release(digest=hashlib.sha256(payload).hexdigest())
        with tempfile.TemporaryDirectory() as d:
            with patch.object(exe_update.requests, "get",
                              return_value=_FakeResponse([payload])):
                path = exe_update.download_and_verify(rel, dest_dir=d)
            self.assertTrue(os.path.isfile(path))
            with open(path, "rb") as fh:
                self.assertEqual(fh.read(), payload)

    def test_wrong_digest_is_refused_and_the_file_deleted(self):
        rel = _release(digest="0" * 64)
        with tempfile.TemporaryDirectory() as d:
            with patch.object(exe_update.requests, "get",
                              return_value=_FakeResponse([b"tampered"])):
                with self.assertRaises(exe_update.ExeUpdateError) as ctx:
                    exe_update.download_and_verify(rel, dest_dir=d)
            self.assertIn("impronta", str(ctx.exception).lower())
            # Niente deve restare in giro da eseguire per sbaglio.
            self.assertEqual(os.listdir(d), [])

    def test_missing_digest_refuses_before_downloading(self):
        rel = _release(digest="")
        with patch.object(exe_update.requests, "get") as get:
            with self.assertRaises(exe_update.ExeUpdateError):
                exe_update.download_and_verify(rel)
        get.assert_not_called()


class TestLatestRelease(unittest.TestCase):
    def _api(self, assets, tag="v9.9.9"):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"tag_name": tag, "assets": assets}
        return resp

    def test_picks_the_installer_and_parses_the_digest(self):
        assets = [
            {"name": "notes.txt", "browser_download_url": "https://github.com/a",
             "digest": "sha256:" + "a" * 64, "size": 1},
            {"name": "SentinelNet-Setup-9.9.9.exe",
             "browser_download_url":
                 "https://github.com/o/r/releases/download/v9.9.9/x.exe",
             "digest": "sha256:" + "b" * 64, "size": 42},
        ]
        with patch.object(exe_update.requests, "get", return_value=self._api(assets)):
            rel = exe_update.latest_release()
        self.assertEqual(rel["version"], "9.9.9")
        self.assertEqual(rel["digest"], "b" * 64)

    def test_non_github_url_is_refused(self):
        assets = [{"name": "SentinelNet-Setup-9.9.9.exe",
                   "browser_download_url": "https://example.invalid/x.exe",
                   "digest": "sha256:" + "b" * 64, "size": 1}]
        with patch.object(exe_update.requests, "get", return_value=self._api(assets)):
            with self.assertRaises(exe_update.ExeUpdateError):
                exe_update.latest_release()

    def test_release_without_an_installer_says_so(self):
        with patch.object(exe_update.requests, "get",
                          return_value=self._api([{"name": "README.md"}])):
            with self.assertRaises(exe_update.ExeUpdateError):
                exe_update.latest_release()


class TestUpdateRefusals(unittest.TestCase):
    def test_without_the_service_nothing_is_downloaded(self):
        # Il rifiuto arriva PRIMA della rete: l'installer chiederebbe
        # privilegi che non ci sono, e scaricarlo sarebbe lavoro sprecato.
        with patch.object(exe_update.sys, "platform", "win32"), \
             patch.object(exe_update, "latest_release") as latest, \
             patch.object(exe_update, "spawn_installer") as spawn:
            with self.assertRaises(exe_update.ExeUpdateError) as ctx:
                exe_update.update("")
        latest.assert_not_called()
        spawn.assert_not_called()
        self.assertIn("servizio", str(ctx.exception).lower())

    def test_already_current_does_not_download(self):
        from core.version import __version__
        with patch.object(exe_update.sys, "platform", "win32"), \
             patch.object(exe_update, "latest_release",
                          return_value=_release(version=__version__,
                                                digest="c" * 64)), \
             patch.object(exe_update, "download_and_verify") as dl, \
             patch.object(exe_update, "spawn_installer") as spawn:
            out = exe_update.update("windows-service")
        self.assertEqual(out["status"], "up-to-date")
        dl.assert_not_called()
        spawn.assert_not_called()

    def test_newer_version_downloads_then_launches_with_mergetasks(self):
        with patch.object(exe_update.sys, "platform", "win32"), \
             patch.object(exe_update, "latest_release",
                          return_value=_release(version="99.0.0", digest="c" * 64)), \
             patch.object(exe_update, "download_and_verify",
                          return_value=r"C:\tmp\SentinelNet-Setup-99.0.0.exe"), \
             patch.object(exe_update.subprocess, "Popen") as popen:
            out = exe_update.update("windows-service")
        self.assertEqual(out["status"], "updating")
        args = popen.call_args[0][0]
        self.assertIn("/VERYSILENT", args)
        # Senza questo un aggiornamento silenzioso lascerebbe il servizio
        # deregistrato: in silent mode i task tornano ai default.
        self.assertIn("/MERGETASKS=service", args)


if __name__ == "__main__":
    unittest.main()
