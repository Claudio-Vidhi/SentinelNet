# -*- coding: utf-8 -*-
"""Optional git mirror of the config archive — redundancy, not a backend.

The '.history' archive is the source of truth and the only thing the drift
engine reads. This module keeps a second copy in a git repository so the
archive survives losing the folder. Nothing here is ever read back.
"""
import logging
import os
import shutil
import subprocess

_SETTING = "config_drift_git_mirror"


class MirrorUnavailable(Exception):
    """git is not usable on this host, so the mirror cannot be turned on."""


def _git() -> str:
    path = shutil.which("git")
    if not path:
        raise MirrorUnavailable(
            "git non e' installato su questo host: il mirror di ridondanza "
            "non puo' essere attivato.")
    return path


def is_enabled() -> bool:
    from core.app_settings import get_app_settings
    return bool(get_app_settings().get(_SETTING))


def enable() -> None:
    """Turn the mirror on, refusing if git is missing."""
    from core.app_settings import get_app_settings, save_app_settings
    _git()
    settings = get_app_settings()
    settings[_SETTING] = True
    save_app_settings(settings)


def disable() -> None:
    from core.app_settings import get_app_settings, save_app_settings
    settings = get_app_settings()
    settings[_SETTING] = False
    save_app_settings(settings)


def commit_version(device: dict, filename: str) -> None:
    """Commit one archived version. Never raises into the collection path."""
    if not is_enabled():
        return
    from services.config_drift import history
    try:
        repo = history.history_dir(device)
        git = _git()
        if not os.path.isdir(os.path.join(repo, ".git")):
            subprocess.run([git, "init", "-q"], cwd=repo, check=True)
        subprocess.run([git, "add", "--", filename], cwd=repo, check=True)
        subprocess.run([git, "commit", "-q", "-m", f"{device.get('IP')} {filename}"],
                       cwd=repo, check=True)
    except (OSError, subprocess.SubprocessError, MirrorUnavailable) as e:
        logging.warning(f"Mirror git non aggiornato per {device.get('IP')}: {e}")
