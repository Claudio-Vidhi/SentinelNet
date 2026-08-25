# -*- coding: utf-8 -*-
"""Offsite mirror of backup-config/ to an SFTP host.

The local archive stays the source of truth: nothing in the app ever reads
from the remote. See docs/superpowers/specs/2026-08-25-cloud-backup-design.md.
"""
