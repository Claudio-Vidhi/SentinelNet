# -*- coding: utf-8 -*-
"""The standalone restore script uploaded next to the manifest.

Kept as a string, not a module: it is data to be shipped, and it must not
import anything from this repository. A backup that needs the software that
produced it is a backup with a dependency nobody wrote down.
"""

RESTORE_SCRIPT = '''#!/usr/bin/env python3
"""Rebuild a SentinelNet configuration archive from this folder.

    python restore.py --source . --target ./restored [--key-file fernet.key]

Reads _manifest.json, copies every listed file into --target, decrypting when
the manifest says the archive is encrypted. Requires only Python 3 (plus the
`cryptography` package for an encrypted archive).
"""
import argparse
import json
import os
import sys


def main():
    ap = argparse.ArgumentParser(description="Restore a SentinelNet backup archive")
    ap.add_argument("--source", default=".", help="folder holding _manifest.json")
    ap.add_argument("--target", required=True, help="where to write the rebuilt tree")
    ap.add_argument("--key-file", help="Fernet key file, for an encrypted archive")
    args = ap.parse_args()

    manifest_path = os.path.join(args.source, "_manifest.json")
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except OSError as exc:
        print("cannot read %s: %s" % (manifest_path, exc), file=sys.stderr)
        return 2

    encrypted = bool(manifest.get("encrypted"))
    decrypt = None
    if encrypted:
        if not args.key_file:
            print("this archive is encrypted: pass --key-file with the Fernet key",
                  file=sys.stderr)
            return 2
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            print("an encrypted archive needs the 'cryptography' package: "
                  "pip install cryptography", file=sys.stderr)
            return 2
        with open(args.key_file, "rb") as fh:
            decrypt = Fernet(fh.read().strip()).decrypt

    written = failed = 0
    for rel in sorted(manifest.get("files") or {}):
        remote_rel = rel + ".enc" if encrypted else rel
        src = os.path.join(args.source, *remote_rel.split("/"))
        dst = os.path.join(args.target, *rel.split("/"))
        try:
            with open(src, "rb") as fh:
                data = fh.read()
            if decrypt is not None:
                data = decrypt(data)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as fh:
                fh.write(data)
            written += 1
        except Exception as exc:
            print("FAILED %s: %s" % (rel, exc), file=sys.stderr)
            failed += 1

    print("restored %d file(s), %d failed, into %s" % (written, failed, args.target))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
'''
