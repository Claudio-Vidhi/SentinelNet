# -*- coding: utf-8 -*-
"""SFTP transport. The only module here that imports paramiko.

Two rules carry the security of the whole feature:
  - the host key is pinned. AutoAddPolicy with no pin is how a redirected DNS
    entry turns a backup into an exfiltration channel;
  - every upload lands on a temporary name and is renamed into place, so an
    interrupted transfer never leaves a truncated config looking current.
"""

import base64
import hashlib
import posixpath

import paramiko


class HostKeyMismatch(Exception):
    """The server presented a key different from the pinned fingerprint."""


def _fingerprint(host_key) -> str:
    b64 = host_key.get_base64()
    b64 += "=" * (-len(b64) % 4)  # tolerate unpadded base64 from some clients
    digest = hashlib.sha256(base64.b64decode(b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class SftpTarget:

    def __init__(self, ssh, client, pinned_fingerprint: str = ""):
        self._ssh = ssh
        self._client = client
        self.pinned_fingerprint = pinned_fingerprint
        self.fingerprint = _fingerprint(ssh.get_transport().get_remote_server_key())
        self._known_dirs: set = set()

    def verify_host_key(self) -> None:
        if self.pinned_fingerprint and self.pinned_fingerprint != self.fingerprint:
            raise HostKeyMismatch(
                f"host key {self.fingerprint} does not match pinned "
                f"{self.pinned_fingerprint}")

    def ensure_dir(self, remote_dir: str) -> None:
        path = ""
        for part in [p for p in remote_dir.strip("/").split("/") if p]:
            path = f"{path}/{part}"
            if path in self._known_dirs:
                continue
            try:
                self._client.stat(path)
            except IOError:
                self._client.mkdir(path)
            self._known_dirs.add(path)

    def put(self, data: bytes, remote_path: str) -> None:
        self.ensure_dir(posixpath.dirname(remote_path))
        tmp = remote_path + ".part"
        with self._client.open(tmp, "wb") as fh:
            fh.write(data)
        self._client.posix_rename(tmp, remote_path)

    def size(self, remote_path: str) -> int | None:
        try:
            return self._client.stat(remote_path).st_size
        except IOError:
            return None

    def get(self, remote_path: str) -> bytes:
        with self._client.open(remote_path, "rb") as fh:
            return fh.read()

    def close(self) -> None:
        try:
            self._client.close()
        finally:
            self._ssh.close()


def open_target(cfg: dict) -> SftpTarget:
    """Connects with the operator's key or password. The key file is read,
    never created or rewritten."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": cfg["host"], "port": int(cfg.get("port") or 22),
        "username": cfg["username"], "timeout": 20, "allow_agent": False,
        "look_for_keys": False,
    }
    if cfg.get("auth") == "key":
        kwargs["key_filename"] = cfg["key_path"]
        if cfg.get("key_passphrase"):
            kwargs["passphrase"] = cfg["key_passphrase"]
    else:
        kwargs["password"] = cfg.get("password") or ""
    ssh.connect(**kwargs)
    target = SftpTarget(ssh, ssh.open_sftp(),
                        pinned_fingerprint=cfg.get("host_key_fingerprint") or "")
    try:
        target.verify_host_key()
    except HostKeyMismatch:
        target.close()
        raise
    return target
