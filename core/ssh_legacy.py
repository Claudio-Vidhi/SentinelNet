# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""SHA-1 SSH algorithms, offered only as a fallback.

paramiko 5 deleted the SHA-1 key exchanges and the ssh-rsa host key. Older
Cisco IOS switches speak nothing else (observed offer: kex group14-sha1 and
group-exchange-sha1, host key ssh-rsa), so with paramiko 5 alone they fail at
the handshake with "Incompatible ssh peer (no acceptable kex algorithm)".

Two pieces:

- install() puts the implementations back. The DH groups and the exchange
  are paramiko's own sha256 classes; only the hash differs, which those
  classes already read from ``hash_algo``.
- with_fallback() keeps them out of the first attempt (disabled_algorithms),
  and retries with them only when the device rejected every modern
  algorithm. A device that speaks anything modern never sees SHA-1 offered.

This reaches into paramiko internals (_kex_info, _key_info, the preferred
tuples, RSAKey.HASHES). tests/test_ssh_legacy_algorithms.py fails the day a
paramiko release moves them, which is why pyproject pins the major version.
"""
import logging
from hashlib import sha1
from typing import Any

import paramiko
from cryptography.hazmat.primitives import hashes
from paramiko.kex_gex import KexGexSHA256
from paramiko.kex_group14 import KexGroup14SHA256
from paramiko.rsakey import RSAKey

logger = logging.getLogger("sentinelnet.ssh")


class KexGroup14SHA1(KexGroup14SHA256):
    name = "diffie-hellman-group14-sha1"
    hash_algo = sha1


class KexGexSHA1(KexGexSHA256):
    name = "diffie-hellman-group-exchange-sha1"
    hash_algo = sha1


class KexGroup1SHA1(KexGroup14SHA1):
    # Oakley group 2, RFC 2409 sec. 6.2: 1024-bit, the only kex older IOS
    # 12.x offers. Offered last of all.
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF  # noqa
    name = "diffie-hellman-group1-sha1"


LEGACY_KEX = (KexGroup14SHA1.name, KexGexSHA1.name, KexGroup1SHA1.name)
LEGACY_KEYS = ("ssh-rsa",)
# What the first attempt leaves out.
MODERN_ONLY = {"kex": list(LEGACY_KEX), "keys": list(LEGACY_KEYS)}


def install() -> None:
    # Any: these are paramiko internals, absent from its type stubs.
    T: Any = paramiko.Transport
    for cls in (KexGroup14SHA1, KexGexSHA1, KexGroup1SHA1):
        T._kex_info[cls.name] = cls
    T._preferred_kex = tuple(T._preferred_kex) + tuple(
        k for k in LEGACY_KEX if k not in T._preferred_kex)
    T._key_info["ssh-rsa"] = RSAKey
    if "ssh-rsa" not in T._preferred_keys:
        T._preferred_keys = tuple(T._preferred_keys) + ("ssh-rsa",)
    RSAKey.HASHES.setdefault("ssh-rsa", hashes.SHA1)


def is_negotiation_failure(exc: BaseException) -> bool:
    """True when the device and our modern list had nothing in common.

    netmiko re-raises paramiko's IncompatiblePeer as its own exception with
    the original text inside, so the message is what survives both paths.
    """
    e = exc
    while e is not None:
        if isinstance(e, paramiko.ssh_exception.IncompatiblePeer):
            return True
        e = e.__cause__ or e.__context__
    text = str(exc)
    return "Incompatible ssh peer" in text or "no acceptable" in text


def merged(disabled: "dict | None", extra: "dict | None") -> "dict | None":
    """Caller's own disabled_algorithms plus ``extra``."""
    if not extra:
        return disabled
    out = {k: list(v) for k, v in (disabled or {}).items()}
    for k, v in extra.items():
        out[k] = list(dict.fromkeys(out.get(k, []) + list(v)))
    return out


# Any: _really_parse_kex_init is a paramiko internal, absent from its stubs.
_Transport: Any = paramiko.Transport


class OfferTransport(_Transport):
    """A Transport that keeps the device's KEXINIT.

    paramiko drops the offer once negotiation fails, so the terminal could
    only say "no acceptable kex algorithm" without naming what the device
    wanted. Pass as SSHClient.connect(transport_factory=OfferTransport).
    """
    remote_offer: "dict | None" = None

    def _really_parse_kex_init(self, m, ignore_first_byte=False):
        parsed = super()._really_parse_kex_init(m, ignore_first_byte)
        # ignore_first_byte=True is _get_latest_kex_init re-reading a stored
        # message, possibly our own; only the incoming one is the device's.
        if not ignore_first_byte:
            self.remote_offer = parsed
        return parsed


def describe_offer(offer: dict) -> str:
    """The device's offer per category, flagging any we cannot speak at all."""
    T: Any = paramiko.Transport
    rows = (("kex", "kex_algo_list", T._kex_info),
            ("host key", "server_key_algo_list", T._key_info),
            ("cipher", "client_encrypt_algo_list", T._cipher_info),
            ("mac", "client_mac_algo_list", T._mac_info))
    lines = []
    for label, field, known in rows:
        algos = offer.get(field) or []
        miss = "" if any(a in known for a in algos) else "   <-- non supportato"
        lines.append(f"  {label}: {', '.join(algos)}{miss}")
    return "\r\n".join(lines)


# Hosts that refused the modern list once. Without it every session to such a
# device costs a refused handshake, and paramiko logs a traceback for each.
# ponytail: process memory only - a restart re-learns it with one refusal, and
# a device upgraded in place stays on the fallback list until then.
_needs_legacy: "set[str]" = set()


def with_fallback(attempt, host: str = ""):
    """attempt(extra_disabled) -> connection. Modern first, SHA-1 on refusal."""
    if host not in _needs_legacy:
        try:
            return attempt(MODERN_ONLY)
        except Exception as e:
            if not is_negotiation_failure(e):
                raise
        logger.warning("SSH %s: no modern algorithm in common, retrying with SHA-1 "
                       "key exchange / ssh-rsa host key", host)
        if host:
            _needs_legacy.add(host)
    return attempt(None)


install()
