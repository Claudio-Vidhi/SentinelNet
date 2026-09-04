# -*- coding: utf-8 -*-
"""Self-signed certificate for the panel's own HTTPS listener.

Lifted out of routers/settings.py: building an X.509 certificate is not an
HTTP concern, and the route was 80 lines of key generation between a pydantic
model and a response dict.

Built with `cryptography`, already a hard dependency (crypto_vault uses it).
Shelling out to `openssl` meant hoping it was on PATH -- on Windows it
normally is not -- and macOS ships LibreSSL, which rejects -addext. This
behaves identically on every operating system.
"""
import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from core import data_config

# Un certificato self-signed di lunga durata: 825 giorni e' il tetto che i
# client accettano per un certificato emesso a mano.
VALIDITY_DAYS = 825

# Solo un IPv4 letterale o un nome DNS: e' cio' che un SAN puo' contenere, e
# un host fuori da queste due forme e' un errore di battitura, non un caso
# d'uso. La validazione resta anche ora che il certificato non passa piu' da
# una riga di comando.
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DNS_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class CertError(Exception):
    """Rifiuto atteso della generazione.

    Porta il codice HTTP perche' i due casi non sono lo stesso errore per chi
    chiama: un host malformato e' 400 e si corregge riscrivendolo, un
    certificato gia' presente e' 409 e si risolve archiviando i file."""

    def __init__(self, detail: str, status: int = 400):
        super().__init__(detail)
        self.status = status


def generate_self_signed(host: str) -> dict:
    """Genera certificato e chiave self-signed per questo host.

    Il subjectAltName porta l'indirizzo con cui i client contattano davvero il
    pannello: senza, ogni client moderno rifiuta il certificato qualunque sia
    il CN."""
    host = (host or "").strip()
    is_ip = bool(_IPV4_RE.match(host))
    if is_ip:
        if any(int(o) > 255 for o in host.split(".")):
            raise CertError("Indirizzo IPv4 non valido.")
    elif not (host and len(host) <= 253 and _DNS_RE.match(host)):
        raise CertError("Host non valido: usare un indirizzo IPv4 o un nome DNS.")

    certs_dir = data_config.get_path("certs")
    os.makedirs(certs_dir, exist_ok=True)
    certfile = os.path.join(certs_dir, "server.crt")
    keyfile = os.path.join(certs_dir, "server.key")
    if os.path.exists(certfile) or os.path.exists(keyfile):
        raise CertError(
            "Un certificato esiste gia'. Rimuovi o archivia "
            f"{certfile} e {keyfile} prima di generarne uno nuovo.", status=409)

    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    san = x509.IPAddress(ipaddress.ip_address(host)) if is_ip else x509.DNSName(host)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=VALIDITY_DAYS))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))

    # La chiave prima del certificato, e i permessi subito dopo averla scritta:
    # tra la creazione e restrict_permissions il file esiste con i permessi
    # ereditati dalla cartella, e quella finestra va tenuta corta.
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    # Non os.chmod: su Windows non restringe nulla e la chiave privata
    # resterebbe leggibile da chiunque erediti i permessi della cartella.
    # restrict_permissions usa icacls la' e chmod 600 su POSIX.
    data_config.restrict_permissions(keyfile)
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return {"certfile": certfile, "keyfile": keyfile, "days": VALIDITY_DAYS,
            "not_after": cert.not_valid_after_utc.isoformat()}
