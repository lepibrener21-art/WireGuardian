import base64
import ipaddress
from typing import Set, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def generate_keypair() -> Tuple[str, str]:
    """Return (private_key_b64, public_key_b64) compatible with WireGuard."""
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return (
        base64.b64encode(priv_bytes).decode(),
        base64.b64encode(pub_bytes).decode(),
    )


def allocate_ip(subnet: str, used: Set[str]) -> str:
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(network.hosts())
    # .1 is reserved for the server interface
    server_ip = str(hosts[0])
    for host in hosts:
        ip = str(host)
        if ip != server_ip and ip not in used:
            return ip
    raise RuntimeError("No available IPs in subnet")


def render_client_config(
    client_private_key: str,
    client_ip: str,
    server_public_key: str,
    server_endpoint: str,
    dns: str = "1.1.1.1",
) -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {client_private_key}\n"
        f"Address = {client_ip}/32\n"
        f"DNS = {dns}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"Endpoint = {server_endpoint}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    )


def render_server_peer_stanza(client_public_key: str, client_ip: str) -> str:
    return (
        "[Peer]\n"
        f"PublicKey = {client_public_key}\n"
        f"AllowedIPs = {client_ip}/32\n"
    )


def generate_self_signed_cert(cert_path: str, key_path: str, hostname: str = "wireguardian") -> None:
    """Generate a self-signed TLS certificate and private key using the cryptography library."""
    import datetime
    import os

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        Encoding,
        PrivateFormat,
    )
    from cryptography.x509.oid import NameOID

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(rsa_key, hashes.SHA256())
    )

    os.makedirs(os.path.dirname(cert_path) or ".", exist_ok=True)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(
            rsa_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )
        )

    os.chmod(key_path, 0o600)
