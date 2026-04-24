"""
generate_cert.py
──────────────────────────────────────────────
Generates self-signed TLS certificates for BOTH server and client.
  Mutual TLS (mTLS) — both sides authenticate each other.

Output:
  certs/server.crt  — Server certificate (PEM)
  certs/server.key  — Server private key (PEM)
  certs/client.crt  — Client certificate (PEM)
  certs/client.key  — Client private key (PEM)
  certs/ca.crt      — CA certificate (signs both)
  certs/ca.key      — CA private key

Run once before starting server or client:
    python generate_cert.py
"""

import os
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

os.makedirs("certs", exist_ok=True)


# ──────────────────────────────────────────────
# Helper — generate RSA key
# ──────────────────────────────────────────────
def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def save_key(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


# ──────────────────────────────────────────────
# Step 1 — Generate CA (Certificate Authority)
# This CA will sign both server and client certs
# ──────────────────────────────────────────────
print("Generating CA certificate...")
ca_key = generate_key()
save_key(ca_key, "certs/ca.key")

ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME,           "IN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,      "Port Scanner CA"),
    x509.NameAttribute(NameOID.COMMON_NAME,            "Port Scanner Root CA"),
])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)
save_cert(ca_cert, "certs/ca.crt")
print("  ✅ certs/ca.crt + certs/ca.key")


# ──────────────────────────────────────────────
# Step 2 — Generate Server Certificate
# ──────────────────────────────────────────────
print("Generating server certificate...")
server_key = generate_key()
save_key(server_key, "certs/server.key")

server_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME,           "IN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
    x509.NameAttribute(NameOID.LOCALITY_NAME,          "Bengaluru"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,      "Custom Port Scanner"),
    x509.NameAttribute(NameOID.COMMON_NAME,            "PortScannerServer"),
])

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_name)
    .issuer_name(ca_cert.subject)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    )
    .sign(ca_key, hashes.SHA256())   # signed by CA
)
save_cert(server_cert, "certs/server.crt")
print("  ✅ certs/server.crt + certs/server.key")


# ──────────────────────────────────────────────
# Step 3 — Generate Client Certificate
# ──────────────────────────────────────────────
print("Generating client certificate...")
client_key = generate_key()
save_key(client_key, "certs/client.key")

client_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME,           "IN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
    x509.NameAttribute(NameOID.LOCALITY_NAME,          "Bengaluru"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,      "Custom Port Scanner"),
    x509.NameAttribute(NameOID.COMMON_NAME,            "PortScannerClient"),
])

client_cert = (
    x509.CertificateBuilder()
    .subject_name(client_name)
    .issuer_name(ca_cert.subject)
    .public_key(client_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=False,
    )
    .sign(ca_key, hashes.SHA256())   # signed by same CA
)
save_cert(client_cert, "certs/client.crt")
print("  ✅ certs/client.crt + certs/client.key")


print("\n✅ All certificates generated successfully!")
print("\nFiles in certs/:")
print("   ca.crt      — CA certificate (share with both server & client)")
print("   server.crt  — Server certificate")
print("   server.key  — Server private key (keep secret!)")
print("   client.crt  — Client certificate")
print("   client.key  — Client private key (keep secret!)")
print("\n⚠️  Share ca.crt + client.crt + client.key with your friend (Manoj)")
