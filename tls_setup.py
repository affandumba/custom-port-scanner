"""
tls_setup.py
──────────────────────────────────────────────
Centralised SSL context builders.
Used by both server.py and client.py so SSL config
is defined in one place.
"""

import ssl


def create_server_ssl_context() -> ssl.SSLContext:
    """
    Server-side SSL context.
    Loads the self-signed certificate and private key from certs/.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")
    return ctx


def create_client_ssl_context() -> ssl.SSLContext:
    """
    Client-side SSL context.
    Skips hostname/cert verification for self-signed certs (development use).
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx
