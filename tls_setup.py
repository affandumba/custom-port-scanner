import ssl

def create_server_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")
    return context

def create_client_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context