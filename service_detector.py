import socket

# ──────────────────────────────────────────────
# Well-known port → service name mapping
# ──────────────────────────────────────────────
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "MS-RPC",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    5900: "VNC", 161: "SNMP", 389: "LDAP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    5000: "Dev-Server", 9200: "Elasticsearch",
    2181: "Zookeeper", 11211: "Memcached",
    6443: "Kubernetes-API", 2375: "Docker", 2376: "Docker-TLS",
}

SERVICE_PROBES = {
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    21: None, 22: None, 25: None, 110: None, 143: None,
}


def get_service_name(port: int) -> str:
    return PORT_SERVICES.get(port, "Unknown")


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            probe = SERVICE_PROBES.get(port, b"")
            if probe:
                s.sendall(probe)
            banner = s.recv(1024).decode(errors="replace").strip()
            first_line = banner.splitlines()[0] if banner else ""
            return first_line[:120]
    except Exception:
        return ""


def detect_service(host: str, port: int, timeout: float = 2.0) -> dict:
    service_name = get_service_name(port)
    banner = grab_banner(host, port, timeout)
    return {
        "service": service_name,
        "banner": banner if banner else "N/A",
    }