"""
service_detector.py
──────────────────────────────────────────────
Service detection via:
  1. Well-known port → service name mapping
  2. Banner grabbing with per-protocol probes
"""

import socket

# ──────────────────────────────────────────────
# Port → service name (expanded list)
# ──────────────────────────────────────────────
PORT_SERVICES = {
    20:    "FTP-Data",
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    67:    "DHCP",
    68:    "DHCP",
    80:    "HTTP",
    110:   "POP3",
    119:   "NNTP",
    123:   "NTP",
    135:   "MS-RPC",
    137:   "NetBIOS-NS",
    138:   "NetBIOS-DGM",
    139:   "NetBIOS-SSN",
    143:   "IMAP",
    161:   "SNMP",
    194:   "IRC",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    514:   "Syslog",
    587:   "SMTP-Submission",
    636:   "LDAPS",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "Oracle-DB",
    2181:  "Zookeeper",
    2375:  "Docker",
    2376:  "Docker-TLS",
    3000:  "Dev-Server",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit",
    5000:  "Dev-Server",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    6443:  "Kubernetes-API",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch-Cluster",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    50070: "Hadoop-HDFS",
}

# ──────────────────────────────────────────────
# Per-port probes to elicit a banner
# None = just recv (service sends banner first, e.g. FTP/SSH/SMTP)
# ──────────────────────────────────────────────
SERVICE_PROBES = {
    21:    None,
    22:    None,
    23:    None,
    25:    None,
    80:    b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:   None,
    143:   None,
    443:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    587:   None,
    993:   None,
    995:   None,
    3306:  None,
    5432:  None,
    6379:  b"PING\r\n",
    8080:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    9200:  b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    11211: b"version\r\n",
    27017: None,
}


def get_service_name(port: int) -> str:
    """Return service name for well-known port, else 'Unknown'."""
    return PORT_SERVICES.get(port, "Unknown")


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """
    Connect to host:port and attempt to read a banner.
    Sends a probe if one is defined for the port.
    Returns the first line of the response (max 120 chars), or '' on failure.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            probe = SERVICE_PROBES.get(port, b"")   # None or bytes
            if probe:
                s.sendall(probe)

            raw = s.recv(1024).decode(errors="replace").strip()
            first_line = raw.splitlines()[0] if raw else ""
            return first_line[:120]

    except Exception:
        return ""


def detect_service(host: str, port: int, timeout: float = 2.0) -> dict:
    """
    Return {'service': str, 'banner': str} for an open port.
    """
    service = get_service_name(port)
    banner  = grab_banner(host, port, timeout)
    return {
        "service": service,
        "banner":  banner if banner else "N/A",
    }
