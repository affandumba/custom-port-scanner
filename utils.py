import socket
import json
import time
from datetime import datetime


def resolve_host(host: str) -> str:
    """
    Resolve a hostname to an IP address.
    Returns the IP string, or raises an error if unresolvable.
    """
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve host '{host}': {e}")


def validate_port_range(start_port: int, end_port: int):
    """
    Validate that port range is within 1–65535 and start <= end.
    Raises ValueError if invalid.
    """
    if not (1 <= start_port <= 65535):
        raise ValueError(f"Start port {start_port} is out of range (1-65535)")
    if not (1 <= end_port <= 65535):
        raise ValueError(f"End port {end_port} is out of range (1-65535)")
    if start_port > end_port:
        raise ValueError(f"Start port {start_port} must be <= end port {end_port}")


def format_scan_summary(scan_result: dict) -> str:
    """
    Return a human-readable summary string from a scan result dict.
    """
    target      = scan_result.get("target", "N/A")
    ip          = scan_result.get("ip", "N/A")
    mode        = scan_result.get("mode", "N/A")
    total_time  = scan_result.get("total_scan_time_sec", 0)
    results     = scan_result.get("results", [])

    open_ports  = [r for r in results if r.get("status") == "open"]
    closed      = [r for r in results if r.get("status") == "closed"]
    timeouts    = [r for r in results if r.get("status") == "timeout"]

    lines = [
        "=" * 55,
        f"  SCAN SUMMARY",
        "=" * 55,
        f"  Target      : {target} ({ip})",
        f"  Mode        : {mode}",
        f"  Total Time  : {total_time}s",
        f"  Ports Scanned : {len(results)}",
        f"  Open        : {len(open_ports)}",
        f"  Closed      : {len(closed)}",
        f"  Timed Out   : {len(timeouts)}",
        "=" * 55,
    ]

    if open_ports:
        lines.append("  OPEN PORTS:")
        for r in open_ports:
            svc     = r.get("service", "Unknown")
            banner  = r.get("banner", "N/A")
            latency = r.get("latency_ms", "N/A")
            lines.append(f"    [{r['port']}]  {svc}  |  {banner}  |  {latency}ms")

    lines.append("=" * 55)
    return "\n".join(lines)


def timestamp() -> str:
    """Return current timestamp as ISO string."""
    return datetime.now().isoformat()


def safe_recv_all(sock, buffer_size: int = 65536, timeout: float = 10.0) -> str:
    """
    Receive potentially large responses from a socket in chunks.
    Stops when no more data arrives or timeout is hit.
    """
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = sock.recv(buffer_size)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout:
        pass
    return b"".join(chunks).decode(errors="replace")
