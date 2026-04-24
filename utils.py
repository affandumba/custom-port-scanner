"""
utils.py
──────────────────────────────────────────────
Shared helpers used across server, client, and scanner:
  - resolve_host()         : hostname → IP
  - validate_port_range()  : check port range bounds
  - format_scan_summary()  : pretty-print scan results to terminal
  - save_results()         : save scan results to JSON and/or TXT
  - safe_recv_all()        : receive large responses from a socket
  - timestamp()            : ISO timestamp string
"""

import socket
import json
import os
from datetime import datetime


# ──────────────────────────────────────────────
# Network helpers
# ──────────────────────────────────────────────

def resolve_host(host: str) -> str:
    """
    Resolve hostname to IP. Returns IP string.
    Raises ValueError if unresolvable.
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve host '{host}': {e}")


def validate_port_range(start_port: int, end_port: int):
    """
    Validate port range is within 1–65535 and start <= end.
    Raises ValueError with a descriptive message if invalid.
    """
    if not isinstance(start_port, int) or not isinstance(end_port, int):
        raise ValueError("Port numbers must be integers.")
    if not (1 <= start_port <= 65535):
        raise ValueError(f"Start port {start_port} out of range (1–65535).")
    if not (1 <= end_port <= 65535):
        raise ValueError(f"End port {end_port} out of range (1–65535).")
    if start_port > end_port:
        raise ValueError(f"Start port ({start_port}) must be ≤ end port ({end_port}).")


# ──────────────────────────────────────────────
# Output formatters
# ──────────────────────────────────────────────

def format_scan_summary(scan_result: dict) -> str:
    """
    Return a human-readable summary string from a complete scan result dict.
    """
    target     = scan_result.get("target", "N/A")
    mode       = scan_result.get("mode", "N/A")
    total_time = scan_result.get("total_scan_time_sec", 0)
    results    = scan_result.get("results", [])

    open_ports  = [r for r in results if r.get("status") == "open"]
    closed      = [r for r in results if r.get("status") == "closed"]
    timeouts    = [r for r in results if r.get("status") == "timeout"]
    errors      = [r for r in results if r.get("status") == "error"]

    lines = [
        "=" * 60,
        "  SCAN SUMMARY",
        "=" * 60,
        f"  Target        : {target}",
        f"  Mode          : {mode}",
        f"  Total Time    : {total_time}s",
        f"  Ports Scanned : {len(results)}",
        f"  Open          : {len(open_ports)}",
        f"  Closed        : {len(closed)}",
        f"  Timed Out     : {len(timeouts)}",
        f"  Errors        : {len(errors)}",
        "=" * 60,
    ]

    if open_ports:
        lines.append("  OPEN PORTS DETAIL:")
        lines.append(f"  {'PORT':<8} {'SERVICE':<18} {'LATENCY':>10}  BANNER")
        lines.append("  " + "-" * 56)
        for r in sorted(open_ports, key=lambda x: x["port"]):
            port    = r["port"]
            svc     = r.get("service", "Unknown")
            latency = r.get("latency_ms", "N/A")
            banner  = r.get("banner", "N/A")
            lines.append(f"  {port:<8} {svc:<18} {str(latency)+' ms':>10}  {banner}")

    lines.append("=" * 60)
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Save results to file
# ──────────────────────────────────────────────

def save_results(scan_result: dict, output_dir: str = "scan_results") -> dict:
    """
    Save scan results to both JSON and TXT files.

    Files are named:  <target>_<timestamp>.json / .txt
    inside output_dir (created if it doesn't exist).

    Returns {'json': path, 'txt': path}
    """
    os.makedirs(output_dir, exist_ok=True)

    target = scan_result.get("target", "unknown").replace(".", "_")
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    base   = os.path.join(output_dir, f"{target}_{ts}")

    json_path = base + ".json"
    txt_path  = base + ".txt"

    # ── JSON ──────────────────────────────────
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=2)

    # ── TXT (human-readable) ──────────────────
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(format_scan_summary(scan_result))
        f.write("\n\nFULL RESULTS (all ports):\n")
        f.write(f"{'PORT':<8} {'STATUS':<10} {'SERVICE':<18} {'LATENCY':>10}  BANNER\n")
        f.write("-" * 70 + "\n")
        for r in scan_result.get("results", []):
            f.write(
                f"{r['port']:<8} {r['status']:<10} {r.get('service','N/A'):<18} "
                f"{str(r.get('latency_ms','N/A'))+' ms':>10}  {r.get('banner','N/A')}\n"
            )

    return {"json": json_path, "txt": txt_path}


# ──────────────────────────────────────────────
# Socket helpers
# ──────────────────────────────────────────────

def safe_recv_all(sock, buffer_size: int = 65536, timeout: float = 30.0) -> bytes:
    """
    Receive a potentially large response from a socket in chunks.
    Stops when the connection closes or the socket times out.
    Returns raw bytes.
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
    return b"".join(chunks)


def timestamp() -> str:
    """Return current timestamp as a readable ISO string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
