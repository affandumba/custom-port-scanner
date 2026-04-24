"""
scanner.py
──────────────────────────────────────────────
Core port scanning engine.
  - scan_port()               : scans a single port with retries
  - scan_range_sequential()   : scans a range one-by-one
  - scan_range_concurrent()   : scans a range using a thread pool
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from service_detector import detect_service

# ──────────────────────────────────────────────
# Scan a single port
# ──────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float, retries: int = 1) -> dict:
    """
    Attempt to connect to (ip, port). Retries on timeout.
    Returns a result dict with status, latency, service, and banner.
    """
    last_status = "timeout"
    latency = 0.0

    for attempt in range(max(1, retries)):
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result_code = sock.connect_ex((ip, port))
            latency = round((time.time() - start) * 1000, 2)

            if result_code == 0:
                last_status = "open"
                break                      # open → no need to retry
            else:
                last_status = "closed"
                break                      # definitively closed → stop retrying

        except socket.timeout:
            latency = round((time.time() - start) * 1000, 2)
            last_status = "timeout"        # will retry if attempts remain

        except OSError:
            latency = round((time.time() - start) * 1000, 2)
            last_status = "error"
            break

        finally:
            sock.close()

    # Service + banner only for open ports
    if last_status == "open":
        detected = detect_service(ip, port, timeout)
        service = detected["service"]
        banner  = detected["banner"]
    else:
        service = "N/A"
        banner  = "N/A"

    return {
        "port":       port,
        "status":     last_status,
        "latency_ms": latency,
        "service":    service,
        "banner":     banner,
    }


# ──────────────────────────────────────────────
# Sequential scan
# ──────────────────────────────────────────────
def scan_range_sequential(ip: str, start: int, end: int,
                          timeout: float, retries: int = 1) -> tuple[list, float]:
    """Scan ports start..end one by one. Returns (results, elapsed_sec)."""
    t0 = time.time()
    results = [scan_port(ip, p, timeout, retries) for p in range(start, end + 1)]
    return results, round(time.time() - t0, 2)


# ──────────────────────────────────────────────
# Concurrent scan
# ──────────────────────────────────────────────
def scan_range_concurrent(ip: str, start: int, end: int,
                          timeout: float, retries: int = 1,
                          max_threads: int = 100) -> tuple[list, float]:
    """Scan ports start..end using a thread pool. Returns (results, elapsed_sec)."""
    t0 = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_map = {
            executor.submit(scan_port, ip, port, timeout, retries): port
            for port in range(start, end + 1)
        }
        for future in as_completed(future_map):
            try:
                results.append(future.result())
            except Exception as exc:
                port = future_map[future]
                results.append({
                    "port": port, "status": "error",
                    "latency_ms": 0, "service": "N/A",
                    "banner": f"Exception: {exc}",
                })

    # Return results sorted by port number for clean output
    results.sort(key=lambda r: r["port"])
    return results, round(time.time() - t0, 2)
