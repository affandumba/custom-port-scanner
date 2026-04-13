import socket
import time
import threading
from queue import Queue
from service_detector import detect_service

# ──────────────────────────────────────────────
# Single port scan
# ──────────────────────────────────────────────
def scan_port(target, port, timeout=1.0, retries=1):
    attempt = 0

    while attempt <= retries:
        try:
            start_time = time.time()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            elapsed_time = (time.time() - start_time) * 1000
            sock.close()

            if result == 0:
                # Port is open — grab service info and banner
                svc_info = detect_service(target, port, timeout)
                return {
                    "port":       port,
                    "status":     "open",
                    "latency_ms": round(elapsed_time, 2),
                    "service":    svc_info["service"],
                    "banner":     svc_info["banner"],
                }
            else:
                return {
                    "port":       port,
                    "status":     "closed",
                    "latency_ms": round(elapsed_time, 2),
                    "service":    "N/A",
                    "banner":     "N/A",
                }

        except socket.timeout:
            attempt += 1
            if attempt > retries:
                return {
                    "port":       port,
                    "status":     "timeout",
                    "latency_ms": None,
                    "service":    "N/A",
                    "banner":     "N/A",
                }

        except Exception as e:
            return {
                "port":       port,
                "status":     f"error: {str(e)}",
                "latency_ms": None,
                "service":    "N/A",
                "banner":     "N/A",
            }


# ──────────────────────────────────────────────
# Sequential scan
# ──────────────────────────────────────────────
def scan_range_sequential(target, start_port, end_port, timeout=1.0, retries=1):
    results = []
    start_time = time.time()

    for port in range(start_port, end_port + 1):
        result = scan_port(target, port, timeout, retries)
        results.append(result)

    total_time = time.time() - start_time
    return results, round(total_time, 2)


# ──────────────────────────────────────────────
# Concurrent scan (threaded)
# ──────────────────────────────────────────────
def scan_range_concurrent(target, start_port, end_port, timeout=1.0, retries=1, max_threads=100):
    results = []
    results_lock = threading.Lock()
    port_queue = Queue()

    # Fill queue
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    def worker():
        while not port_queue.empty():
            try:
                port = port_queue.get_nowait()
            except Exception:
                break
            result = scan_port(target, port, timeout, retries)
            with results_lock:
                results.append(result)
            port_queue.task_done()

    total_ports = end_port - start_port + 1
    num_threads = min(max_threads, total_ports)

    start_time = time.time()

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    total_time = time.time() - start_time

    # Sort results by port number for clean output
    results.sort(key=lambda x: x["port"])
    return results, round(total_time, 2)
