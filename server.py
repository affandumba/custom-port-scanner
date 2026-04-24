"""
server.py
──────────────────────────────────────────────
SSL/TLS-secured TCP server with MUTUAL TLS (mTLS).
  - Server verifies client certificate
  - Client verifies server certificate
  - Username + password authentication on top
  - Multiple concurrent clients via threading
  - Graceful Ctrl+C shutdown
"""

import socket
import ssl
import json
import time
import threading
import signal
import sys

from scanner import scan_range_sequential, scan_range_concurrent
from utils   import validate_port_range, resolve_host, save_results, timestamp

HOST = "0.0.0.0"
PORT = 5000

# ──────────────────────────────────────────────
# Registered users
# ──────────────────────────────────────────────
VALID_USERS = {
    "admin":  "scanner123",
    "affan":  "pass123",
    "manoj":  "pass456",
}

shutdown_flag = threading.Event()


# ──────────────────────────────────────────────
# SSL context — mTLS (server verifies client cert)
# ──────────────────────────────────────────────
def build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Server's own certificate + key
    ctx.load_cert_chain(
        certfile="certs/server.crt",
        keyfile="certs/server.key"
    )

    # CA certificate — used to verify the CLIENT's certificate
    ctx.load_verify_locations("certs/ca.crt")

    # REQUIRE client to present a valid certificate
    ctx.verify_mode = ssl.CERT_REQUIRED

    return ctx


# ──────────────────────────────────────────────
# Username + password authentication
# ──────────────────────────────────────────────
def authenticate(secure_sock, addr) -> bool:
    try:
        raw = secure_sock.recv(4096).decode()
        creds = json.loads(raw)

        username = creds.get("username", "").strip()
        password = creds.get("password", "").strip()

        if VALID_USERS.get(username) == password:
            secure_sock.sendall(json.dumps({
                "auth": "success",
                "message": f"Welcome {username}!"
            }).encode())
            print(f"[SERVER] Auth SUCCESS for user '{username}' from {addr}")
            return True
        else:
            secure_sock.sendall(json.dumps({
                "auth": "failed",
                "message": "Invalid username or password."
            }).encode())
            print(f"[SERVER] Auth FAILED for user '{username}' from {addr}")
            return False

    except Exception as e:
        print(f"[SERVER] Auth error from {addr}: {e}")
        return False


# ──────────────────────────────────────────────
# Handle one client in its own thread
# ──────────────────────────────────────────────
def handle_client(client_sock, addr, context):
    print(f"[SERVER] New client: {addr}")

    try:
        # TLS handshake — server verifies client cert here
        secure_sock = context.wrap_socket(client_sock, server_side=True)

        # Show which client cert was presented
        client_cert = secure_sock.getpeercert()
        subject = dict(x[0] for x in client_cert.get("subject", []))
        print(f"[SERVER] TLS established with {addr}")
        print(f"[SERVER] Client cert CN: {subject.get('commonName', 'Unknown')}")

        # ── Username + password auth ──────────
        secure_sock.settimeout(30)
        if not authenticate(secure_sock, addr):
            return

        # ── Receive scan request ──────────────
        secure_sock.settimeout(300)
        raw = b""
        while True:
            chunk = secure_sock.recv(65536)
            if not chunk:
                break
            raw += chunk
            try:
                request = json.loads(raw.decode())
                break
            except json.JSONDecodeError:
                continue

        if not raw:
            print(f"[SERVER] Empty request from {addr}")
            return

        # ── Parse fields ──────────────────────
        target      = request["target"]
        start_port  = int(request["start_port"])
        end_port    = int(request["end_port"])
        timeout     = float(request.get("timeout", 1.0))
        mode        = request.get("mode", "concurrent").lower()
        retries     = int(request.get("retries", 1))
        max_threads = int(request.get("max_threads", 100))

        timeout = max(0.1, min(timeout, 10.0))
        validate_port_range(start_port, end_port)
        resolved_ip = resolve_host(target)

        print(f"[SERVER] Scanning {resolved_ip} ({start_port}-{end_port}) [{mode}]")

        # ── Run scan ──────────────────────────
        t_start = time.time()
        if mode == "sequential":
            results, scan_time = scan_range_sequential(
                resolved_ip, start_port, end_port, timeout, retries
            )
        else:
            results, scan_time = scan_range_concurrent(
                resolved_ip, start_port, end_port, timeout, retries, max_threads
            )
        total_time = round(time.time() - t_start, 2)

        open_ports   = sum(1 for r in results if r["status"] == "open")
        closed_ports = sum(1 for r in results if r["status"] == "closed")
        timed_out    = sum(1 for r in results if r["status"] == "timeout")
        errors       = sum(1 for r in results if r["status"] == "error")

        response = {
            "target":              target,
            "resolved_ip":         resolved_ip,
            "mode":                mode,
            "retries":             retries,
            "total_scan_time_sec": total_time,
            "ports_scanned":       len(results),
            "open_ports":          open_ports,
            "closed_ports":        closed_ports,
            "timed_out":           timed_out,
            "errors":              errors,
            "results":             results,
        }

        try:
            saved = save_results(response)
            print(f"[SERVER] Results saved → {saved['json']}")
        except Exception as e:
            print(f"[SERVER] Could not save results: {e}")

        secure_sock.sendall(json.dumps(response).encode())
        print(f"[SERVER] Scan complete for {addr} ({open_ports} open, {total_time}s)")

    except ssl.SSLError as e:
        print(f"[SERVER] SSL/cert error from {addr}: {e}")
        print(f"[SERVER] Client may not have a valid certificate!")

    except ValueError as ve:
        try:
            secure_sock.sendall(json.dumps({"error": str(ve)}).encode())
        except Exception:
            pass
        print(f"[SERVER] Validation error for {addr}: {ve}")

    except Exception as e:
        try:
            secure_sock.sendall(json.dumps({"error": str(e)}).encode())
        except Exception:
            pass
        print(f"[ERROR] {addr}: {e}")

    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        print(f"[SERVER] Connection closed: {addr}")


# ──────────────────────────────────────────────
# Ctrl+C handler
# ──────────────────────────────────────────────
def handle_shutdown(sig, frame):
    print(f"\n[{timestamp()}] [SERVER] Shutting down gracefully...")
    shutdown_flag.set()


# ──────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────
def main():
    signal.signal(signal.SIGINT,  handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    print("[SERVER] Starting server...")

    context = build_ssl_context()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    server.settimeout(1.0)

    print(f"[SERVER] Listening on {HOST}:{PORT} (SSL/TLS — mTLS enabled)")
    print(f"[SERVER] Ready to accept multiple concurrent clients")
    print(f"[SERVER] Registered users: {list(VALID_USERS.keys())}")
    print(f"[SERVER] Press Ctrl+C to stop\n")

    active_threads = []

    while not shutdown_flag.is_set():
        try:
            client_sock, addr = server.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(client_sock, addr, context),
                daemon=True,
            )
            thread.start()
            active_threads.append(thread)
            active_threads = [t for t in active_threads if t.is_alive()]

        except socket.timeout:
            continue

        except Exception as e:
            if not shutdown_flag.is_set():
                print(f"[SERVER] Unexpected error: {e}")

    print("[SERVER] Waiting for active scans to finish...")
    for t in active_threads:
        t.join(timeout=5.0)

    server.close()
    print("[SERVER] Server stopped. Goodbye!")
    sys.exit(0)


if __name__ == "__main__":
    main()
