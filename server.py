import socket
import ssl
import json
import threading
from tls_setup import create_server_ssl_context
from scanner import scan_range_sequential, scan_range_concurrent
from utils import validate_port_range, resolve_host, format_scan_summary, timestamp

HOST = "0.0.0.0"
PORT = 5000


def handle_client(secure_socket, client_address):
    """Handle a single client connection in its own thread."""
    print(f"[SERVER] [{timestamp()}] Handling client: {client_address}")
    try:
        # Receive full request (may be large)
        raw_data = b""
        secure_socket.settimeout(10.0)
        while True:
            try:
                chunk = secure_socket.recv(4096)
                if not chunk:
                    break
                raw_data += chunk
                # Try parsing — if valid JSON, we have the full message
                try:
                    json.loads(raw_data.decode())
                    break
                except json.JSONDecodeError:
                    continue
            except socket.timeout:
                break

        if not raw_data:
            print(f"[SERVER] Empty request from {client_address}, closing.")
            return

        request = json.loads(raw_data.decode())
        print(f"[SERVER] Scan request: {request}")

        # ── Validate inputs ──────────────────────────────
        target     = request["target"]
        start_port = int(request["start_port"])
        end_port   = int(request["end_port"])
        timeout    = float(request.get("timeout", 1.0))
        retries    = int(request.get("retries", 1))
        mode       = request.get("mode", "sequential").lower()

        validate_port_range(start_port, end_port)
        ip = resolve_host(target)

        print(f"[SERVER] Resolved {target} → {ip}")
        print(f"[SERVER] Mode: {mode} | Ports: {start_port}-{end_port}")

        # ── Run scan ─────────────────────────────────────
        if mode == "concurrent":
            results, total_time = scan_range_concurrent(
                ip, start_port, end_port, timeout, retries
            )
        else:
            results, total_time = scan_range_sequential(
                ip, start_port, end_port, timeout, retries
            )

        # ── Build response ───────────────────────────────
        response = {
            "target":             target,
            "ip":                 ip,
            "mode":               mode,
            "total_scan_time_sec": total_time,
            "timestamp":          timestamp(),
            "results":            results,
        }

        # Print summary on server side
        print(format_scan_summary(response))

        # Send response
        response_bytes = json.dumps(response, indent=2).encode()
        secure_socket.sendall(response_bytes)
        print(f"[SERVER] Response sent to {client_address} ({len(response_bytes)} bytes)")

    except ValueError as e:
        error_resp = json.dumps({"error": str(e)}).encode()
        try:
            secure_socket.sendall(error_resp)
        except Exception:
            pass
        print(f"[SERVER] Validation error: {e}")

    except ssl.SSLError as e:
        print(f"[SERVER] SSL error with {client_address}: {e}")

    except Exception as e:
        print(f"[SERVER] Error handling {client_address}: {e}")

    finally:
        try:
            secure_socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            secure_socket.close()
        except Exception:
            pass
        print(f"[SERVER] Connection closed: {client_address}")


def main():
    context = create_server_ssl_context()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    print(f"[SERVER] Secure Port Scanner Server started")
    print(f"[SERVER] Listening on {HOST}:{PORT} (TLS enabled)")
    print(f"[SERVER] Waiting for clients...\n")

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            print(f"[SERVER] New connection from {client_address}")

            try:
                secure_socket = context.wrap_socket(client_socket, server_side=True)
                print(f"[SERVER] TLS handshake successful with {client_address}")
            except ssl.SSLError as e:
                # This handles the EOF / bad handshake gracefully
                print(f"[SERVER] TLS handshake failed with {client_address}: {e}")
                client_socket.close()
                continue

            # Each client gets its own thread → multi-client support
            t = threading.Thread(
                target=handle_client,
                args=(secure_socket, client_address),
                daemon=True
            )
            t.start()

        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down.")
            break
        except Exception as e:
            print(f"[SERVER] Accept error: {e}")

    server_socket.close()


if __name__ == "__main__":
    main()
