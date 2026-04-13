import socket
import json
from tls_setup import create_client_ssl_context
from utils import format_scan_summary, safe_recv_all

HOST = "127.0.0.1"
PORT = 5000


def main():
    context = create_client_ssl_context()

    target     = input("Enter target host/IP: ").strip()
    start_port = int(input("Enter start port: "))
    end_port   = int(input("Enter end port: "))
    timeout    = float(input("Enter timeout in seconds (e.g. 0.5): "))
    retries    = int(input("Enter retry count (e.g. 1): "))
    mode       = input("Enter scan mode (sequential/concurrent): ").strip().lower()

    request_data = {
        "target":     target,
        "start_port": start_port,
        "end_port":   end_port,
        "timeout":    timeout,
        "retries":    retries,
        "mode":       mode,
    }

    print(f"\n[CLIENT] Connecting to server {HOST}:{PORT} over TLS...")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_socket = context.wrap_socket(client_socket, server_hostname=HOST)
    secure_socket.connect((HOST, PORT))
    print("[CLIENT] TLS connection established ✓")

    # Send request
    secure_socket.sendall(json.dumps(request_data).encode())
    print("[CLIENT] Scan request sent. Waiting for results...\n")

    # Receive full response (chunked)
    response_raw = safe_recv_all(secure_socket)
    secure_socket.close()

    try:
        response = json.loads(response_raw)

        # Check for server-side error
        if "error" in response:
            print(f"[CLIENT] Server error: {response['error']}")
            return

        # Pretty summary
        print(format_scan_summary(response))

        # Also show full JSON if user wants
        show_json = input("\nShow full JSON output? (y/n): ").strip().lower()
        if show_json == "y":
            print(json.dumps(response, indent=2))

    except json.JSONDecodeError:
        print("[CLIENT] Could not parse server response:")
        print(response_raw)


if __name__ == "__main__":
    main()
