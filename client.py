"""
client.py
──────────────────────────────────────────────
SSL/TLS client with MUTUAL TLS (mTLS).
  - Client presents its own certificate to server
  - Client verifies server certificate via CA
  - Username + password authentication on top
  - Full input validation

Run:  python3 client.py
"""

import socket
import ssl
import json
import os
from datetime import datetime


# ──────────────────────────────────────────────
# Input helpers
# ──────────────────────────────────────────────

def get_str(prompt: str) -> str:
    while True:
        val = input(prompt).strip()
        if val:
            return val
        print("  [!] This field cannot be empty. Try again.")


def get_int(prompt: str, lo: int, hi: int) -> int:
    while True:
        raw = input(prompt).strip()
        try:
            val = int(raw)
            if lo <= val <= hi:
                return val
            print(f"  [!] Must be between {lo} and {hi}. Try again.")
        except ValueError:
            print(f"  [!] '{raw}' is not a valid number. Try again.")


def get_float(prompt: str, lo: float, hi: float) -> float:
    while True:
        raw = input(prompt).strip()
        try:
            val = float(raw)
            if lo <= val <= hi:
                return val
            print(f"  [!] Must be between {lo} and {hi}. Try again.")
        except ValueError:
            print(f"  [!] '{raw}' is not a valid number. Try again.")


def get_choice(prompt: str, choices: list) -> str:
    choices_str = "/".join(choices)
    while True:
        val = input(f"{prompt} ({choices_str}): ").strip().lower()
        if val in choices:
            return val
        print(f"  [!] Please enter one of: {choices_str}")


def get_password(prompt: str) -> str:
    try:
        import getpass
        return getpass.getpass(prompt)
    except Exception:
        return input(prompt).strip()


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ──────────────────────────────────────────────
# SSL context — mTLS (client presents its cert)
# ──────────────────────────────────────────────

def build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # CA certificate — used to VERIFY the server's certificate
    ctx.load_verify_locations("certs/ca.crt")

    # Client's own certificate + key — presented TO the server
    ctx.load_cert_chain(
        certfile="certs/client.crt",
        keyfile="certs/client.key"
    )

    # Verify server cert but skip hostname check (self-signed)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_REQUIRED

    return ctx


# ──────────────────────────────────────────────
# Authentication
# ──────────────────────────────────────────────

def authenticate(secure_sock) -> bool:
    print("\n" + "-" * 50)
    print("  AUTHENTICATION REQUIRED")
    print("-" * 50)

    username = get_str("Username : ")
    password = get_password("Password : ")

    creds = json.dumps({
        "username": username,
        "password": password,
    }).encode()
    secure_sock.sendall(creds)

    raw      = secure_sock.recv(4096).decode()
    response = json.loads(raw)

    if response.get("auth") == "success":
        print(f"\n  ✅ {response.get('message', 'Authenticated!')}")
        print("-" * 50 + "\n")
        return True
    else:
        print(f"\n  ❌ {response.get('message', 'Authentication failed.')}")
        print("-" * 50 + "\n")
        return False


# ──────────────────────────────────────────────
# Display results
# ──────────────────────────────────────────────

def display_summary(response: dict):
    results   = response.get("results", [])
    open_list = [r for r in results if r.get("status") == "open"]

    print("\n" + "=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    print(f"  Target        : {response.get('target', 'N/A')}")
    print(f"  Mode          : {response.get('mode', 'N/A')}")
    print(f"  Total Time    : {response.get('total_scan_time_sec', 'N/A')}s")
    print(f"  Ports Scanned : {response.get('ports_scanned', len(results))}")
    print(f"  Open          : {response.get('open_ports', len(open_list))}")
    print(f"  Closed        : {response.get('closed_ports', 'N/A')}")
    print(f"  Timed Out     : {response.get('timed_out', 0)}")
    print("=" * 60)

    if open_list:
        print("  OPEN PORTS DETAIL:")
        print(f"  {'PORT':<8} {'SERVICE':<18} {'LATENCY':>10}  BANNER")
        print("  " + "-" * 56)
        for r in sorted(open_list, key=lambda x: x["port"]):
            print(
                f"  {r['port']:<8} {r.get('service','N/A'):<18} "
                f"{str(r.get('latency_ms','N/A'))+' ms':>10}  {r.get('banner','N/A')}"
            )
    print("=" * 60)


def display_full(response: dict):
    print(f"\n{'PORT':<8} {'STATUS':<10} {'SERVICE':<18} {'LATENCY':>10}  BANNER")
    print("-" * 70)
    for r in response.get("results", []):
        print(
            f"{r['port']:<8} {r['status']:<10} {r.get('service','N/A'):<18} "
            f"{str(r.get('latency_ms','N/A'))+' ms':>10}  {r.get('banner','N/A')}"
        )


def save_results(response: dict):
    os.makedirs("scan_results", exist_ok=True)
    target = response.get("target", "unknown").replace(".", "_")
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    base   = os.path.join("scan_results", f"{target}_{ts}")

    json_path = base + ".json"
    with open(json_path, "w") as f:
        json.dump(response, f, indent=2)

    txt_path = base + ".txt"
    with open(txt_path, "w") as f:
        results = response.get("results", [])
        f.write("=" * 60 + "\n")
        f.write("SCAN SUMMARY\n")
        f.write("=" * 60 + "\n")
        f.write(f"Target        : {response.get('target')}\n")
        f.write(f"Mode          : {response.get('mode')}\n")
        f.write(f"Total Time    : {response.get('total_scan_time_sec')}s\n")
        f.write(f"Ports Scanned : {len(results)}\n")
        f.write(f"Open          : {response.get('open_ports')}\n")
        f.write(f"Closed        : {response.get('closed_ports')}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"{'PORT':<8} {'STATUS':<10} {'SERVICE':<18} {'LATENCY':>10}  BANNER\n")
        f.write("-" * 70 + "\n")
        for r in results:
            f.write(
                f"{r['port']:<8} {r['status']:<10} {r.get('service','N/A'):<18} "
                f"{str(r.get('latency_ms','N/A'))+' ms':>10}  {r.get('banner','N/A')}\n"
            )

    print(f"  [+] JSON saved → {json_path}")
    print(f"  [+] TXT  saved → {txt_path}")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    print("\n" + "=" * 50)
    print("   CUSTOM PORT SCANNER — CLIENT")
    print("=" * 50 + "\n")

    server_ip = get_str("Server IP                          : ")

    ctx      = build_ssl_context()
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        secure_sock = ctx.wrap_socket(raw_sock, server_hostname=server_ip)
        print(f"\n[{timestamp()}] [CLIENT] Connecting to {server_ip}:5000 ...")
        secure_sock.connect((server_ip, 5000))
        print(f"[{timestamp()}] [CLIENT] Connected (mTLS — both certs verified).")

        # ── Authenticate ──────────────────────
        if not authenticate(secure_sock):
            print("[CLIENT] Access denied. Closing connection.")
            return

        # ── Scan parameters ───────────────────
        target     = get_str("Target IP / Host                   : ")
        start_port = get_int ("Start Port          (1 - 65535)   : ", 1, 65535)

        while True:
            end_port = get_int("End Port            (1 - 65535)   : ", 1, 65535)
            if end_port >= start_port:
                break
            print(f"  [!] End port must be >= start port ({start_port}). Try again.")

        timeout  = get_float("Timeout per port    (0.1 - 10 sec): ", 0.1, 10.0)
        retries  = get_int  ("Retries on timeout  (0 - 3)       : ", 0, 3)
        mode     = get_choice("Mode                              ", ["sequential", "concurrent"])

        print()

        request = {
            "target":      target,
            "start_port":  start_port,
            "end_port":    end_port,
            "timeout":     timeout,
            "retries":     retries,
            "mode":        mode,
            "max_threads": 100,
        }

        secure_sock.sendall(json.dumps(request).encode())
        print(f"[{timestamp()}] [CLIENT] Request sent. Waiting for results...\n")

        raw = b""
        secure_sock.settimeout(300)
        while True:
            chunk = secure_sock.recv(65536)
            if not chunk:
                break
            raw += chunk
            try:
                response = json.loads(raw.decode())
                break
            except json.JSONDecodeError:
                continue

        if "error" in response:
            print(f"\n[!] Server error: {response['error']}")
            return

        display_summary(response)

        show = get_choice("\nShow full port list?  ", ["y", "n"])
        if show == "y":
            display_full(response)

        save = get_choice("\nSave results to file? ", ["y", "n"])
        if save == "y":
            save_results(response)

    except ssl.SSLError as e:
        print(f"\n[!] SSL/Certificate error: {e}")
        print("[!] Make sure certs/ca.crt, certs/client.crt, certs/client.key exist.")
    except ConnectionRefusedError:
        print(f"\n[!] Connection refused. Is the server running on {server_ip}:5000?")
    except socket.timeout:
        print("\n[!] Connection timed out.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
    finally:
        raw_sock.close()


if __name__ == "__main__":
    main()
