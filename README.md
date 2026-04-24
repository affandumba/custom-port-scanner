# 🔍 Custom Port Scanner with Service Detection

A secure, networked port scanner built using **raw Python sockets** with **Mutual TLS (mTLS)** authentication, concurrent scanning, banner grabbing, and service detection.

> **Computer Networks Mini Project — B.Tech CSE**

---

## 📋 Table of Contents
- [Features](#features)
- [Project Structure](#project-structure)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Setup & Installation](#setup--installation)
- [How to Run](#how-to-run)
- [Usage](#usage)
- [Performance Evaluation](#performance-evaluation)
- [Security](#security)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔌 **TCP Port Scanning** | Raw socket-based scanning using `connect_ex()` |
| ⚡ **Concurrent Scanning** | ThreadPoolExecutor for parallel port scanning |
| 🔄 **Sequential Scanning** | One-by-one scanning for performance comparison |
| 🏷️ **Service Detection** | Maps 40+ well-known ports to service names |
| 📢 **Banner Grabbing** | Retrieves service banners from open ports |
| 🔐 **Mutual TLS (mTLS)** | Both server and client authenticate via certificates |
| 👤 **User Authentication** | Username + password login before scanning |
| 👥 **Multi-Client Support** | Multiple clients can connect simultaneously via threads |
| 💾 **Save Results** | Exports scan results to JSON and TXT files |
| 📊 **Performance Report** | HTML report with charts comparing scan modes |

---

## 📁 Project Structure

```
custom-port-scanner/
│
├── server.py             # SSL/TLS server — handles client connections & scanning
├── client.py             # SSL/TLS client — sends scan requests, displays results
├── scanner.py            # Core scanning engine (sequential + concurrent)
├── service_detector.py   # Port → service name mapping + banner grabbing
├── utils.py              # Shared helpers (validation, formatting, file saving)
├── tls_setup.py          # SSL context builders
├── generate_cert.py      # Generates CA, server, and client certificates (mTLS)
├── performance_eval.py   # Benchmarks sequential vs concurrent scanning
├── performance_report.html  # Auto-generated HTML performance report
└── .gitignore
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLIENT SIDE                         │
│                                                         │
│  client.py                                              │
│  ┌─────────────────────────────────────────────────┐   │
│  │  1. Load client cert + CA cert (mTLS)           │   │
│  │  2. Connect to server via SSL/TLS               │   │
│  │  3. Send username + password                    │   │
│  │  4. Send scan parameters (JSON)                 │   │
│  │  5. Receive + display results                   │   │
│  │  6. Save JSON + TXT to scan_results/            │   │
│  └─────────────────────────────────────────────────┘   │
└───────────────────────┬─────────────────────────────────┘
                        │  TCP + SSL/TLS (Port 5000)
                        │  Encrypted JSON over network
                        ▼
┌─────────────────────────────────────────────────────────┐
│                     SERVER SIDE                         │
│                                                         │
│  server.py                                              │
│  ┌─────────────────────────────────────────────────┐   │
│  │  1. Load server cert + CA cert (mTLS)           │   │
│  │  2. Accept connections (threaded)               │   │
│  │  3. Verify client certificate                   │   │
│  │  4. Verify username + password                  │   │
│  │  5. Run scan (sequential / concurrent)          │   │
│  │  6. Save results to scan_results/               │   │
│  │  7. Send results back to client                 │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  scanner.py + service_detector.py + utils.py            │
└─────────────────────────────────────────────────────────┘
```

---

## 🔧 Requirements

- Python 3.10+
- `cryptography` library

Install dependencies:
```bash
pip install cryptography
```

---

## ⚙️ Setup & Installation

### Step 1 — Clone the repository
```bash
git clone https://github.com/affandumba/custom-port-scanner.git
cd custom-port-scanner
```

### Step 2 — Install dependencies
```bash
pip install cryptography
```

### Step 3 — Generate certificates (run once)
```bash
python generate_cert.py
```

This creates a `certs/` folder with:
```
certs/
├── ca.crt        ← Share with all clients
├── ca.key        ← Keep secret
├── server.crt    ← Server only
├── server.key    ← Server only (keep secret)
├── client.crt    ← Share with clients
└── client.key    ← Share with clients (keep secret)
```

> ⚠️ Share `ca.crt`, `client.crt`, and `client.key` with anyone running the client.

---

## 🚀 How to Run

### Start the Server
```bash
python server.py
```
```
[SERVER] Starting server...
[SERVER] Listening on 0.0.0.0:5000 (SSL/TLS — mTLS enabled)
[SERVER] Ready to accept multiple concurrent clients
[SERVER] Press Ctrl+C to stop
```

### Start the Client
```bash
python client.py        # Windows
python3 client.py       # Mac/Linux
```

> The client needs `certs/ca.crt`, `certs/client.crt`, and `certs/client.key` in a `certs/` folder.

---

## 💻 Usage

When you run `client.py`, you will be prompted for:

```
Server IP                          : 192.168.x.x
──────────────────────────────────────────────────
  AUTHENTICATION REQUIRED
──────────────────────────────────────────────────
Username                           : affan
Password                           : ****

  ✅ Welcome affan!

Target IP / Host                   : 192.168.x.x
Start Port          (1 - 65535)   : 1
End Port            (1 - 65535)   : 1000
Timeout per port    (0.1 - 10 sec): 0.5
Retries on timeout  (0 - 3)       : 1
Mode                (sequential/concurrent): concurrent
```

### Sample Output
```
============================================================
  SCAN SUMMARY
============================================================
  Target        : 192.168.x.x
  Mode          : concurrent
  Total Time    : 5.14s
  Ports Scanned : 1000
  Open          : 3
  Closed        : 997
  Timed Out     : 0
============================================================
  OPEN PORTS DETAIL:
  PORT     SERVICE               LATENCY    BANNER
  --------------------------------------------------------
  135      MS-RPC                3.75 ms    N/A
  139      NetBIOS-SSN           0.54 ms    N/A
  445      SMB                   2.82 ms    N/A
============================================================
```

### Default Credentials
| Username | Password |
|---|---|
| `admin` | `scanner123` |
| `affan` | `pass123` |
| `manoj` | `pass456` |

> 📝 Credentials can be changed in `VALID_USERS` dictionary in `server.py`

---

## 📊 Performance Evaluation

Run the performance benchmark:
```bash
python performance_eval.py
```

This runs 3 tests and generates `performance_report.html`:

| Test | Description |
|---|---|
| Test 1 | Sequential vs Concurrent (ports 1–200) |
| Test 2 | Thread count scaling (1 to 200 threads) |
| Test 3 | Port range size scaling (50 to 1000 ports) |

**Results:**
- Sequential scan (200 ports): ~60s
- Concurrent scan (200 ports): ~0.6s
- **Speedup: ~92x faster with concurrent mode**

---

## 🔐 Security

### Mutual TLS (mTLS)
- Both server and client present certificates signed by the same CA
- Server rejects any client without a valid certificate
- All communication is encrypted end-to-end

### Authentication Flow
```
Client → presents client.crt to server
Server → verifies client.crt using ca.crt     ✅ Certificate check
Client → sends username + password
Server → checks against VALID_USERS           ✅ Credential check
Server → allows scan only if both pass        ✅ Double authentication
```

### Certificate Generation
- RSA 2048-bit key pairs
- SHA-256 signature algorithm
- X.509 certificate format
- Valid for 365 days

---

## 👨‍💻 Author

**Muhammad Affan Dumba**
B.Tech CSE — Computer Networks Project
