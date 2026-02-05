# 🐍 Basilisk EDR v7.0 (Enterprise Core)

**Basilisk** is a lightweight, modular Endpoint Detection and Response (EDR) system built with Python. It features a centralized C2 server, real-time telemetry, active response capabilities, and a strictly typed architecture using Pydantic and SQLAlchemy.

> ⚠️ **DISCLAIMER**: This software is for EDUCATIONAL PURPOSES ONLY. Do not use on unauthorized systems.

---

## 🚀 Key Features v7.0

* **Enterprise Architecture**: Fully modular package structure (`basilisk` core).
* **Type Safety**: End-to-end data validation using **Pydantic** schemas.
* **Active Response**:
    * Process Termination (`KILL`)
    * Network Isolation (Firewall containment)
    * YARA Scanning
* **Advanced Telemetry**:
    * Real-time Process Monitoring (with risk scoring)
    * Network Traffic Analysis
    * Port Auditing
    * System Compliance Checks (UAC, Defender, Firewall)
* **Secure C2**: HTTPS-ready server with Session Guard and Role-Based Access.

---

## 🛠️ Installation

### Prerequisites
* Python 3.10+
* Virtual Environment (Recommended)

### Setup
1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/yourusername/basilisk.git](https://github.com/yourusername/basilisk.git)
    cd basilisk
    ```

2.  **Create and activate virtual environment:**
    ```bash
    python -m venv venv
    # Windows:
    .\venv\Scripts\activate
    # Linux/Mac:
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configuration:**
    * Edit `config.yaml` to set your Admin credentials and C2 IP.
    * *Default User:* `admin`
    * *Default Pass:* Check `config.yaml` (usually `admin` or hash).

---

## ⚡ Usage

### 1. Start the C2 Server
The server handles agent connections, stores telemetry in `basilisk.db`, and hosts the Web Dashboard.

```bash
python run_server.py

Dashboard URL: https://localhost:8443

Note: Accept the self-signed certificate warning on first launch.
```
### 2. Start the Agent

Run this on the target machine (requires Admin privileges for full visibility).
```bash
python run_agent.py
```

## 📂 Project Structure
```Plaintext

Basilisk/
├── basilisk/               # Main Package
│   ├── agent/              # Agent Engine & Dispatcher
│   ├── server/             # FastAPI Backend & Database
│   ├── modules/            # EDR Capabilities (Net, Proc, Audit...)
│   ├── core/               # Shared Schemas & Config
│   └── utils/              # Loggers & Helpers
├── certs/                  # SSL Certificates (Auto-generated)
├── config.yaml             # Global Configuration
├── run_server.py           # Server Entry Point
├── run_agent.py            # Agent Entry Point
└── requirements.txt        # Dependencies
```

### 🛡️ License

MIT License - See LICENSE file for details.