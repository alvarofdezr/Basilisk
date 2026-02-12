# 🐍 Basilisk EDR v7.0 (Enterprise Core)

<p align="center">
    <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
    <img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build Passing">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
    <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux-lightgrey" alt="Platform">
</p>

| Feature                | Description                                  |
|------------------------|----------------------------------------------|
| Modular EDR            | Pluggable modules for all EDR capabilities   |
| Real-time Telemetry    | Live process, network, and system monitoring |
| Active Response        | Kill, isolate, scan, and audit remotely      |
| YARA & Threat Intel    | Malware detection and VirusTotal integration |
| Compliance Auditing    | UAC, Defender, Firewall, Registry, USB, etc. |
| Secure C2              | HTTPS, session guard, RBAC, self-signed cert |
| Docker Support         | Easy deployment with Docker Compose          |
| Type Safety            | Pydantic schemas for all data flows          |

**Basilisk** is a lightweight, modular Endpoint Detection and Response (EDR) system built with Python. It features a centralized C2 server, real-time telemetry, active response capabilities, and a strictly typed architecture using Pydantic and SQLAlchemy.

> ⚠️ **DISCLAIMER**: This project is provided **for educational and research purposes only**. Usage on unauthorized systems is strictly prohibited and may be illegal. The author assumes no responsibility for misuse or damages. Use responsibly and always with proper authorization.

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
* Docker & Docker Compose (Optional, for containerized deployment)

### Quick Setup
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/basilisk.git
    cd basilisk
    ```

2.  **Create and activate a virtual environment:**
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
    * You can also use a `.env` file to override secrets (see `basilisk/core/config.py`).
    * *Default User:* `admin`
    * *Default Pass:* Check `config.yaml` or `.env` (usually `admin` or hash).

#### Docker Deployment (Optional)
You can deploy Basilisk C2 and an agent simulator using Docker Compose:
```bash
docker-compose up --build
```
* The C2 server will be available at `https://localhost:8443` (accept the self-signed certificate).
* Edit environment variables in `.env` as needed.

#### Security Recommendations
* Change all default credentials and secrets before production use.
* Use strong, unique passwords and store them securely.
* Restrict network access to the C2 server.
* Review and harden firewall rules if using network isolation features.

---

## ⚡ Usage


### 1. Start the C2 Server
The server handles agent connections, stores telemetry in `basilisk.db`, and hosts the Web Dashboard.

```bash
python run_server.py
```
* Dashboard URL: https://localhost:8443
* Accept the self-signed certificate warning on first launch.

### 2. Start the Agent
Run this on the target machine (requires Admin privileges for full visibility):
```bash
python run_agent.py
```

#### Useful CLI Options
* You can pass environment variables to customize the C2 URL, admin hash, and more.
* For advanced deployments, see the Docker and config documentation.

## 📂 Project Structure

## 🏗️ Architecture Overview
**Basilisk** is split into two main components:

### 1. C2 Server (`basilisk/server/`)
* **FastAPI** backend for agent management, dashboards, and command dispatch.
* Stores telemetry and incident logs in a local SQLite database (`basilisk.db`).
* Handles authentication, session management, and secure communications (HTTPS, self-signed certs).
* Exposes REST API endpoints for agent heartbeat, alerts, and reports.

### 2. Agent (`basilisk/agent/`)
* Modular, multi-threaded Python agent for Windows endpoints.
* Periodically sends telemetry and receives commands from the C2.
* Implements a dispatcher pattern for real-time response to C2 commands.
* Integrates multiple security modules (see below).

### 3. Core & Shared (`basilisk/core/`)
* Configuration loader (YAML/env), Pydantic schemas, and database manager.
* Strict typing and validation for all data exchanged between modules.

### 4. Modules (`basilisk/modules/`)
Each module provides a specific EDR capability:

| Module                | Description                                      |
|-----------------------|--------------------------------------------------|
| `network_monitor`     | Detects suspicious network connections           |
| `process_monitor`     | Monitors processes and risk scoring              |
| `fim`                 | File Integrity Monitoring (baseline & live)      |
| `yara_scanner`        | YARA-based malware detection                     |
| `anti_ransomware`     | Canary files/honeypot for ransomware detection   |
| `usb_monitor`         | Detects USB device insertions/removals          |
| `port_monitor`        | Audits open/listening ports and risk             |
| `audit_scanner`       | System compliance checks (UAC, Defender, FW)    |
| `registry_monitor`    | Detects persistence via registry changes         |
| `log_watcher`         | Monitors logs for brute force/intrusion attempts |
| `network_isolation`   | Active response: isolate host via firewall       |
| `threat_intel`        | VirusTotal hash reputation lookups               |
| `win_event_watcher`   | Monitors Windows Security Event Log              |

### 5. Utils (`basilisk/utils/`)
* Logging, PDF reporting, certificate management, notifications, system metrics.

### 6. Other
* `certs/` - Auto-generated SSL certificates for HTTPS.
* `config.yaml` - Main configuration file (can be overridden by `.env`).
* `run_server.py` / `run_agent.py` - Entry points for server and agent.
* `requirements.txt` - All dependencies (see also `setup.py`).

---

### 🛡️ License

MIT License - See LICENSE file for details.
Copyright (c) 2026 Álvaro Fernández Ramos

---

## 🧪 Testing & Development

### Running Tests
* Basilisk uses **pytest** for smoke and unit tests.
* To run all tests:
    ```bash
    pytest
    ```
* Test files are located in the `tests/` directory. Example: `test_smoke.py` checks core imports and schema validation.

### Linting & Formatting
* Code style is enforced with **flake8** and **black**.
* Run lint checks:
    ```bash
    flake8 basilisk/
    ```
* Auto-format code:
    ```bash
    black basilisk/
    ```

### Contributing

---

## 🤝 Support & Contact

* For questions, bug reports, or feature requests, open an [issue](https://github.com/yourusername/basilisk/issues).
* For security concerns, contact the maintainer directly at: `alvarofdezr@outlook.es`
* Community contributions and feedback are highly appreciated!