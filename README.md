# 🐍 Basilisk EDR v7.1.0 (Enterprise Core)

<p align="center">
    <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
    <img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build Passing">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
    <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux-lightgrey" alt="Platform">
    <img src="https://img.shields.io/badge/version-7.1.0-blue" alt="Version">
    <img src="https://img.shields.io/badge/package%20manager-uv-purple" alt="uv">
</p>

| Feature                | Description                                  |
|------------------------|----------------------------------------------|
| Modular EDR            | Pluggable modules for all EDR capabilities   |
| Real-time Telemetry    | Live process, network, and system monitoring |
| Active Response        | Kill, isolate, scan, and audit remotely      |
| YARA & Threat Intel    | Malware detection and VirusTotal integration |
| Compliance Auditing    | UAC, Defender, Firewall, Registry, USB, etc. |
| Secure C2              | HTTPS, session guard, RBAC, agent token auth |
| Type Safety            | Pydantic schemas for all data flows          |
| Professional Dashboard | Cyberpunk-themed web interface               |

**Basilisk** is a lightweight, modular Endpoint Detection and Response (EDR) system built with Python. It features a centralized C2 server, real-time telemetry, active response capabilities, and a strictly typed architecture using Pydantic and SQLAlchemy.

> ⚠️ **DISCLAIMER**: This project is provided **for educational and research purposes only**. Usage on unauthorized systems is strictly prohibited and may be illegal. The author assumes no responsibility for misuse or damages. Use responsibly and always with proper authorization.

---

## 🚀 Key Features v7.1.0

### Core Capabilities
* **Enterprise Architecture**: Fully modular package structure (`basilisk` core)
* **Type Safety**: End-to-end data validation using **Pydantic** schemas
* **Modern Tooling**: Managed with **uv** — fast, reproducible, standards-compliant
* **Code Quality**: Refactored codebase with industry-standard practices

### Active Response
* Process Termination (`KILL`)
* Network Isolation (Firewall containment)
* YARA Scanning
* Remote Command Execution
* Multi-command queuing system

### Advanced Telemetry
* Real-time Process Monitoring (with risk scoring)
* Network Traffic Analysis
* Port Auditing
* System Compliance Checks (UAC, Defender, Firewall)
* USB Device Monitoring
* File Integrity Monitoring (FIM)

### Security Features
* **Secure C2**: HTTPS server with Session Guard and Role-Based Access
* **Agent Authentication**: Shared token (`X-Agent-Token`) on all agent endpoints
* **Anti-Ransomware**: Canary file detection with watchdog monitoring
* **Threat Intelligence**: VirusTotal integration for hash reputation
* **Audit Logging**: Comprehensive event tracking and reporting
* **Fail-secure**: Server refuses to start with missing secrets — no insecure fallbacks

---

## 🛠️ Installation

### Prerequisites
* Python 3.10+
* [uv](https://docs.astral.sh/uv/) — install once, globally
* Administrator/Root privileges (for full agent capabilities on Windows)

### Install uv (once, globally)

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

```bash
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Quick Setup

**1. Clone the repository:**
```bash
git clone https://github.com/alvarofdezr/basilisk.git
cd basilisk
```

**2. Create the virtual environment and install all dependencies:**
```bash
# uv creates .venv automatically and installs everything from uv.lock
uv sync

# On Windows, also install the Windows-specific extras:
uv sync --extra windows
```

That's it. No manual `python -m venv`, no `pip install`. uv handles everything.

**3. Configure secrets:**

```bash
# Copy the example env file
cp .env.example .env
```

Generate the required secrets:

```bash
# Generate Argon2 hash for your admin password
uv run python -c "from basilisk.core.security import hash_password; print(hash_password('your_password'))"

# Generate session secret key
uv run python -c "import secrets; print(secrets.token_hex(32))"

# Generate agent token
uv run python -c "import secrets; print(secrets.token_hex(32))"
```

Edit `.env` with the generated values:

```ini
BASILISK_ADMIN_PASSWORD_HASH=$argon2id$v=19$...
BASILISK_SERVER_SECRET_KEY=<generated>
BASILISK_AGENT_TOKEN=<generated>
```

> ⚠️ **Default Credentials**: `admin` / `admin123` — **change before any real use**.

---

## ⚡ Usage

### Start the C2 Server

```bash
uv run python run_server.py
```

Dashboard: `https://localhost:8443` — accept the self-signed certificate warning on first launch.

### Start the Agent

Run on the target Windows machine (Administrator privileges required for full visibility):

```bash
uv run python run_agent.py
```

### Using the Dashboard

1. Open `https://localhost:8443` and log in
2. Connected agents appear in the left panel
3. Click an agent to open the **Inspector** (processes, ports, compliance audit)
4. Use the **Response** tab to send remote commands
5. Monitor the **Live Incident Feed** for real-time alerts

---

## 📂 Project Structure

```
basilisk/
├── agent/
│   └── engine.py              # Agent core with command dispatcher
├── core/
│   ├── config.py              # Configuration loader (YAML/env)
│   ├── database.py            # SQLite manager (agent-side)
│   ├── schemas.py             # Pydantic data models
│   ├── security.py            # Argon2 password hashing
│   └── active_response.py     # Process termination
├── modules/                   # EDR capabilities
├── server/
│   ├── server.py              # FastAPI C2 server
│   ├── database.py            # SQLAlchemy ORM models
│   ├── static/                # CSS/JS for dashboard
│   └── templates/             # HTML templates
├── utils/
│   ├── logger.py              # Singleton logger
│   ├── cert_manager.py        # Auto SSL certificate generation
│   ├── notifier.py            # Telegram notifications
│   ├── pdf_generator.py       # Security report PDFs
│   └── system_monitor.py      # CPU/RAM/Disk metrics
├── rules/
│   └── index.yar              # YARA signatures
├── tests/
│   ├── test_smoke.py          # Unit tests (imports, schemas, security)
│   └── test_flow.py           # End-to-end integration test
├── run_agent.py               # Agent entry point
├── run_server.py              # Server entry point
├── pyproject.toml             # Project definition, dependencies, tool config
├── uv.lock                    # Locked dependency tree (commit this)
├── .env.example               # Environment variable template
└── config.example.yaml        # Configuration template
```

---

## 🏗️ Architecture Overview

### 1. C2 Server (`basilisk/server/`)
* **FastAPI** backend for agent management, dashboards, and command dispatch
* Agent endpoints protected by shared `X-Agent-Token` header
* Session-based admin authentication with rate limiting and expiry
* Refuses to start if required secrets are missing

### 2. Agent (`basilisk/agent/`)
* Modular, multi-threaded Python agent for Windows endpoints
* Sends `X-Agent-Token` on every request to the C2
* Implements dispatcher pattern for O(1) command routing

### 3. EDR Modules (`basilisk/modules/`)

| Module                | Platform | Description                                      |
|-----------------------|----------|--------------------------------------------------|
| `network_monitor`     | All      | Detects suspicious network connections           |
| `process_monitor`     | All      | Monitors processes and risk scoring              |
| `fim`                 | All      | File Integrity Monitoring                        |
| `yara_scanner`        | All      | YARA-based malware detection                     |
| `anti_ransomware`     | All      | Canary files for ransomware detection            |
| `usb_monitor`         | All      | Detects USB device insertions/removals           |
| `port_monitor`        | All      | Audits open ports and risk assessment            |
| `threat_intel`        | All      | VirusTotal hash reputation (TTL-bounded cache)   |
| `audit_scanner`       | Windows  | System compliance checks (UAC, Defender, FW)     |
| `registry_monitor`    | Windows  | Detects persistence via registry changes         |
| `win_event_watcher`   | Windows  | Monitors Windows Security Event Log              |
| `memory_scanner`      | Windows  | Process hollowing detection                      |
| `network_isolation`   | Windows  | Isolate host via Windows Firewall                |
| `log_watcher`         | All      | Monitors logs for brute force attempts           |

---

## 🧪 Testing & Development

### Running Tests

```bash
# All tests
uv run pytest

# With coverage report
uv run pytest --cov=basilisk --cov-report=term-missing

# Stop on first failure
uv run pytest -x
```

### Integration Test

Requires both server and agent running:

```bash
# Set these in your .env (or export them):
# BASILISK_TEST_PASS=your_password
# BASILISK_TEST_AGENT_ID=AGENT_YOUR_HOSTNAME

uv run python tests/test_flow.py
```

### Linting & Type Checking

```bash
# Syntax errors and undefined names (most critical)
uv run flake8 basilisk --count --select=E9,F63,F7,F82 --show-source

# Full lint
uv run flake8 basilisk --count --exit-zero --max-line-length=127

# Type checking
uv run mypy basilisk

# Security scan (SAST)
uv run bandit -r basilisk -ll

# Known vulnerabilities in dependencies
uv run safety check
```

### Adding / Removing Dependencies

```bash
# Add a runtime dependency
uv add some-package

# Add a dev-only dependency
uv add --dev some-package

# Remove a dependency
uv remove some-package

# Upgrade all dependencies to latest compatible versions
uv lock --upgrade
uv sync
```

> **Never** edit `uv.lock` by hand. Always use `uv add` / `uv remove`.

---

## 🔒 Security

See [SECURITY.md](SECURITY.md) for the full security policy, known limitations, and vulnerability disclosure process.

Key points:
* Change default credentials (`admin`/`admin123`) **before any real use**
* Generate strong unique values for all three required secrets
* The server will not start with missing secrets — no insecure fallbacks
* Agent endpoints require `X-Agent-Token` authentication

---

## 📋 Version History

### v7.1.0 (2025-02-14)
* **Migrated** to `uv` + `pyproject.toml` — modern, reproducible tooling
* **Fixed** agent endpoint authentication (shared token, no more open endpoints)
* **Fixed** server fails fast on missing secrets instead of using insecure fallbacks
* **Fixed** `docker-compose.yml` pointing to non-existent file
* **Fixed** version inconsistencies across `Dockerfile`, `config.example.yaml`, `SECURITY.md`
* **Fixed** `setup.py` placeholder URL
* **Fixed** Windows-only imports crashing on Linux CI
* **Fixed** `ThreatIntel` cache: now has TTL and max-size with LRU eviction
* **Improved** smoke tests: 17 real assertions (previously `assert True`)
* **Improved** `test_flow.py`: credentials from env vars, no hardcoded secrets

### v7.0.0
* Enterprise architecture with modular design
* Pydantic schemas, SQLAlchemy ORM, FastAPI C2 server
* Cyberpunk-themed dashboard, Docker support

---

## 🛡️ License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contact

* **Issues**: [GitHub Issues](https://github.com/alvarofdezr/basilisk/issues)
* **Security**: `alvarofdezr@outlook.es`

---

**Built with 💚 for cybersecurity education and research**