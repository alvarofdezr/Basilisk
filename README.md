# 🐍 Basilisk EDR v7.1.0 (Enterprise Core)

<p align="center">
    <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
    <img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build Passing">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
    <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux-lightgrey" alt="Platform">
    <img src="https://img.shields.io/badge/version-7.1.0-blue" alt="Version">
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
| Professional Dashboard | Cyberpunk-themed web interface               |

**Basilisk** is a lightweight, modular Endpoint Detection and Response (EDR) system built with Python. It features a centralized C2 server, real-time telemetry, active response capabilities, and a strictly typed architecture using Pydantic and SQLAlchemy.

> ⚠️ **DISCLAIMER**: This project is provided **for educational and research purposes only**. Usage on unauthorized systems is strictly prohibited and may be illegal. The author assumes no responsibility for misuse or damages. Use responsibly and always with proper authorization.

---

## 🚀 Key Features v7.1.0

### Core Capabilities
* **Enterprise Architecture**: Fully modular package structure (`basilisk` core)
* **Type Safety**: End-to-end data validation using **Pydantic** schemas
* **Professional Documentation**: Comprehensive docstrings and type hints
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
* **Secure C2**: HTTPS-ready server with Session Guard and Role-Based Access
* **Anti-Ransomware**: Canary file detection with watchdog monitoring
* **Threat Intelligence**: VirusTotal integration for hash reputation
* **Audit Logging**: Comprehensive event tracking and reporting

---

## 🛠️ Installation

### Prerequisites
* Python 3.10+
* Virtual Environment (Recommended)
* Docker & Docker Compose (Optional, for containerized deployment)
* Administrator/Root privileges (for full agent capabilities)

### Quick Setup
1. **Clone the repository:**
   ```bash
   git clone https://github.com/alvarofdezr/basilisk.git
   cd basilisk
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # Windows:
   .\venv\Scripts\activate
   # Linux/Mac:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configuration:**
   * Copy `config.example.yaml` to `config.yaml`
   * Edit `config.yaml` to set your Admin credentials and C2 IP
   * Alternatively, use a `.env` file to override secrets (see `basilisk/core/config.py`)
   
   **Default Credentials:**
   * Username: `admin`
   * Password: `admin123` (⚠️ **Change immediately in production!**)

### Docker Deployment (Optional)
Deploy Basilisk C2 and agent simulator using Docker Compose:
```bash
docker-compose up --build
```
* C2 server: `https://localhost:8443`
* Accept self-signed certificate warning
* Configure environment variables in `.env`

### Security Recommendations
* ⚠️ **Change all default credentials before production use**
* Use strong, unique passwords (minimum 16 characters)
* Store secrets securely (consider using a secrets manager)
* Restrict network access to the C2 server
* Review and harden firewall rules if using network isolation features
* Enable HTTPS with valid certificates in production
* Regularly update dependencies for security patches

---

## ⚡ Usage

### 1. Start the C2 Server
The server handles agent connections, stores telemetry in `basilisk.db`, and hosts the Web Dashboard.

```bash
python run_server.py
```
* Dashboard URL: `https://localhost:8443`
* Accept the self-signed certificate warning on first launch
* Login with admin credentials

### 2. Start the Agent
Run this on the target machine (requires Admin privileges for full visibility):
```bash
python run_agent.py
```

**Agent Features:**
* Automatic C2 connection with heartbeat every 3 seconds
* Real-time telemetry collection
* Command execution from C2
* Modular threat detection

### 3. Using the Dashboard

**Main Features:**
* 🖥️ **Agent Overview**: See all connected endpoints
* 📊 **Live Incident Feed**: Real-time security alerts
* 🔍 **Agent Inspector**: Deep dive into process, port, and audit data
* 🚨 **Active Response**: Execute remote commands (kill, isolate, scan)
* 📈 **Metrics**: Charts for threat severity and attack vectors

**Common Workflows:**
1. Click on an agent to open Inspector
2. View processes, ports, or compliance audit
3. Send commands (refresh data, run scans, etc.)
4. Monitor incidents in real-time feed

### CLI Options
Configure via environment variables:
```bash
# Server
export BASILISK_ADMIN_PASSWORD_HASH="your_argon2_hash_here"
export BASILISK_SERVER_SECRET_KEY="your_secret_key_here"

# Agent
export BASILISK_C2_URL="https://your-server:8443"
export BASILISK_VIRUSTOTAL_API_KEY="your_vt_api_key"
```

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
├── modules/                   # EDR capabilities (see table below)
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
│   ├── test_smoke.py          # Basic import tests
│   └── test_flow.py           # End-to-end workflow tests
├── run_agent.py               # Agent entry point
├── run_server.py              # Server entry point
├── setup.py                   # Package configuration
├── requirements.txt           # Python dependencies
├── config.yaml                # Main configuration (create from example)
└── docker-compose.yml         # Container orchestration
```

---

## 🏗️ Architecture Overview

### 1. C2 Server (`basilisk/server/`)
* **FastAPI** backend for agent management, dashboards, and command dispatch
* Stores telemetry and incident logs in local SQLite database (`basilisk.db`)
* Handles authentication, session management, and secure communications (HTTPS)
* Exposes REST API endpoints for agent heartbeat, alerts, and reports
* **New in 7.1.0**: Fixed static file serving, improved logging, enhanced documentation

### 2. Agent (`basilisk/agent/`)
* Modular, multi-threaded Python agent for Windows endpoints
* Periodically sends telemetry and receives commands from the C2
* Implements dispatcher pattern for O(1) command routing
* Integrates multiple security modules
* **New in 7.1.0**: Enhanced command dispatcher, improved error handling

### 3. Core & Shared (`basilisk/core/`)
* Configuration loader (YAML/env)
* Pydantic schemas for strict typing
* Database manager with thread-safe operations
* **New in 7.1.0**: Comprehensive type hints, improved documentation

### 4. EDR Modules (`basilisk/modules/`)

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
| `memory_scanner`      | Process hollowing detection                      |

**New in 7.1.0**: All modules now have comprehensive docstrings and type hints

---

## 🧪 Testing & Development

### Running Tests
Basilisk uses **pytest** for smoke and integration tests.

```bash
# Run all tests
pytest

# Run specific test
pytest tests/test_smoke.py

# Run with verbose output
pytest -v
```

### Test Flow Script
Test the complete command flow (login → queue commands → verify reports):
```bash
python tests/test_flow.py
```

### Linting & Formatting
Code style is enforced with **flake8** and **black**.

```bash
# Run lint checks
flake8 basilisk/

# Auto-format code
black basilisk/

# Type checking
mypy basilisk --ignore-missing-imports

# Security scan
bandit -r basilisk -ll
```

### Development Workflow
1. Create feature branch: `git checkout -b feature/your-feature`
2. Make changes with proper documentation
3. Run tests: `pytest`
4. Run linters: `flake8` and `mypy`
5. Commit with conventional format: `feat: add new feature`
6. Submit pull request

---

## 📋 Version History

### v7.1.0 (2025-02-14) - Major Refactoring
* **Fixed**: 403 Forbidden error on static files
* **Improved**: Comprehensive code documentation (18 files)
* **Enhanced**: Type hints across entire codebase
* **Converted**: All Spanish comments to English
* **Added**: JSDoc headers for JavaScript files
* **Updated**: Professional commit message standards
* **Maintained**: 100% backward compatibility

### v7.0.0 (Previous)
* Enterprise architecture with modular design
* Pydantic schemas for type safety
* Enhanced C2 server with RBAC
* Docker support
* Cyberpunk-themed dashboard

---

## 🛡️ License

MIT License - See [LICENSE.md](LICENSE.md) for details.

---

## 🤝 Support & Contact

* **Issues**: [GitHub Issues](https://github.com/alvarofdezr/basilisk/issues)
* **Security**: Contact maintainer directly at `alvarofdezr@outlook.es`
* **Documentation**: See `/docs` folder for detailed guides
* **Community**: Contributions and feedback welcome!

---

## 🙏 Acknowledgments

* Built with [FastAPI](https://fastapi.tiangolo.com/) for the C2 server
* Uses [Pydantic](https://pydantic-docs.helpmanual.io/) for data validation
* Powered by [SQLAlchemy](https://www.sqlalchemy.org/) ORM
* UI components from [Bootstrap 5](https://getbootstrap.com/)
* Icons from [Font Awesome](https://fontawesome.com/)

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

## 🔒 Security Policy

See [SECURITY.md](SECURITY.md) for security advisories and responsible disclosure.

---

**Built with 💚 for cybersecurity education and research**