# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [7.1.0] - 2025-02-14

### Breaking Changes
- **Requires uv** for dependency management. Run `uv sync --extra windows`
  instead of `pip install -r requirements.txt`.
- **Server requires three environment variables** to start:
  `BASILISK_ADMIN_PASSWORD_HASH`, `BASILISK_SERVER_SECRET_KEY`,
  `BASILISK_AGENT_TOKEN`. Missing any of them causes immediate exit.
- **Agent endpoints now require authentication** via `X-Agent-Token` header.
  Agents without the token receive `401 Unauthorized`.

### Security
- Added `X-Agent-Token` authentication to `/heartbeat`, `/alert`, and
  `/report` endpoints — previously open to unauthenticated requests.
- Removed hardcoded `ADMIN_HASH` fallback from `server.py`. Server now
  refuses to start instead of using an insecure default.
- Added `Referrer-Policy: strict-origin-when-cross-origin` security header.
- Added session expiry enforcement in the HTTP middleware.
- Bounded `login_attempts` dict with `_MAX_TRACKED_IPS` limit to prevent
  unbounded memory growth under distributed brute-force attacks.

### Fixed
- `docker-compose.yml`: agent command pointed to non-existent
  `agent/agent_core.py` — corrected to `run_agent.py`.
- `Dockerfile`: version label was `6.7.0`, corrected to `7.1.0`.
- `config.example.yaml`: version was `6.6.0`, corrected to `7.1.0`.
- `SECURITY.md`: impossible date `2025-01-35` corrected to `2025-02-14`.
- `setup.py` → `pyproject.toml`: placeholder URL `yourusername` replaced
  with actual GitHub username.
- `audit_scanner.py`, `registry_monitor.py`: `import winreg` now guarded
  with `sys.platform == "win32"` — no longer crashes on Linux CI.
- `system_monitor.py`: `disk_usage('/')` now uses the correct drive path
  on Windows instead of always returning 0.0.
- `test_flow.py`: `sys.exit` at module level caused pytest `INTERNALERROR`.
  Fixed by using `pytest.skip(allow_module_level=True)` for missing config,
  and real `assert` statements instead of `return False`.
- `server.py`: missing `main()` function caused the `basilisk-server`
  entry point defined in `pyproject.toml` to fail at runtime.

### Added
- `pyproject.toml` replacing `setup.py`, `requirements.txt`,
  `requirements-dev.txt`, `.flake8`, and `pytest.ini`.
- `uv.lock` for fully reproducible installs.
- `.env.example` with all required and optional variables documented.
- `basilisk-server` and `basilisk-agent` CLI entry points via
  `pyproject.toml [project.scripts]`.
- `main()` functions in `server.py` and `engine.py` for entry point support.

### Changed
- Migrated from `setup.py` + `requirements.txt` to `uv` + `pyproject.toml`.
- Dev dependencies (pytest, mypy, ruff, bandit, etc.) moved to
  `[dependency-groups] dev` in `pyproject.toml`.
- `ThreatIntel` cache replaced with TTL-bounded LRU implementation
  (`OrderedDict`, default TTL=1h, max 1000 entries).
- `test_smoke.py`: replaced `assert True` stubs with 17 real assertions
  covering imports, Pydantic validation, password hashing, and cache behaviour.
- `test_flow.py`: replaced hardcoded `admin/admin123` and `AGENT_PC-ALVARO`
  with env vars (`BASILISK_TEST_PASS`, `BASILISK_TEST_AGENT_ID`).
- All Spanish comments translated to English throughout codebase.
- CI workflow updated to use `astral-sh/setup-uv@v4`.

---

## [7.0.0] - 2024-02-12

### Added
- Enterprise architecture with modular design
- Pydantic schemas for strict type safety
- SQLAlchemy ORM for database management
- FastAPI-based C2 server
- Multi-threaded agent with command dispatcher
- Cyberpunk-themed web dashboard
- Real-time telemetry collection
- Active response capabilities (kill, isolate, scan)
- YARA malware scanning
- Anti-ransomware canary detection
- Network monitoring and analysis
- Port risk assessment
- USB device monitoring
- File Integrity Monitoring (FIM)
- System compliance auditing
- Registry persistence detection
- Windows Event Log monitoring
- Memory scanning (process hollowing detection)
- Threat intelligence (VirusTotal integration)
- Network isolation capability
- Self-signed certificate generation
- Session-based authentication
- Telegram notifications
- PDF report generation

### Changed
- Migrated from monolithic to modular architecture
- Upgraded to Python 3.10+ requirement
- Improved security with Argon2 password hashing

---

## [6.7.1] - 2024-XX-XX

### Added
- Initial EDR capabilities
- Basic C2 server
- Agent with telemetry collection

---

## Version Guidelines

| Increment | When |
|-----------|------|
| Major (X.0.0) | Breaking changes, major architecture changes |
| Minor (x.X.0) | New features, backward compatible |
| Patch (x.x.X) | Bug fixes, security patches, docs |

---

**Note**: Dates use ISO 8601 format (YYYY-MM-DD).