# Security Policy

## 🛡️ Security Overview

Basilisk EDR is an educational cybersecurity project designed for legitimate security research, threat hunting, and defensive security operations. While we strive for secure code, this project should **never be deployed in production environments without thorough security review and hardening**.

## Supported Versions

| Version | Supported          | Status                |
| ------- | ------------------ | --------------------- |
| 7.1.x   | ✅ Yes             | Active Development    |
| 7.0.x   | ✅ Yes             | Security Updates Only |
| < 7.0   | ❌ No              | End of Life           |

## 🔒 Security Considerations

### Known Limitations

1. **Self-Signed Certificates** — Default config uses self-signed certs. Risk: MITM. Mitigation: use CA-signed certs in any sensitive environment.
2. **Default Credentials** — Ships with `admin`/`admin123`. **Change immediately on first run.**
3. **SQLite Database** — Not suitable for high-concurrency or multi-node deployments.
4. **No Encryption at Rest** — Database and logs are stored unencrypted. Use disk encryption (LUKS, BitLocker).
5. **Agent Privileges** — Agent requires administrator/root. Run in isolated environments.

### Security Features

✅ **Implemented:**
- Argon2id password hashing (OWASP recommended)
- HTTPS-only communication
- Session-based auth with timeout and expiry enforcement
- Rate limiting on login (5 attempts / IP)
- Agent endpoint authentication via shared token (`X-Agent-Token`)
- Input validation with Pydantic schemas
- SQL injection prevention (SQLAlchemy ORM)
- Security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`)
- Server refuses to start with missing secrets (no insecure fallbacks)

❌ **Not Implemented (known gaps):**
- Multi-factor authentication (MFA)
- Certificate pinning
- Encryption at rest
- Tamper-proof audit log storage
- Intrusion detection for the C2 server itself

## 🚨 Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

1. **Email**: `alvarofdezr@outlook.es`
2. **Subject**: `[SECURITY] Basilisk EDR — <brief description>`
3. **Include**: description, steps to reproduce, impact, suggested fix (optional)

| Timeline | Action |
|----------|--------|
| 24 hours | Initial acknowledgment |
| 7 days   | Preliminary assessment |
| 30 days  | Fix developed and tested |
| 45 days  | Patch released (if confirmed) |
| 90 days  | Public disclosure (coordinated) |

## 🛠️ Security Best Practices

### Pre-Deployment Checklist
- [ ] Change all default credentials
- [ ] Generate strong secret keys (`python -c "import secrets; print(secrets.token_hex(32))"`)
- [ ] Generate a unique `BASILISK_AGENT_TOKEN`
- [ ] Disable unnecessary modules
- [ ] Review firewall rules

### Code Review Checklist (for contributors)
- [ ] No hardcoded secrets, credentials, or machine names
- [ ] Input validation on all user-supplied data
- [ ] Proper error handling (no stack traces exposed to clients)
- [ ] SQL queries use parameterization (SQLAlchemy ORM only)
- [ ] File operations validate paths (no directory traversal)
- [ ] Windows-only imports guarded with `if sys.platform == "win32"`

## 🔐 Cryptographic Details

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Password hashing | Argon2id | m=65536 KB, t=3, p=4 |
| TLS | TLS 1.2+ | RSA 4096-bit self-signed |
| Session secret | HMAC-SHA256 | via Starlette SessionMiddleware |

## 🏆 Hall of Fame

| Researcher | Vulnerability | Date | Severity |
|------------|---------------|------|----------|
| *Awaiting first submission* | — | — | — |

---

**Last Updated**: 2025-02-14
**Version**: 7.1.0