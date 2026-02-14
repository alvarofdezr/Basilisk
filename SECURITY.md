# Security Policy

## 🛡️ Security Overview

Basilisk EDR is an educational cybersecurity project designed for legitimate security research, threat hunting, and defensive security operations. While we strive for secure code, this project should **never be deployed in production environments without thorough security review and hardening**.

## Supported Versions

We actively support security updates for the following versions:

| Version | Supported          | Status                |
| ------- | ------------------ | --------------------- |
| 7.1.x   | ✅ Yes             | Active Development    |
| 7.0.x   | ✅ Yes             | Security Updates Only |
| < 7.0   | ❌ No              | End of Life          |

## 🔒 Security Considerations

### Known Limitations

1. **Self-Signed Certificates**
   - Default configuration uses self-signed certificates
   - **Risk**: Susceptible to man-in-the-middle attacks
   - **Mitigation**: Use CA-signed certificates in any sensitive environment

2. **Default Credentials**
   - Ships with default admin credentials (`admin`/`admin123`)
   - **Risk**: Unauthorized access if not changed
   - **Mitigation**: Change immediately on first deployment

3. **SQLite Database**
   - Uses SQLite for simplicity
   - **Risk**: Not suitable for high-concurrency or multi-node deployments
   - **Mitigation**: Migrate to PostgreSQL/MySQL for production

4. **No Built-in Encryption at Rest**
   - Database and logs stored unencrypted
   - **Risk**: Sensitive data exposure if filesystem is compromised
   - **Mitigation**: Use disk encryption (LUKS, BitLocker, etc.)

5. **Agent Privileges**
   - Agent requires administrator/root privileges
   - **Risk**: If compromised, attacker gains elevated access
   - **Mitigation**: Run in isolated environments, implement least privilege where possible

### Security Features

✅ **Implemented:**
- Argon2id password hashing (OWASP recommended)
- HTTPS-only communication
- Session-based authentication with timeout
- Rate limiting on login attempts (5 attempts per IP)
- CSRF protection via session middleware
- Input validation with Pydantic schemas
- SQL injection prevention (SQLAlchemy ORM)
- XSS prevention (proper escaping in templates)
- Security headers (X-Frame-Options, X-Content-Type-Options)

❌ **Not Implemented:**
- Multi-factor authentication (MFA)
- Certificate pinning
- Encryption at rest
- Audit logging to tamper-proof storage
- Intrusion detection for the C2 server itself
- Automated vulnerability scanning

## 🚨 Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow responsible disclosure practices:

### What to Report

- Authentication bypasses
- Remote code execution vulnerabilities
- SQL injection or XSS vulnerabilities
- Privilege escalation issues
- Information disclosure bugs
- Denial of service vulnerabilities
- Cryptographic weaknesses

### How to Report

**🔴 Do NOT open a public GitHub issue for security vulnerabilities.**

Instead:

1. **Email**: Send details to `alvarofdezr@outlook.es`
2. **Subject Line**: `[SECURITY] Basilisk EDR - [Brief Description]`
3. **Include**:
   - Vulnerability description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)
   - Your contact information (optional, for credit)

### What to Expect

| Timeline | Action |
|----------|--------|
| 24 hours | Initial acknowledgment |
| 7 days   | Preliminary assessment |
| 30 days  | Fix developed and tested |
| 45 days  | Patch released (if confirmed) |
| 90 days  | Public disclosure (coordinated) |

### Disclosure Policy

- We follow **coordinated disclosure** practices
- Reporters will be credited (unless anonymity requested)
- Critical vulnerabilities will be prioritized
- We aim for transparency while protecting users

### Bug Bounty

Currently, we do **not** offer a bug bounty program. This is an educational open-source project. However:

- ✅ Public credit in CHANGELOG and GitHub
- ✅ Recognition in SECURITY.md Hall of Fame
- ✅ My sincere gratitude 🙏

## 🛠️ Security Best Practices

If you're deploying Basilisk (even in a lab), follow these guidelines:

### Pre-Deployment

- [ ] Change all default credentials
- [ ] Generate strong secret keys (minimum 32 characters)
- [ ] Review and understand all configuration options
- [ ] Disable unnecessary modules
- [ ] Review firewall rules

### Deployment

- [ ] Use CA-signed certificates (Let's Encrypt, corporate CA)
- [ ] Restrict C2 server access (firewall, VPN, IP whitelist)
- [ ] Enable disk encryption
- [ ] Use dedicated user accounts (not root/admin)
- [ ] Implement network segmentation
- [ ] Set up centralized logging

### Post-Deployment

- [ ] Monitor logs regularly
- [ ] Keep dependencies updated (`pip list --outdated`)
- [ ] Review access logs for anomalies
- [ ] Rotate credentials periodically
- [ ] Perform security audits
- [ ] Test backup and recovery procedures

### Code Review Checklist

When contributing code, ensure:

- [ ] No hardcoded secrets or credentials
- [ ] Input validation on all user-supplied data
- [ ] Proper error handling (no stack traces to users)
- [ ] SQL queries use parameterization
- [ ] File operations validate paths (no directory traversal)
- [ ] Dependencies are up-to-date
- [ ] No use of `eval()`, `exec()`, or similar dangerous functions

## 🔐 Cryptographic Details

### Password Hashing
- **Algorithm**: Argon2id
- **Parameters**: 
  - Memory: 65536 KB (64 MB)
  - Iterations: 3
  - Parallelism: 4
- **Library**: `argon2-cffi` (official CFFI bindings)

### HTTPS/TLS
- **Protocol**: TLS 1.2+ (handled by uvicorn)
- **Certificates**: Self-signed by default (cryptography library)
- **Key Size**: RSA 4096-bit
- **Validity**: 5 years

### Session Management
- **Storage**: Server-side (Starlette SessionMiddleware)
- **Cookie Flags**: `HttpOnly`, `Secure`, `SameSite=Lax`
- **Timeout**: 8 hours (configurable)

## 🧪 Security Testing

### Running Security Scans

```bash
# Install security tools
pip install bandit safety

# Run Bandit (SAST)
bandit -r basilisk/ -ll

# Check for known vulnerabilities
safety check

# Run all tests
pytest tests/
```

### Recommended Tools

- **Bandit**: Python security linter
- **Safety**: Dependency vulnerability checker
- **Trivy**: Docker image scanner
- **OWASP ZAP**: Web application scanner
- **Burp Suite**: HTTP interceptor and fuzzer

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security.html)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)

## 🏆 Hall of Fame

We recognize security researchers who help improve Basilisk:

| Researcher | Vulnerability | Date | Severity |
|------------|---------------|------|----------|
| *Awaiting first submission* | - | - | - |

*Want to be listed here? Report a valid security issue!*

## 📝 Disclaimer

**THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL PURPOSES ONLY.**

- ⚠️ Not intended for production use without thorough security review
- ⚠️ No warranty of any kind (see LICENSE)
- ⚠️ Use on unauthorized systems is illegal
- ⚠️ Author is not responsible for misuse

## 📧 Contact

- **Security Issues**: `alvarofdezr@outlook.es`
- **General Issues**: [GitHub Issues](https://github.com/alvarofdezr/basilisk/issues)
- **Documentation**: See README.md

---

**Last Updated**: 2025-01-35  
**Version**: 7.1.0