# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [7.1.0] - 2025-02-14

### Added
- Comprehensive JSDoc headers for all JavaScript modules
- Type hints across entire Python codebase
- Professional docstrings in all modules
- Module-level documentation for frontend and backend
- Enhanced error messages with context
- Detailed logging in server endpoints
- Test flow script for end-to-end validation (`tests/test_flow.py`)
- Multi-command queuing system in heartbeat endpoint
- Version badge in README
- CHANGELOG.md (this file)
- SECURITY.md with security policy
- LICENSE file with MIT license

### Changed
- **[CRITICAL]** Fixed 403 Forbidden error on static files by changing middleware to prefix matching (`/static/`)
- Converted all Spanish comments to English throughout codebase
- Updated `setup.py` to version 7.1.0 with enhanced metadata
- Improved README.md with version history and better organization
- Enhanced commit message format to follow Conventional Commits
- Refactored all utility modules for better readability
- Standardized docstring format across all Python files
- Improved CSS organization in dashboard and login stylesheets
- Enhanced JavaScript code organization and documentation
- Updated default admin password hash in server configuration

### Removed
- 200+ redundant inline comments
- Duplicate `app.mount()` declaration in server.py
- Verbose section dividers (`---`, `===`)
- Spanish language comments
- Unnecessary decorative comments

### Fixed
- **Static file serving**: Changed `/static` to `/static/` prefix in middleware
- HTML typo in login.html (`</html>s` → `</html>`)
- Encoding issues in comment strings
- Inconsistent quotation marks in docstrings
- Missing type hints in multiple modules

### Security
- Enhanced documentation of security best practices
- Improved password hashing documentation
- Better error handling to prevent information leakage
- Clarified security recommendations in README

### Documentation
- All 18 modified files now have comprehensive documentation
- Added migration notes in commit message
- Enhanced inline documentation for complex logic
- Improved function and class descriptions

### Performance
- No performance changes (refactoring focused on code quality)

### Testing
- All smoke tests passing
- Server starts without errors
- Static files load correctly
- Authentication flow verified
- Agent-server communication tested

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
- Docker support with docker-compose
- Self-signed certificate generation
- Session-based authentication
- RBAC (Role-Based Access Control)
- Telegram notifications
- PDF report generation
- Comprehensive logging system

### Changed
- Migrated from monolithic to modular architecture
- Upgraded to Python 3.10+ requirement
- Improved security with Argon2 password hashing

### Security
- HTTPS-only server communication
- Session guards with timeout
- Rate limiting on login attempts
- Self-signed certificate auto-generation
- Secure password storage with Argon2

## [6.7.1] - 2024-XX-XX

### Added
- Initial EDR capabilities
- Basic C2 server
- Agent with telemetry collection

### Changed
- Various improvements and bug fixes

## Earlier Versions

See git history for changes in versions prior to 6.7.1.

---

## Version Guidelines

### Major Version (X.0.0)
- Breaking changes
- Major architecture changes
- Significant feature additions

### Minor Version (x.X.0)
- New features (backward compatible)
- Significant improvements
- New modules or capabilities

### Patch Version (x.x.X)
- Bug fixes
- Documentation updates
- Minor improvements
- Security patches

---

## Links

- [GitHub Repository](https://github.com/alvarofdezr/basilisk)
- [Issue Tracker](https://github.com/alvarofdezr/basilisk/issues)
- [Security Policy](SECURITY.md)
- [Contributing Guidelines](CONTRIBUTING.md)

---

**Note**: Dates are in YYYY-MM-DD format (ISO 8601).