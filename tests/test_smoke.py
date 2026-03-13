"""
Basilisk Smoke Tests
Basic import and schema validation tests. Every test must actually assert
something meaningful — `assert True` is not a test.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# ── Import tests ──────────────────────────────────────────────────────────────

def test_import_schemas():
    """Core schemas module imports without error."""
    from basilisk.core import schemas  # noqa: F401


def test_import_config():
    """Config module imports without error."""
    from basilisk.core import config  # noqa: F401


def test_import_security():
    """Security module imports without error."""
    from basilisk.core import security  # noqa: F401


def test_import_database():
    """Agent-side database module imports without error."""
    from basilisk.core import database  # noqa: F401


def test_import_logger():
    """Logger utility imports without error."""
    from basilisk.utils import logger  # noqa: F401


def test_import_process_monitor():
    """ProcessMonitor imports without error (cross-platform module)."""
    from basilisk.modules import process_monitor  # noqa: F401


def test_import_network_monitor():
    """NetworkMonitor imports without error (cross-platform module)."""
    from basilisk.modules import network_monitor  # noqa: F401


# ── Schema validation ─────────────────────────────────────────────────────────

def test_process_model_defaults():
    """ProcessModel sets correct default values."""
    from basilisk.core.schemas import ProcessModel
    proc = ProcessModel(pid=1234, name="test.exe", cpu_percent=5.5, memory_percent=10.0, risk_score=0)
    assert proc.pid == 1234
    assert proc.name == "test.exe"
    assert proc.risk_level == "INFO"
    assert proc.risk_score == 0
    assert proc.username == "SYSTEM"


def test_process_model_rejects_missing_required_fields():
    """ProcessModel raises ValidationError when required fields are absent."""
    from basilisk.core.schemas import ProcessModel
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ProcessModel()  # pid and name are required


def test_network_conn_model():
    """NetworkConnModel validates correctly."""
    from basilisk.core.schemas import NetworkConnModel
    conn = NetworkConnModel(src="192.168.1.1:1234", dst="8.8.8.8:443", process="chrome.exe", pid=999)
    assert conn.status == "ESTABLISHED"
    assert conn.pid == 999


def test_port_risk_model():
    """PortRiskModel validates correctly."""
    from basilisk.core.schemas import PortRiskModel
    port = PortRiskModel(port=445, ip_bind="0.0.0.0", proto="TCP", service="SMB", process="System", pid=4, risk="CRITICAL")
    assert port.port == 445
    assert port.risk == "CRITICAL"


# ── Security helpers ──────────────────────────────────────────────────────────

def test_password_verify_correct():
    """verify_password returns True for correct password."""
    from basilisk.core.security import hash_password, verify_password
    h = hash_password("hunter2")
    assert verify_password(h, "hunter2") is True


def test_password_verify_wrong():
    """verify_password returns False for wrong password."""
    from basilisk.core.security import hash_password, verify_password
    h = hash_password("hunter2")
    assert verify_password(h, "wrongpassword") is False


def test_password_verify_bad_hash():
    """verify_password returns False for a malformed hash (no exception)."""
    from basilisk.core.security import verify_password
    assert verify_password("not_a_real_hash", "password") is False


# ── ThreatIntel cache ─────────────────────────────────────────────────────────

def test_threat_intel_no_api_key_returns_none():
    """ThreatIntel.check_hash returns None when api_key is empty."""
    from basilisk.modules.threat_intel import ThreatIntel
    ti = ThreatIntel(api_key="")
    result = ti.check_hash("aabbcc")
    assert result is None


def test_threat_intel_cache_eviction():
    """ThreatIntel evicts oldest entry when max_cache_size is exceeded."""
    from basilisk.modules.threat_intel import ThreatIntel
    import time

    ti = ThreatIntel(api_key="dummy", max_cache_size=2, cache_ttl=60)
    # Inject entries directly into cache to avoid real API calls
    ti._set_cached("hash1", {"malicious": 0, "total": 10, "scan_date": time.time()})
    ti._set_cached("hash2", {"malicious": 0, "total": 10, "scan_date": time.time()})
    assert ti.cache_size == 2
    ti._set_cached("hash3", {"malicious": 0, "total": 10, "scan_date": time.time()})
    # Oldest entry (hash1) should have been evicted
    assert ti.cache_size == 2
    assert ti._get_cached("hash1") is None
    assert ti._get_cached("hash3") is not None


def test_threat_intel_cache_ttl_expiry():
    """ThreatIntel does not return expired cache entries."""
    from basilisk.modules.threat_intel import ThreatIntel
    import time

    ti = ThreatIntel(api_key="dummy", max_cache_size=10, cache_ttl=1)
    ti._set_cached("deadbeef", {"malicious": 5, "total": 70, "scan_date": time.time()})
    assert ti._get_cached("deadbeef") is not None
    # Manually expire the entry
    ti._cache["deadbeef"].expires_at = time.time() - 1
    assert ti._get_cached("deadbeef") is None
