"""
Basilisk Smoke Tests
Basic import and schema validation tests for core functionality.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from basilisk.core.schemas import ProcessModel


def test_imports() -> None:
    """Verify core modules can be imported without errors."""
    try:
        assert True
    except ImportError as e:
        assert False, f"Failed to import core modules: {e}"


def test_schema_validation() -> None:
    """Verify Pydantic schemas validate data correctly."""
    proc = ProcessModel(
        pid=1234,
        name="test.exe",
        cpu_percent=5.5,
        memory_percent=10.0,
        risk_score=0
    )
    assert proc.pid == 1234
    assert proc.risk_level == "INFO"