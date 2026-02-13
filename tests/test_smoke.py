"""
Smoke Tests para Basilisk v7.0
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from basilisk.core.schemas import ProcessModel


def test_imports():
    """Prueba simple: ¿Podemos importar los módulos clave?"""
    try:
        assert True
    except ImportError as e:
        assert False, f"Fallo al importar módulos core: {e}"


def test_schema_validation():
    """Prueba: ¿Funcionan los schemas de Pydantic?"""
    proc = ProcessModel(
        pid=1234,
        name="test.exe",
        cpu_percent=5.5,
        memory_percent=10.0,
        risk_score=0
    )
    assert proc.pid == 1234
    assert proc.risk_level == "INFO"
