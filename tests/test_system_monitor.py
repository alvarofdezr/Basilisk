# tests/test_system_monitor.py
import pytest
from pysentinel.utils.system_monitor import get_system_metrics

def test_metrics_structure():
    """Verifica que la función devuelve los datos correctos (CPU, RAM, DISK)"""
    
    # Ejecutamos la función real
    data = get_system_metrics()
    
    # Verificaciones (Asserts)
    assert isinstance(data, dict), "El resultado debería ser un diccionario"
    assert "cpu" in data, "Falta la clave CPU"
    assert "ram" in data, "Falta la clave RAM"
    assert "disk" in data, "Falta la clave DISK"
    
    # Verificamos que los valores sean números lógicos (0-100)
    assert 0 <= data['cpu'] <= 100
    assert 0 <= data['ram'] <= 100