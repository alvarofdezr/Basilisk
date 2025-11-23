# tests/test_active_response.py
import pytest
import psutil
from unittest.mock import patch, MagicMock
from pysentinel.core.active_response import kill_process_by_pid

def test_kill_existing_process():
    """Simula matar un proceso exitosamente"""
    pid_falso = 1234
    
    # Usamos 'patch' para NO matar un proceso real de tu Windows
    with patch('psutil.Process') as MockProcess:
        # Configuramos el mock para que actúe como un proceso real
        process_instance = MockProcess.return_value
        process_instance.terminate.return_value = None
        process_instance.wait.return_value = None # Simula que cerró a tiempo
        
        # Llamamos a TU función
        resultado = kill_process_by_pid(pid_falso)
        
        # Verificamos
        assert resultado is True
        process_instance.terminate.assert_called_once() # ¿Se llamó a terminate?

def test_kill_access_denied():
    """Simula qué pasa si no tenemos permisos de Administrador"""

    
    with patch('psutil.Process') as MockProcess:
        process_instance = MockProcess.return_value
        # Hacemos que lance una excepción de acceso denegado
        process_instance.terminate.side_effect = psutil.AccessDenied(pid=999)
        
        resultado = kill_process_by_pid(999)
        
        assert resultado is False # La función debe manejar el error y devolver False