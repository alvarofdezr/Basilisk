import pytest
import hashlib
from unittest.mock import MagicMock  # <--- HERRAMIENTA CLAVE
from basilisk.modules.fim import FileIntegrityMonitor

# 1. SETUP
@pytest.fixture
def temp_file(tmp_path):
    """Crea un archivo temporal seguro"""
    d = tmp_path / "test_data"
    d.mkdir()
    p = d / "secreto.txt"
    p.write_text("Contenido Super Secreto")
    return p

# 2. TEST CÁLCULO
def test_sha256_calculation(temp_file):
    """Verifica el cálculo del hash"""
    
    # --- MOCKING ---
    # Creamos un objeto falso. FileIntegrityMonitor creerá que es su base de datos.
    mock_db = MagicMock() 
    
    # Instanciamos pasando el mock
    fim = FileIntegrityMonitor(db_manager=mock_db) 
    
    # Probamos la función
    calculated_hash = fim.calculate_hash(str(temp_file))
    expected_hash = hashlib.sha256(b"Contenido Super Secreto").hexdigest()
    
    assert calculated_hash == expected_hash

# 3. TEST DETECCIÓN
def test_fim_detection(temp_file):
    """Simula modificación"""
    
    # --- MOCKING ---
    mock_db = MagicMock()
    fim = FileIntegrityMonitor(db_manager=mock_db)
    
    # A. Hash original
    hash_inicial = fim.calculate_hash(str(temp_file))
    
    # B. Modificación
    temp_file.write_text("HACKED BY RANSOMWARE")
    
    # C. Nuevo Hash
    hash_final = fim.calculate_hash(str(temp_file))
    
    assert hash_inicial != hash_final