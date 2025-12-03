# tests/test_integration.py
import pytest
import os
import time
import threading
from unittest.mock import MagicMock, patch

# Importamos tus módulos reales
from basilisk.core.database import Config
from basilisk.modules.fim import FileIntegrityMonitor
from basilisk.modules.anti_ransomware import CanarySentry
from basilisk.modules.network_monitor import NetworkMonitor

# --- FIXTURES (Configuración previa a cada test) ---

@pytest.fixture
def test_db(tmp_path):
    """Crea una base de datos real pero temporal para el test"""
    db_file = tmp_path / "test_basilisk.db"
    db = Config(db_name=str(db_file))
    return db

@pytest.fixture
def test_folder(tmp_path):
    """Crea una carpeta vacía para jugar con archivos"""
    d = tmp_path / "vulnerable_folder"
    d.mkdir()
    return d

@pytest.fixture
def mock_config():
    """Simula una configuración con el Kill Switch ACTIVADO"""
    conf = MagicMock()
    conf.active_response = True  # ¡Importante!
    conf.network_whitelist = ["chrome.exe", "python.exe"] # Whitelist básica
    return conf

# --- TEST 1: AUTOMATIZAR EL FIM ---
def test_fim_full_cycle(test_db, test_folder):
    """Prueba el ciclo completo: Baseline -> Modificación -> Detección"""
    fim = FileIntegrityMonitor(test_db)
    target_file = test_folder / "passwords.txt"
    
    # 1. Estado Inicial: Creamos archivo
    target_file.write_text("password123")
    
    # 2. Tomamos la FOTO (Baseline)
    # Nota: Usamos una lista para capturar el callback de progreso si quieres probarlo, o None
    fim.scan_directory(str(test_folder), mode="baseline")
    
    # 3. EL ATAQUE: Modificamos el archivo
    time.sleep(1) # Asegurar cambio de timestamp
    target_file.write_text("HACKED_BY_ALVARO")
    
    # 4. VIGILANCIA: Escaneamos de nuevo
    # Capturamos los logs o verificamos la BD
    fim.scan_directory(str(test_folder), mode="monitor")
    
    # 5. VERIFICACIÓN: Consultamos la BD real a ver si se registró
    events = test_db.get_recent_events()
    
    # Buscamos si hay algún evento CRITICAL de tipo FILE_MOD
    found = any("MODIFICADO" in e[3] and "CRITICAL" in e[2] for e in events)
    assert found, "El FIM falló: No se generó evento CRÍTICO en la base de datos tras la modificación."

# --- TEST 2: AUTOMATIZAR ANTI-RANSOMWARE ---
def test_ransomware_trigger(tmp_path):
    """Prueba que tocar la trampa dispara la alarma"""
    
    # Mockeamos el callback (la función que pondría la pantalla roja)
    mock_alert_callback = MagicMock()
    
    # Iniciamos el Centinela
    sentry = CanarySentry(on_detection_callback=mock_alert_callback)
    
    # Forzamos la carpeta trampa a ser una temporal del test para no ensuciar tu usuario
    trap_dir = tmp_path / ".test_trap"
    sentry.trap_dir = str(trap_dir)
    
    try:
        sentry.start()
        time.sleep(1) # Esperar a que Watchdog arranque
        
        # EL ATAQUE: Borrar un archivo trampa
        # Primero aseguramos que existan (el start los crea)
        victim_file = trap_dir / "passwords_2024.docx"
        if victim_file.exists():
            victim_file.write_text("Ransomware was here") # Modificar
        
        time.sleep(2) # Dar tiempo al hilo de Watchdog
        
        # VERIFICACIÓN: ¿Se llamó a la alerta?
        if mock_alert_callback.called:
            print("\n[TEST] ¡El sistema detectó el ataque ransomware!")
        else:
            pytest.fail("El Watchdog no detectó la modificación del archivo trampa.")
            
    finally:
        sentry.stop()

# --- TEST 3: AUTOMATIZAR BLOQUEO DE RED (SIMULADO) ---
def test_network_blocking_logic(test_db, mock_config):
    """
    Simula que 'malware.exe' se conecta a internet y verifica 
    que basilisk INTENTA matarlo.
    """
    mock_notifier = MagicMock()
    net_mon = NetworkMonitor(test_db, mock_notifier, mock_config)
    
    # MOCKEAMOS psutil para inventarnos una conexión peligrosa
    # No queremos matar procesos reales en el test
    with patch('psutil.net_connections') as mock_conns, \
        patch('psutil.Process') as MockProcess:
        
        # 1. Preparamos la mentira: "Hay una conexión de malware.exe"
        fake_conn = MagicMock()
        fake_conn.status = 'ESTABLISHED'
        fake_conn.pid = 666
        fake_conn.raddr.ip = "1.2.3.4" # IP remota
        fake_conn.raddr.port = 80
        
        mock_conns.return_value = [fake_conn]
        
        # 2. Preparamos el proceso falso
        process_instance = MockProcess.return_value
        process_instance.name.return_value = "malware.exe" # ¡No está en whitelist!
        process_instance.pid = 666
        
        # 3. EJECUTAMOS EL ESCÁNER
        net_mon.scan_connections()
        
        # 4. VERIFICACIÓN: ¿Ordenó matar al proceso?
        # Verificamos si llamó a process.kill()
        if process_instance.kill.called:
            print("\n[TEST] ¡Disparo confirmado! El EDR intentó matar a malware.exe")
        else:
            pytest.fail("El EDR dejó pasar a malware.exe y no lo mató.")
            
        # 5. Verificamos que se guardó en la BD
        events = test_db.get_recent_events()
        assert any("malware.exe" in e[3] for e in events), "No se registró el bloqueo en la BD"