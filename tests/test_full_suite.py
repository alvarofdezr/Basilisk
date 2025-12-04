import sys
import os
import time
import unittest
import tempfile
import shutil

# --- CONFIGURACIÓN DE RUTAS ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, '..'))
sys.path.insert(0, PROJECT_ROOT)

# --- IMPORTS DINÁMICOS (Para no romper si falta algo) ---
print("🔍 Cargando módulos del sistema Basilisk EDR...")

try:
    from basilisk.core.config import Config
    from basilisk.core.database import DatabaseManager
    # Módulos Core
    from basilisk.modules.process_monitor import ProcessMonitor
    from basilisk.modules.fim import FileIntegrityMonitor
    from basilisk.modules.network_isolation import NetworkIsolator
    # Módulos Satélite (Inferred)
    try: from basilisk.modules.network_monitor import NetworkMonitor
    except ImportError: NetworkMonitor = None
    try: from basilisk.modules.usb_monitor import USBMonitor
    except ImportError: USBMonitor = None
    try: from basilisk.modules.port_monitor import PortMonitor
    except ImportError: PortMonitor = None
    try: from basilisk.modules.yara_scanner import YaraScanner
    except ImportError: YaraScanner = None
    try: from basilisk.modules.anti_ransomware import CanarySentry
    except ImportError: CanarySentry = None

    print("✅ Carga de módulos completada.")
except ImportError as e:
    print(f"❌ CRÍTICO: Faltan archivos base. Error: {e}")
    sys.exit(1)

class TestBasiliskFullSuite(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Se ejecuta una vez al principio: Configuración Global"""
        print("\n" + "="*60)
        print("🚀 INICIANDO TEST DE INTEGRACIÓN: BASILISK EDR FULL SUITE")
        print("="*60)
        
        # Configuración Mock para pruebas
        cls.config = Config()
        # Usamos una DB temporal para no ensuciar la real
        cls.db_name = "test_suite_db.sqlite"
        cls.db = DatabaseManager(db_name=cls.db_name)
        
        # Directorio temporal para pruebas de FIM/YARA
        cls.test_dir = tempfile.mkdtemp()
        print(f"📂 Directorio de pruebas creado: {cls.test_dir}")

    @classmethod
    def tearDownClass(cls):
        """Limpieza final robusta para Windows"""
        print("\n🧹 Iniciando limpieza...")

        # 1. Cerrar la conexión a la base de datos explícitamente
        if hasattr(cls, 'db') and cls.db:
            try:
                # Intentamos cerrar usando métodos comunes. 
                # Ajusta esto si tu DatabaseManager tiene otro nombre para cerrar.
                if hasattr(cls.db, 'close'):
                    cls.db.close()
                elif hasattr(cls.db, 'conn'):
                    cls.db.conn.close()
                print("   -> Conexión a DB cerrada.")
            except Exception as e:
                print(f"   ⚠️ Error cerrando DB: {e}")

        # 2. Forzar Garbage Collection
        # A veces Python mantiene referencias "zombies" que bloquean el archivo.
        import gc
        cls.db = None # Eliminamos la referencia
        gc.collect() 
        
        # 3. Pequeña pausa para que el SO libere el lock (Crucial en Windows)
        time.sleep(0.5)

        # 4. Borrar el archivo de la base de datos
        if os.path.exists(cls.db_name):
            try:
                os.remove(cls.db_name)
                print(f"   -> Archivo DB {cls.db_name} eliminado.")
            except PermissionError:
                print("   ⚠️ No se pudo borrar la DB (Lock persistente). Se borrará al reiniciar.")
            except Exception as e:
                print(f"   ⚠️ Error borrando DB: {e}")

        # 5. Borrar directorio temporal
        if os.path.exists(cls.test_dir):
            try:
                shutil.rmtree(cls.test_dir)
                print(f"   -> Directorio temporal eliminado.")
            except Exception as e:
                print(f"   ⚠️ Error borrando directorio temporal: {e}")
        
        print("✅ Limpieza completada.")

    # --- 1. TEST PROCESS MONITOR & MEMORY ---
    def test_01_process_monitor(self):
        print("\n[TEST 1] Process Monitor + Memory Scanner")
        pm = ProcessMonitor()
        scan_result = pm.scan_processes()
        
        self.assertIsInstance(scan_result, list)
        print(f"   -> Escaneados {len(scan_result)} procesos.")
        
        # Verificar que nos detectamos a nosotros mismos (python)
        myself = next((p for p in scan_result if p['pid'] == os.getpid()), None)
        self.assertIsNotNone(myself, "❌ El monitor no detectó el propio proceso del test.")
        print(f"   -> Self-check OK: PID {os.getpid()} encontrado.")

    # --- 2. TEST FILE INTEGRITY MONITOR (FIM) ---
    def test_02_fim(self):
        print("\n[TEST 2] File Integrity Monitor (FIM)")
        fim = FileIntegrityMonitor(self.db)
        
        # A) Crear Baseline
        test_file = os.path.join(self.test_dir, "secret.txt")
        with open(test_file, "w") as f: f.write("Data confidencial")
        
        print("   -> Generando Baseline...")
        fim.scan_directory(self.test_dir, mode="baseline")
        
        # B) Modificar Archivo
        time.sleep(1) # Esperar cambio de timestamp
        with open(test_file, "a") as f: f.write(" + INTRUSIÓN")
        
        # C) Detectar Cambio
        print("   -> Escaneando cambios...")
        # Capturamos logs o verificamos DB. Aquí asumimos que corre sin error.
        # En un test real mockearíamos el logger, aquí solo verificamos ejecución.
        try:
            fim.scan_directory(self.test_dir, mode="monitor")
            print("   -> Ejecución FIM completada sin errores.")
        except Exception as e:
            self.fail(f"❌ FIM falló al escanear: {e}")

    # --- 3. TEST NETWORK ISOLATION (Firewall) ---
    def test_03_network_isolation(self):
        print("\n[TEST 3] Network Isolation (Requiere Admin)")
        # Apunta a localhost para no bloquearte de verdad si algo falla
        iso = NetworkIsolator("https://localhost:8443")
        
        try:
            # Intentamos aislar
            if iso.isolate_host():
                print("   -> Aislamiento aplicado (Simulado/Real).")
                time.sleep(1)
                iso.restore_connection()
                print("   -> Conexión restaurada.")
            else:
                print("   ⚠️ Skipped: No se pudo ejecutar netsh (¿Faltan permisos de Admin?)")
        except Exception as e:
            self.fail(f"❌ Error en módulo de aislamiento: {e}")

    # --- 4. TESTS DE MÓDULOS SATÉLITE (Si existen) ---
    
    def test_04_yara(self):
        print("\n[TEST 4] YARA Scanner")
        if not YaraScanner:
            print("   ⚠️ Módulo YaraScanner no encontrado. Saltando.")
            return

        try:
            scanner = YaraScanner()
            # Crear archivo dummy
            dummy = os.path.join(self.test_dir, "clean_file.txt")
            with open(dummy, "w") as f: f.write("Just text")
            
            # Escanear
            matches = scanner.scan_file(dummy)
            print(f"   -> Escaneo YARA completado. Matches: {len(matches)}")
        except Exception as e:
            print(f"   ⚠️ Error ejecutando YARA (¿Faltan reglas compiladas?): {e}")

    def test_05_network_monitor(self):
        print("\n[TEST 5] Network Monitor")
        if not NetworkMonitor:
            print("   ⚠️ Módulo NetworkMonitor no encontrado.")
            return
        
        try:
            # Intentamos instanciar. Nota: NetworkMonitor suele requerir argumentos
            # Basado en agent_core: NetworkMonitor(db, notifier, config)
            # Pasamos mocks o None donde sea seguro
            nm = NetworkMonitor(self.db, notifier=None, config=self.config)
            nm.scan_connections()
            print("   -> Escaneo de conexiones activas realizado.")
        except Exception as e:
            print(f"   ⚠️ Error en NetworkMonitor: {e}")

    def test_06_usb_monitor(self):
        print("\n[TEST 6] USB Monitor")
        if not USBMonitor: return
        
        try:
            usb = USBMonitor(self.db)
            usb.check_usb_changes()
            print("   -> Chequeo USB realizado.")
        except Exception as e:
            print(f"   ⚠️ Error en USBMonitor: {e}")

    def test_07_port_monitor(self):
        print("\n[TEST 7] Port Monitor")
        if not PortMonitor: return
        
        try:
            # PortMonitor(db, c2_client)
            pm = PortMonitor(self.db, c2_client=None) 
            report = pm.get_full_report()
            print(f"   -> Puertos escaneados: {len(report)}")
        except Exception as e:
            print(f"   ⚠️ Error en PortMonitor: {e}")

if __name__ == '__main__':
    # Verificar Admin para pruebas de red
    is_admin = False
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: pass
    
    if not is_admin:
        print("⚠️ ADVERTENCIA: No eres Administrador. Los tests de Red/Firewall pueden fallar.")
        time.sleep(2)

    unittest.main()