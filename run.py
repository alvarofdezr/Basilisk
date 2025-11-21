# run.py
import os
from pysentinel.core.database import DatabaseManager
from pysentinel.modules.fim import FileIntegrityMonitor

def main():
    # 1. Inicializar Base de Datos
    db = DatabaseManager()
    
    # 2. Inicializar Módulo FIM
    fim = FileIntegrityMonitor(db)
    
    # CARPETA A VIGILAR (Crea una carpeta 'test_folder' para probar sin riesgo)
    target_folder = "./test_folder"
    
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
        print(f"Carpeta de prueba creada: {target_folder}. Añade archivos ahí.")

    try:
        fim.scan_directory(target_folder)
    except KeyboardInterrupt:
        print("\nDeteniendo PySentinel...")
    finally:
        db.close()

if __name__ == "__main__":
    main()