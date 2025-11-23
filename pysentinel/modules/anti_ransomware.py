import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pysentinel.core.active_response import kill_process_by_pid

# Configuración de la trampa
CANARY_FOLDER = os.path.join(os.path.expanduser("~"), ".pysentinel_trap")
CANARY_FILES = {
    "passwords_2024.docx": "Contenido falso para atraer ransomware...",
    "bitcoin_wallet.dat": "Hex data fake...",
    "nomina_confidencial.xlsx": "Datos financieros falsos..."
}
class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, callback_func):
        self.callback_func = callback_func  # Guardamos la función de la GUI

    def on_modified(self, event):
        self._trigger_alarm(event, "MODIFICADO")

    def on_deleted(self, event):
        self._trigger_alarm(event, "ELIMINADO")

    def _trigger_alarm(self, event, tipo):
        if event.is_directory:
            return
        
        msg = f"RANSOMWARE DETECTADO: {event.src_path} ({tipo})"
        logging.critical(msg)
        
        # LLAMAMOS A LA GUI AQUI
        if self.callback_func:
            self.callback_func(msg)

class CanarySentry:
    def __init__(self, on_detection_callback=None):
        self.observer = Observer()
        # Pasamos el callback al Handler
        self.handler = RansomwareHandler(callback_func=on_detection_callback)
        self.trap_dir = CANARY_FOLDER

    def deploy_trap(self):
        # ... (Igual que antes: crea carpeta y archivos) ...
        if not os.path.exists(self.trap_dir):
            os.makedirs(self.trap_dir)
            try:
                os.system(f'attrib +h "{self.trap_dir}"') # Ocultar en Windows
            except:
                pass
        
        # Recrear archivos si no existen (Auto-healing)
        from pysentinel.modules.anti_ransomware import CANARY_FILES # Import local o usar la var global
        for filename, content in CANARY_FILES.items():
            path = os.path.join(self.trap_dir, filename)
            if not os.path.exists(path):
                with open(path, 'w') as f:
                    f.write(content)

    def start(self):
        self.deploy_trap()
        self.observer.schedule(self.handler, self.trap_dir, recursive=False)
        self.observer.start()
    
    def stop(self):
        self.observer.stop()
        self.observer.join()