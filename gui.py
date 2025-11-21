# gui.py
import customtkinter as ctk
import threading
import time
import sys
import os  # <--- Importante para crear carpetas

# Imports del proyecto
from pysentinel.core.database import DatabaseManager
from pysentinel.modules.fim import FileIntegrityMonitor
from pysentinel.modules.log_watcher import LogWatcher
from pysentinel.core.config import Config
from pysentinel.utils.notifier import TelegramNotifier 

# Configuración visual
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PySentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PySentinel - HIDS Monitor Activo")
        self.geometry("800x600")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.monitoring = False 

        # HEADER
        self.header_frame = ctk.CTkFrame(self)
        self.header_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        
        ctk.CTkLabel(self.header_frame, text="PySentinel Dashboard", font=("Roboto Medium", 20)).pack(pady=5)

        # BOTÓN DE CAMBIO DE ESTADO
        self.btn_scan = ctk.CTkButton(self.header_frame, text="ACTIVAR VIGILANCIA", command=self.toggle_monitoring, fg_color="green")
        self.btn_scan.pack(pady=10)

        # LOGS
        self.textbox = ctk.CTkTextbox(self, width=700, font=("Consolas", 12))
        self.textbox.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.textbox.insert("0.0", "Sistema en reposo. Configura config.yaml antes de iniciar.\n")
        
        self.redirect_logging()

    def redirect_logging(self):
        class TextRedirector(object):
            def __init__(self, widget):
                self.widget = widget
            def write(self, str):
                self.widget.configure(state="normal")
                self.widget.insert("end", str)
                self.widget.see("end")
                self.widget.configure(state="disabled")
            def flush(self): pass
        sys.stdout = TextRedirector(self.textbox)

    def toggle_monitoring(self):
        """Enciende o apaga el sistema de vigilancia"""
        if not self.monitoring:
            self.monitoring = True
            self.btn_scan.configure(text="DETENER VIGILANCIA", fg_color="red")
            # Lanzamos el hilo
            threading.Thread(target=self.monitor_loop, daemon=True).start()
        else:
            self.monitoring = False
            self.btn_scan.configure(text="ACTIVAR VIGILANCIA", fg_color="green")
            print("[*] Deteniendo vigilancia...")

    def monitor_loop(self):
        print("[*] CARGANDO CONFIGURACIÓN...")
        
        try:
            # 1. Cargar configuración
            config = Config()
            directorios = config.directories
            archivo_logs = config.log_file
            nombre_db = config.db_name
            
            print(f"[*] Configuración cargada correctamente.")
            print(f"    - DB: {nombre_db}")
            print(f"    - Directorios: {directorios}")
            print(f"    - Telegram Activo: {config.data.get('alerts', {}).get('telegram', {}).get('enabled')}")

        except Exception as e:
            print(f"[ERROR CRÍTICO] Fallo en configuración: {e}")
            self.monitoring = False
            self.btn_scan.configure(text="ACTIVAR VIGILANCIA", fg_color="green")
            return

        # 2. Inicializar el Notificador (Telegram)
        notifier = TelegramNotifier(config)

        # 3. Inicializar Base de Datos y Módulos
        db = DatabaseManager(db_name=nombre_db)
        fim = FileIntegrityMonitor(db)
        
        # Le pasamos el 'notifier' al LogWatcher
        log_watcher = LogWatcher(log_path=archivo_logs, notifier=notifier)
        
        print("[*] SISTEMA ARMADO Y VIGILANDO...")

        while self.monitoring:
            # --- TAREA 1: FIM (Integridad de Archivos) ---
            for folder in directorios:
                # Si la carpeta no existe, la creamos (Resiliencia)
                if not os.path.exists(folder):
                    try:
                        os.makedirs(folder)
                        print(f"[*] Aviso: Se creó la carpeta monitorizada -> {folder}")
                    except OSError as e:
                        print(f"[ERROR] No se pudo crear {folder}: {e}")
                        continue
                
                # Escaneamos la carpeta
                fim.scan_directory(folder)
            
            # --- TAREA 2: Log Watcher (Intrusiones) ---
            log_watcher.monitor_changes()
            
            # Esperamos 3 segundos
            time.sleep(3)
            
        db.close()
        print("[*] Sistema desarmado.")

if __name__ == "__main__":
    app = PySentinelApp()
    app.mainloop()