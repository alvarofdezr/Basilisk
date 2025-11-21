# gui.py (Versión 2.0 - Loop de Monitorización)
import customtkinter as ctk
import threading
import time
from pysentinel.core.database import DatabaseManager
from pysentinel.modules.fim import FileIntegrityMonitor
from pysentinel.modules.log_watcher import LogWatcher # <--- NUEVO IMPORT
import sys

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PySentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PySentinel - HIDS Monitor Activo")
        self.geometry("800x600")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.monitoring = False # Bandera para controlar el bucle

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
        self.textbox.insert("0.0", "Sistema en reposo.\n")
        
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
            # Lanzamos el hilo demonio (se cierra si cierras la app)
            threading.Thread(target=self.monitor_loop, daemon=True).start()
        else:
            self.monitoring = False
            self.btn_scan.configure(text="ACTIVAR VIGILANCIA", fg_color="green")
            print("[*] Deteniendo vigilancia...")

    def monitor_loop(self):
        print("[*] SISTEMA ARMADO Y VIGILANDO...")
        
        # Inicializar módulos
        db = DatabaseManager()
        fim = FileIntegrityMonitor(db)
        log_watcher = LogWatcher("server_logs.txt") # <--- Iniciamos el LogWatcher
        
        target_folder = "./test_folder"

        while self.monitoring:
            # 1. Tarea: Verificar Integridad de Archivos
            fim.scan_directory(target_folder)
            
            # 2. Tarea: Verificar Logs de Ataques
            log_watcher.monitor_changes()
            
            # Esperar 3 segundos antes del siguiente ciclo para no saturar CPU
            time.sleep(3)
            
        db.close()
        print("[*] Sistema desarmado.")

if __name__ == "__main__":
    app = PySentinelApp()
    app.mainloop()