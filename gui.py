# gui.py
import customtkinter as ctk
import threading
import time
import sys
import os
from tkinter import messagebox

# Imports del proyecto
from pysentinel.core.database import DatabaseManager
from pysentinel.modules.fim import FileIntegrityMonitor
from pysentinel.modules.win_event_watcher import WindowsEventWatcher
from pysentinel.modules.network_monitor import NetworkMonitor
from pysentinel.modules.usb_monitor import USBMonitor
from pysentinel.modules.port_monitor import PortMonitor
from pysentinel.core.config import Config
from pysentinel.utils.notifier import TelegramNotifier
from pysentinel.utils.system_monitor import get_system_metrics

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PySentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PySentinel - EDR Security Hub")
        self.geometry("1100x700")

        # --- LAYOUT PRINCIPAL ---
        self.grid_columnconfigure(0, weight=0) # Sidebar fija
        self.grid_columnconfigure(1, weight=1) # Contenido expandible
        self.grid_rowconfigure(0, weight=1)

        self.monitoring = False 
        
        # Carga de Config/DB
        try:
            self.config = Config()
            self.db_instance = DatabaseManager(db_name=self.config.db_name)
        except Exception as e:
            print(f"[ERROR] {e}")
            self.db_instance = None

        # ==============================
        # 1. SIDEBAR (IZQUIERDA)
        # ==============================
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(self.sidebar_frame, text="PySentinel\nEDR Core", font=("Roboto Medium", 20, "bold")).pack(pady=20)

        self.btn_scan = ctk.CTkButton(self.sidebar_frame, text="ACTIVAR VIGILANCIA", command=self.toggle_monitoring, fg_color="green")
        self.btn_scan.pack(pady=10, padx=20)

        # --- SECCIÓN: SALUD ---
        ctk.CTkLabel(self.sidebar_frame, text="ESTADO DEL SISTEMA", font=("Roboto Medium", 14)).pack(pady=(30, 10))
        
        self.lbl_cpu = ctk.CTkLabel(self.sidebar_frame, text="CPU: 0%")
        self.lbl_cpu.pack(pady=(5,0))
        self.prog_cpu = ctk.CTkProgressBar(self.sidebar_frame, width=150, progress_color="#e74c3c")
        self.prog_cpu.pack(pady=5)
        self.prog_cpu.set(0)

        self.lbl_ram = ctk.CTkLabel(self.sidebar_frame, text="RAM: 0%")
        self.lbl_ram.pack(pady=(10,0))
        self.prog_ram = ctk.CTkProgressBar(self.sidebar_frame, width=150, progress_color="#f1c40f")
        self.prog_ram.pack(pady=5)
        self.prog_ram.set(0)

        # ==============================
        # 2. CONTENIDO PRINCIPAL (DERECHA)
        # ==============================
        
        # TabView Principal
        self.main_tabs = ctk.CTkTabview(self)
        self.main_tabs.grid(row=0, column=1, padx=20, pady=10, sticky="nsew")
        
        self.tab_monitor = self.main_tabs.add("Monitor en Vivo")
        self.tab_history = self.main_tabs.add("Historial de Eventos")

        # --- DENTRO DE "MONITOR EN VIVO": SUB-CATEGORÍAS ---
        self.tab_monitor.grid_columnconfigure(0, weight=1)
        self.tab_monitor.grid_rowconfigure(0, weight=1)

        self.monitor_cats = ctk.CTkTabview(self.tab_monitor, height=500)
        self.monitor_cats.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        # Creamos las sub-pestañas
        self.cat_general = self.monitor_cats.add("General")
        self.cat_network = self.monitor_cats.add("🌐 Red")
        self.cat_ports   = self.monitor_cats.add("🚪 Puertos")
        self.cat_files   = self.monitor_cats.add("📂 Archivos")
        self.cat_system  = self.monitor_cats.add("⚙️ Sistema") # USB y Windows Logs

        # Creamos las Cajas de Texto para cada categoría
        # Usamos un diccionario para guardarlas y acceder fácil
        self.log_boxes = {}

        def create_log_box(parent, key):
            parent.grid_columnconfigure(0, weight=1)
            parent.grid_rowconfigure(0, weight=1)
            box = ctk.CTkTextbox(parent, font=("Consolas", 12))
            box.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
            box.insert("0.0", "--- Esperando eventos ---\n")
            self.log_boxes[key] = box

        create_log_box(self.cat_general, "GENERAL")
        create_log_box(self.cat_network, "NET")
        create_log_box(self.cat_ports, "PORT")
        create_log_box(self.cat_files, "FILE") # Usaremos para FIM
        create_log_box(self.cat_system, "SYS") # Usaremos para USB y WinLogs

        # --- PESTAÑA HISTORIAL ---
        self.tab_history.grid_columnconfigure(0, weight=1)
        self.tab_history.grid_rowconfigure(1, weight=1)
        
        self.btn_frame = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        self.btn_frame.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        
        self.btn_export = ctk.CTkButton(self.btn_frame, text="💾 Exportar CSV", command=self.export_csv, fg_color="#d35400", width=100)
        self.btn_export.pack(side="left", padx=5)
        self.btn_refresh = ctk.CTkButton(self.btn_frame, text="🔄 Actualizar", command=self.refresh_history, width=100)
        self.btn_refresh.pack(side="left", padx=5)

        self.history_box = ctk.CTkTextbox(self.tab_history, font=("Consolas", 12), state="disabled")
        self.history_box.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        # INICIAR EL ENRUTADOR DE LOGS INTELIGENTE
        self.redirect_logging()
        
        # Iniciar métricas y cargar historial
        self.update_system_stats()
        self.refresh_history()

    def redirect_logging(self):
        """
        MAGIA DE INGENIERÍA:
        Intercepta 'print()' y decide a qué caja de texto enviarlo según su etiqueta.
        """
        app_ref = self # Referencia a la app para usar dentro de la clase

        class SmartLogRouter(object):
            def write(self, text):
                if not text.strip(): return # Ignorar líneas vacías

                # Siempre escribimos en GENERAL (Log Maestro)
                app_ref.safe_write(app_ref.log_boxes["GENERAL"], text)

                # Enrutamiento por Etiquetas (Tags)
                if "[NET]" in text:
                    app_ref.safe_write(app_ref.log_boxes["NET"], text)
                elif "[PORT]" in text:
                    app_ref.safe_write(app_ref.log_boxes["PORT"], text)
                elif "[USB]" in text or "[ALERTA REAL]" in text:
                    app_ref.safe_write(app_ref.log_boxes["SYS"], text)
                elif "NUEVO ARCHIVO" in text or "MODIFICADO" in text:
                    app_ref.safe_write(app_ref.log_boxes["FILE"], text)
            
            def flush(self): pass

        sys.stdout = SmartLogRouter()

    def safe_write(self, widget, text):
        """Escribe en la GUI de forma segura (Thread-Safe)"""
        try:
            widget.configure(state="normal")
            widget.insert("end", text + "\n") # Añadimos salto de línea
            widget.see("end")
            widget.configure(state="disabled")
        except: pass

    def update_system_stats(self):
        try:
            stats = get_system_metrics()
            self.lbl_cpu.configure(text=f"CPU: {stats['cpu']}%")
            self.prog_cpu.set(stats['cpu'] / 100)
            self.lbl_ram.configure(text=f"RAM: {stats['ram']}%")
            self.prog_ram.set(stats['ram'] / 100)
        except: pass
        self.after(2000, self.update_system_stats)

    def refresh_history(self):
        if not self.db_instance: return
        events = self.db_instance.get_recent_events()
        self.history_box.configure(state="normal")
        self.history_box.delete("0.0", "end")
        header = f"{'FECHA':<20} | {'TIPO':<10} | {'MENSAJE'}\n"
        self.history_box.insert("end", header + "-"*100 + "\n")
        for (timestamp, type_, severity, msg) in events:
            # Limpiamos saltos de línea en el mensaje para que la tabla no se rompa
            clean_msg = msg.replace('\n', ' ').replace('\r', '')[:80] 
            self.history_box.insert("end", f"{timestamp:<20} | {type_:<10} | {clean_msg}\n")
        self.history_box.configure(state="disabled")

    def export_csv(self):
        if not self.db_instance: return
        filename = f"reporte_seguridad_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        success, msg = self.db_instance.export_events_to_csv(filename)
        if success: messagebox.showinfo("Exportación", f"Guardado en:\n{msg}")
        else: messagebox.showerror("Error", msg)

    def toggle_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.btn_scan.configure(text="DETENER VIGILANCIA", fg_color="red")
            threading.Thread(target=self.monitor_loop, daemon=True).start()
        else:
            self.monitoring = False
            self.btn_scan.configure(text="ACTIVAR VIGILANCIA", fg_color="green")
            print("[*] Deteniendo vigilancia...")

    def monitor_loop(self):
        if not self.db_instance: return
        
        # Inicializar Componentes
        notifier = TelegramNotifier(self.config)
        fim = FileIntegrityMonitor(self.db_instance)
        net_monitor = NetworkMonitor(self.db_instance, notifier, config=self.config)
        usb_monitor = USBMonitor(self.db_instance, notifier)
        port_monitor = PortMonitor(self.db_instance, notifier)
        
        win_watcher = None
        try: win_watcher = WindowsEventWatcher(self.db_instance, notifier)
        except: pass
        
        print(f"[*] SISTEMA INICIADO. Módulos activos: FIM, NET, PORT, USB, WINLOGS")

        while self.monitoring:
            # A: FIM
            for folder in self.config.directories:
                if not os.path.exists(folder):
                    try: os.makedirs(folder)
                    except: continue
                fim.scan_directory(folder)

            # B: Windows Logs
            if win_watcher: win_watcher.check_security_logs()

            # C: Red
            net_monitor.scan_connections()

            # D: USB
            usb_monitor.check_usb_changes()

            # E: Puertos
            port_monitor.scan_ports()

            time.sleep(3)
            
        print("[*] Sistema detenido.")

    def destroy(self):
        if self.db_instance: self.db_instance.close()
        super().destroy()

if __name__ == "__main__":
    app = PySentinelApp()
    app.mainloop()