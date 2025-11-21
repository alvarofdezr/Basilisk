# gui.py
import customtkinter as ctk
import threading
import time
import sys
import os
from tkinter import messagebox
from pysentinel.core.database import DatabaseManager
from pysentinel.core.config import Config
from pysentinel.modules.fim import FileIntegrityMonitor
from pysentinel.modules.win_event_watcher import WindowsEventWatcher 
from pysentinel.modules.network_monitor import NetworkMonitor
from pysentinel.modules.usb_monitor import USBMonitor 
from pysentinel.utils.notifier import TelegramNotifier
from pysentinel.utils.system_monitor import get_system_metrics


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PySentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PySentinel - Security & Health Dashboard")
        self.geometry("1000x650") # Un poco más grande

        # --- LAYOUT PRINCIPAL ---
        # Columna 0: Sidebar (Fija) | Columna 1: Contenido Principal (Expandible)
        self.grid_columnconfigure(0, weight=0) 
        self.grid_columnconfigure(1, weight=1)
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

        # Título en Sidebar
        ctk.CTkLabel(self.sidebar_frame, text="PySentinel\nV 1.2", font=("Roboto Medium", 20, "bold")).pack(pady=20)

        # Botón de Vigilancia
        self.btn_scan = ctk.CTkButton(self.sidebar_frame, text="ACTIVAR VIGILANCIA", command=self.toggle_monitoring, fg_color="green")
        self.btn_scan.pack(pady=10, padx=20)

        # --- SECCIÓN: SALUD DEL SISTEMA ---
        ctk.CTkLabel(self.sidebar_frame, text="ESTADO DEL SISTEMA", font=("Roboto Medium", 14)).pack(pady=(30, 10))
        
        # CPU
        self.lbl_cpu = ctk.CTkLabel(self.sidebar_frame, text="CPU: 0%")
        self.lbl_cpu.pack(pady=(5,0))
        self.prog_cpu = ctk.CTkProgressBar(self.sidebar_frame, width=150, progress_color="#e74c3c") # Rojo
        self.prog_cpu.pack(pady=5)
        self.prog_cpu.set(0)

        # RAM
        self.lbl_ram = ctk.CTkLabel(self.sidebar_frame, text="RAM: 0%")
        self.lbl_ram.pack(pady=(10,0))
        self.prog_ram = ctk.CTkProgressBar(self.sidebar_frame, width=150, progress_color="#f1c40f") # Amarillo
        self.prog_ram.pack(pady=5)
        self.prog_ram.set(0)

        # DISCO
        self.lbl_disk = ctk.CTkLabel(self.sidebar_frame, text="DISCO: 0%")
        self.lbl_disk.pack(pady=(10,0))
        self.prog_disk = ctk.CTkProgressBar(self.sidebar_frame, width=150, progress_color="#3498db") # Azul
        self.prog_disk.pack(pady=5)
        self.prog_disk.set(0)

        # ==============================
        # 2. CONTENIDO PRINCIPAL (DERECHA)
        # ==============================
        
        # Tabs
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.tab_live = self.tab_view.add("Monitor en Vivo")
        self.tab_history = self.tab_view.add("Historial de Eventos")

        # Tab 1: Live
        self.tab_live.grid_columnconfigure(0, weight=1)
        self.tab_live.grid_rowconfigure(0, weight=1)
        self.textbox = ctk.CTkTextbox(self.tab_live, font=("Consolas", 12))
        self.textbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.textbox.insert("0.0", "Sistema listo.\n")

        # Tab 2: History
        self.tab_history.grid_columnconfigure(0, weight=1)
        self.tab_history.grid_rowconfigure(1, weight=1)
        self.btn_refresh = ctk.CTkButton(self.tab_history, text="🔄 Actualizar Historial", command=self.refresh_history)
        self.btn_refresh.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.history_box = ctk.CTkTextbox(self.tab_history, font=("Consolas", 12), state="disabled")
        self.history_box.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        # Frame para los botones (para que estén alineados)
        self.btn_frame = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        self.btn_frame.grid(row=0, column=0, padx=10, pady=10, sticky="e")

        # Botón Exportar (NUEVO)
        self.btn_export = ctk.CTkButton(self.btn_frame, text="💾 Exportar CSV", command=self.export_csv, fg_color="#d35400", width=100)
        self.btn_export.pack(side="left", padx=5)

        # Botón Actualizar (El que ya tenías, modificado ligeramente para estar en el frame)
        self.btn_refresh = ctk.CTkButton(self.btn_frame, text="🔄 Actualizar", command=self.refresh_history, width=100)
        self.btn_refresh.pack(side="left", padx=5)

        self.redirect_logging()
        self.refresh_history()
        
        # INICIAR LOOP DE RECURSOS (Se ejecuta cada 2 segundos automáticamente)
        self.update_system_stats()

    def update_system_stats(self):
        """Actualiza las barras de progreso de CPU/RAM"""
        stats = get_system_metrics()
        
        # Actualizar Labels
        self.lbl_cpu.configure(text=f"CPU: {stats['cpu']}%")
        self.lbl_ram.configure(text=f"RAM: {stats['ram']}%")
        self.lbl_disk.configure(text=f"DISCO: {stats['disk']}%")

        # Actualizar Barras (El valor va de 0.0 a 1.0)
        self.prog_cpu.set(stats['cpu'] / 100)
        self.prog_ram.set(stats['ram'] / 100)
        self.prog_disk.set(stats['disk'] / 100)

        # Volver a llamarse a sí mismo en 2000ms (2 segundos)
        self.after(2000, self.update_system_stats)

    def redirect_logging(self):
        class TextRedirector(object):
            def __init__(self, widget):
                self.widget = widget
            def write(self, str):
                try:
                    self.widget.configure(state="normal")
                    self.widget.insert("end", str)
                    self.widget.see("end")
                    self.widget.configure(state="disabled")
                except: pass
            def flush(self): pass
        sys.stdout = TextRedirector(self.textbox)

    def refresh_history(self):
        if not self.db_instance: return
        events = self.db_instance.get_recent_events()
        self.history_box.configure(state="normal")
        self.history_box.delete("0.0", "end")
        header = f"{'FECHA':<20} | {'TIPO':<6} | {'SEVERIDAD':<10} | {'MENSAJE'}\n"
        self.history_box.insert("end", header + "-"*90 + "\n")
        for (timestamp, type_, severity, msg) in events:
            self.history_box.insert("end", f"{timestamp:<20} | {type_:<6} | {severity:<10} | {msg}\n")
        self.history_box.configure(state="disabled")

    def toggle_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.btn_scan.configure(text="DETENER", fg_color="red")
            threading.Thread(target=self.monitor_loop, daemon=True).start()
        else:
            self.monitoring = False
            self.btn_scan.configure(text="ACTIVAR", fg_color="green")
            print("[*] Deteniendo vigilancia...")

    def monitor_loop(self):
        # Verificación de seguridad inicial
        if not self.db_instance:
            print("[ERROR] No hay conexión a la base de datos.")
            return

        # 1. Inicializar Notificaciones (Telegram)
        notifier = TelegramNotifier(self.config)
        
        # 2. Inicializar Monitor de Archivos (FIM)
        fim = FileIntegrityMonitor(self.db_instance)
        
        # 3. Inicializar Vigilante de Windows (REAL)
        # Usamos try/except para que si falla (por no ser admin), el resto siga funcionando
        win_watcher = None
        try:
            win_watcher = WindowsEventWatcher(self.db_instance, notifier)
            print("[*] Conexión establecida con Windows Event Logs.")
        except Exception as e:
            print(f"[ERROR CRÍTICO] No se pudo conectar a los logs de Windows: {e}")
            print("Asegúrate de ejecutar PySentinel como ADMINISTRADOR.")
            # No hacemos return aquí para permitir que los otros módulos funcionen

        # 4. Inicializar Monitor de Red (NetWatch)
        net_monitor = NetworkMonitor(self.db_instance, notifier, config=self.config)
        
        # 5. Inicializar Monitor USB (USB Sentry) - NUEVO
        usb_monitor = USBMonitor(self.db_instance, notifier)
        
        print("[*] VIGILANCIA TOTAL ACTIVA (Archivos + WinLogs + Red + USB).")

        while self.monitoring:
            # --- TAREA A: FIM (Archivos) ---
            for folder in self.config.directories:
                if not os.path.exists(folder):
                    try:
                        os.makedirs(folder)
                    except: continue
                fim.scan_directory(folder)
            
            # --- TAREA B: Windows Events (Intrusiones) ---
            if win_watcher:
                win_watcher.check_security_logs()
            
            # --- TAREA C: Monitor de Red (Conexiones) ---
            net_monitor.scan_connections()
            
            # --- TAREA D: Monitor USB (Físico) ---
            usb_monitor.check_usb_changes()
            
            # Descanso del ciclo
            time.sleep(3)
            
        print("[*] Sistema detenido.")

    def destroy(self):
        if self.db_instance: self.db_instance.close()
        super().destroy()

    def export_csv(self):
        if not self.db_instance:
            return
        
        # Nombre del archivo con fecha para que no se sobrescriba
        filename = f"reporte_seguridad_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        
        success, msg = self.db_instance.export_events_to_csv(filename)
        
        if success:
            messagebox.showinfo("Exportación Exitosa", f"Reporte guardado como:\n{msg}")
        else:
            messagebox.showerror("Error", f"No se pudo exportar:\n{msg}")

if __name__ == "__main__":
    app = PySentinelApp()
    app.mainloop()