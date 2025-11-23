# gui.py
import customtkinter as ctk
import threading
import time
import sys
import os
import hashlib
from tkinter import messagebox

# Imports locales
from pysentinel.core.database import DatabaseManager
from pysentinel.core.config import Config
from pysentinel.utils.notifier import TelegramNotifier
from pysentinel.utils.system_monitor import get_system_metrics

from pysentinel.modules.fim import FileIntegrityMonitor
from pysentinel.modules.network_monitor import NetworkMonitor
from pysentinel.modules.usb_monitor import USBMonitor
from pysentinel.modules.port_monitor import PortMonitor
from pysentinel.modules.anti_ransomware import CanarySentry
from pysentinel.modules.win_event_watcher import WindowsEventWatcher

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PySentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PySentinel v4.2 - Enterprise EDR")
        self.geometry("1200x750")
        
        self.monitoring = False
        self.db_instance = None
        self.config = None

        self._init_backend()
        self._init_ui()
        # Inicializamos la redirección de logs correctamente
        self._redirect_stdout()
        
        self.update_system_stats()
        self.refresh_history()

    def _init_backend(self):
        try:
            self.config = Config()
            self.db_instance = DatabaseManager(db_name=self.config.db_name)
        except Exception as e:
            messagebox.showerror("Error", f"Fallo crítico: {e}")
            self.destroy()

    def _init_ui(self):
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_content()

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(10, weight=1)

        ctk.CTkLabel(self.sidebar, text="PySentinel\nEDR Core", 
                     font=("Roboto", 22, "bold")).pack(pady=25)

        # Botón Vigilancia
        self.btn_scan = ctk.CTkButton(self.sidebar, text="ACTIVAR VIGILANCIA", 
                                      command=self.toggle_monitoring, 
                                      fg_color="#27ae60", hover_color="#2ecc71", 
                                      height=40, font=("Roboto", 12, "bold"))
        self.btn_scan.pack(pady=10, padx=20, fill="x")

        # Botón Baseline
        self.btn_baseline = ctk.CTkButton(self.sidebar, text="ACTUALIZAR BASELINE", 
                                          command=self.create_baseline, 
                                          fg_color="#2980b9", hover_color="#3498db",
                                          height=40)
        self.btn_baseline.pack(pady=5, padx=20, fill="x")

        # Barra de Carga (Oculta por defecto)
        self.lbl_progress = ctk.CTkLabel(self.sidebar, text="Analizando...", font=("Roboto", 10))
        self.progress_bar = ctk.CTkProgressBar(self.sidebar, width=160, progress_color="#3498db")
        self.progress_bar.set(0)

        # Botón Auditoría Puertos
        self.btn_ports = ctk.CTkButton(self.sidebar, text="🔍 AUDITORÍA PUERTOS", 
                                          command=self.show_port_audit, 
                                          fg_color="#8e44ad", hover_color="#9b59b6",
                                          height=40)
        self.btn_ports.pack(pady=5, padx=20, fill="x")

        # Recursos
        ctk.CTkLabel(self.sidebar, text="RECURSOS DEL SISTEMA", 
                     font=("Roboto", 12, "bold"), text_color="gray70").pack(pady=(40, 10))
        
        self.lbl_cpu = ctk.CTkLabel(self.sidebar, text="CPU: 0%")
        self.lbl_cpu.pack(pady=2)
        self.prog_cpu = ctk.CTkProgressBar(self.sidebar, width=160, progress_color="#e74c3c")
        self.prog_cpu.pack(pady=5)
        self.prog_cpu.set(0)

        self.lbl_ram = ctk.CTkLabel(self.sidebar, text="RAM: 0%")
        self.lbl_ram.pack(pady=2)
        self.prog_ram = ctk.CTkProgressBar(self.sidebar, width=160, progress_color="#f1c40f")
        self.prog_ram.pack(pady=5)
        self.prog_ram.set(0)

    def _build_main_content(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=0, column=1, padx=20, pady=10, sticky="nsew")
        
        self.tab_live = self.tabs.add("Monitor en Vivo")
        self.tab_history = self.tabs.add("Historial y Auditoría")

        # Tab Live
        self.tab_live.grid_columnconfigure(0, weight=1)
        self.tab_live.grid_rowconfigure(0, weight=1)
        self.logs_tabs = ctk.CTkTabview(self.tab_live)
        self.logs_tabs.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        self.log_widgets = {}
        categories = {"GENERAL": "General", "NET": "🌐 Red", "PORT": "🚪 Puertos", "FILE": "📂 Archivos", "SYS": "⚙️ Sistema"}

        for key, title in categories.items():
            tab = self.logs_tabs.add(title)
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)
            textbox = ctk.CTkTextbox(tab, font=("Consolas", 11), activate_scrollbars=True)
            textbox.grid(row=0, column=0, sticky="nsew")
            textbox.insert("0.0", f"--- Log iniciado: {title} ---\n")
            textbox.configure(state="disabled")
            self.log_widgets[key] = textbox

        # Tab History
        self.tab_history.grid_columnconfigure(0, weight=1)
        self.tab_history.grid_rowconfigure(1, weight=1)
        controls = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        controls.grid(row=0, column=0, sticky="e", padx=10, pady=5)
        ctk.CTkButton(controls, text="Exportar CSV", command=self.export_csv, width=100, fg_color="#d35400").pack(side="left", padx=5)
        ctk.CTkButton(controls, text="Refrescar", command=self.refresh_history, width=100).pack(side="left", padx=5)
        self.history_box = ctk.CTkTextbox(self.tab_history, font=("Consolas", 11), state="disabled")
        self.history_box.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

    def _redirect_stdout(self):
        """Intercepta los print() para enviarlos a la GUI"""
        app = self
        class LogRouter:
            def write(self, text):
                if not text.strip(): return
                
                # Enviamos al log general
                app._safe_log_write(app.log_widgets["GENERAL"], text)
                
                # Clasificamos por etiquetas
                target = None
                if "[NET]" in text: target = "NET"
                elif "[PORT]" in text: target = "PORT"
                elif "[USB]" in text or "[WIN]" in text or "[ALERTA REAL]" in text: target = "SYS"
                elif "[FIM]" in text or "ARCHIVO" in text or "RANSOMWARE" in text: target = "FILE"
                
                if target: app._safe_log_write(app.log_widgets[target], text)

            def flush(self): pass
        
        # --- CORRECCIÓN AQUÍ: Añadidos paréntesis () para instanciar la clase ---
        sys.stdout = LogRouter() 

    def _safe_log_write(self, widget, text):
        def _update():
            try:
                widget.configure(state="normal")
                widget.insert("end", text + "\n")
                widget.see("end")
                widget.configure(state="disabled")
            except: pass
        self.after(0, _update)

    # --- SEGURIDAD ---
    def verify_admin(self):
        if not self.config.admin_hash:
            messagebox.showwarning("Seguridad", "No se ha configurado 'admin_password_hash'. Acceso permitido.")
            return True

        dialog = ctk.CTkInputDialog(text="Autorización requerida.\nContraseña de Administrador:", title="Security Check")
        pwd = dialog.get_input()
        if not pwd: return False
        
        # SHA-512
        input_hash = hashlib.sha512(pwd.encode()).hexdigest()
        
        if input_hash == self.config.admin_hash:
            return True
        else:
            messagebox.showerror("Acceso Denegado", "Credenciales inválidas.")
            return False

    # --- AUDITORÍA PUERTOS ---
    def show_port_audit(self):
        if not self.db_instance: return

        audit_window = ctk.CTkToplevel(self)
        audit_window.title("Auditoría de Puertos y Servicios")
        audit_window.geometry("750x500")
        audit_window.attributes("-topmost", True)

        ctk.CTkLabel(audit_window, text="LISTADO DE PUERTOS ABIERTOS (LISTENING)", 
                     font=("Roboto", 18, "bold")).pack(pady=10)

        scroll_frame = ctk.CTkScrollableFrame(audit_window, width=700, height=400)
        scroll_frame.pack(pady=10, padx=10, fill="both", expand=True)

        headers = ["PUERTO", "PROTO", "SERVICIO", "PROCESO", "PID"]
        for i, h in enumerate(headers):
            lbl = ctk.CTkLabel(scroll_frame, text=h, font=("Consolas", 12, "bold"), 
                               fg_color="gray30", corner_radius=5, width=130)
            lbl.grid(row=0, column=i, padx=2, pady=5, sticky="ew")

        # Instancia temporal para leer reporte
        pm = PortMonitor(self.db_instance, None) 
        report = pm.get_full_report()

        if not report:
            ctk.CTkLabel(scroll_frame, text="No se detectaron puertos o faltan permisos.").grid(row=1, column=0, columnspan=5, pady=20)
            return

        for idx, row in enumerate(report, start=1):
            bg_color = "gray15" if idx % 2 == 0 else "transparent"
            values = [str(row['port']), row['proto'], row['service'], row['process'], str(row['pid'])]
            
            for col_idx, val in enumerate(values):
                lbl = ctk.CTkLabel(scroll_frame, text=val, font=("Consolas", 11), 
                                   fg_color=bg_color, width=130, anchor="w")
                lbl.grid(row=idx, column=col_idx, padx=2, pady=1, sticky="ew")
                
        for i in range(5): scroll_frame.grid_columnconfigure(i, weight=1)

    # --- BASELINE Y FIM ---
    def count_total_files(self, directories):
        total = 0
        for folder in directories:
            folder = folder.strip('"').strip("'")
            if os.path.exists(folder):
                for _, _, files in os.walk(folder):
                    total += len(files)
        return total

    def create_baseline(self):
        if not self.db_instance or not self.verify_admin():
            return

        self.btn_baseline.configure(state="disabled", text="Procesando...")
        self.progress_bar.set(0)
        self.lbl_progress.pack(pady=(10, 0)) 
        self.progress_bar.pack(pady=5, padx=20)
        
        def _worker():
            fim = FileIntegrityMonitor(self.db_instance)
            directories = self.config.directories
            self.after(0, lambda: self.lbl_progress.configure(text="Calculando archivos..."))
            total_files = self.count_total_files(directories)
            
            processed_count = 0

            def _update_progress():
                nonlocal processed_count
                processed_count += 1
                if total_files > 0:
                    percentage = processed_count / total_files
                    self.after(0, lambda p=percentage: self.progress_bar.set(p))
                    if processed_count % 10 == 0:
                        self.after(0, lambda c=processed_count: self.lbl_progress.configure(text=f"Analizando: {c}/{total_files}"))

            count_dirs = 0
            for folder in directories:
                folder = folder.strip('"').strip("'")
                if os.path.exists(folder):
                    fim.scan_directory(folder, mode="baseline", progress_callback=_update_progress)
                    count_dirs += 1
            
            print(f"[ADMIN] Línea base actualizada. ({count_dirs} directorios, {total_files} archivos)")
            
            self.after(0, lambda: self.progress_bar.pack_forget()) 
            self.after(0, lambda: self.lbl_progress.pack_forget()) 
            self.after(0, lambda: self.btn_baseline.configure(state="normal", text="ACTUALIZAR BASELINE"))
            self.after(0, lambda: messagebox.showinfo("FIM", f"Snapshot completada.\nSe registraron {total_files} archivos."))

        threading.Thread(target=_worker, daemon=True).start()

    # --- MONITOR LOOP ---
    def toggle_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.btn_scan.configure(text="DETENER VIGILANCIA", fg_color="#c0392b", hover_color="#e74c3c")
            print("[SYS] PRUEBA DE LOG: Si lees esto, el sistema de logs funciona.") 
            print("[USB] PRUEBA USB: Simulando conexión...")
            self.configure(fg_color=("white", "gray20"))
            threading.Thread(target=self._monitor_loop, daemon=True).start()
        else:
            self.monitoring = False
            self.btn_scan.configure(text="ACTIVAR VIGILANCIA", fg_color="#27ae60", hover_color="#2ecc71")
            print("[INFO] Deteniendo servicios de vigilancia...")

    def _monitor_loop(self):
        notifier = TelegramNotifier(self.config)
        fim = FileIntegrityMonitor(self.db_instance)
        net_mon = NetworkMonitor(self.db_instance, notifier, config=self.config)
        usb_mon = USBMonitor(self.db_instance, notifier)
        port_mon = PortMonitor(self.db_instance, notifier)
        
        win_watcher = None
        if sys.platform == "win32":
            try: win_watcher = WindowsEventWatcher(self.db_instance, notifier)
            except: pass

        canary = CanarySentry(on_detection_callback=self._handle_ransomware_alert)
        try: canary.start(); print("[SEC] Centinela Anti-Ransomware activo.")
        except: pass

        print("[SYS] Sistema EDR en ejecución.")

        while self.monitoring:
            try:
                for folder in self.config.directories:
                    folder = folder.strip('"').strip("'")
                    if os.path.exists(folder):
                        # Aquí pasamos mode="monitor" y SIN callback, para que sea silencioso
                        fim.scan_directory(folder, mode="monitor")
                
                if win_watcher: win_watcher.check_security_logs()
                net_mon.scan_connections()
                port_mon.scan_ports()
                usb_mon.check_usb_changes()
                time.sleep(3)
            except Exception as e:
                # Este print ahora SÍ funcionará y verás el error si lo hay
                print(f"[ERR] Excepción en ciclo: {e}")

        try: canary.stop()
        except: pass
        print("[SYS] Sistema detenido.")

    def _handle_ransomware_alert(self, msg):
        print(f"\n[ALERTA REAL] !!! RANSOMWARE DETECTADO !!!\n{msg}")
        self.after(0, lambda: self.configure(fg_color="#8B0000"))
        self.after(0, lambda: messagebox.showwarning("AMENAZA CRÍTICA", f"ACTIVIDAD RANSOMWARE DETECTADA\n\n{msg}"))

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
        events = self.db_instance.get_recent_events(limit=100)
        self.history_box.configure(state="normal")
        self.history_box.delete("0.0", "end")
        header = f"{'TIMESTAMP':<20} | {'TIPO':<10} | {'SEVERIDAD':<10} | {'MENSAJE'}\n"
        self.history_box.insert("end", header + "-"*110 + "\n")
        for (ts, type_, sev, msg) in events:
            clean_msg = msg.replace('\n', ' ').strip()[:90]
            self.history_box.insert("end", f"{ts:<20} | {type_:<10} | {sev:<10} | {clean_msg}\n")
        self.history_box.configure(state="disabled")

    def export_csv(self):
        if not self.db_instance: return
        fname = f"audit_log_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        success, msg = self.db_instance.export_events_to_csv(fname)
        if success: messagebox.showinfo("Exportación Exitosa", f"Archivo generado:\n{msg}")
        else: messagebox.showerror("Error", msg)

    def destroy(self):
        if self.db_instance: self.db_instance.close()
        super().destroy()

if __name__ == "__main__":
    app = PySentinelApp()
    app.mainloop()