# gui.py
import customtkinter as ctk
import threading
import time
import sys
import os
import hashlib
from tkinter import messagebox, ttk

# --- MATPLOTLIB (GRÁFICOS) ---
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# --- IMPORTS DEL PROYECTO ---
from pysentinel.core.database import DatabaseManager
from pysentinel.core.config import Config
from pysentinel.utils.notifier import TelegramNotifier
from pysentinel.utils.system_monitor import get_system_metrics

# Módulos de Detección
from pysentinel.modules.fim import FileIntegrityMonitor
from pysentinel.modules.network_monitor import NetworkMonitor
from pysentinel.modules.usb_monitor import USBMonitor
from pysentinel.modules.port_monitor import PortMonitor
from pysentinel.modules.anti_ransomware import CanarySentry
from pysentinel.modules.win_event_watcher import WindowsEventWatcher
from pysentinel.modules.process_monitor import ProcessMonitor
from pysentinel.modules.threat_intel import ThreatIntel
from pysentinel.modules.registry_monitor import RegistryMonitor

# Soporte PDF (Opcional)
try:
    from pysentinel.utils.pdf_generator import generate_pdf
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# Configuración Global UI
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PySentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PySentinel EDR | Enterprise Edition v5.0")
        self.geometry("1280x850")
        
        # Icono y Centrado
        try: self.iconbitmap("app_icon.ico")
        except: pass
        self._center_window(1280, 850)
        
        # Estado
        self.monitoring = False
        self.db_instance = None
        self.config = None

        # Inicialización
        self._init_backend()
        self._init_ui()
        self._redirect_stdout()
        
        # Loops de Interfaz
        self.update_system_stats()
        self.refresh_history()
        self.refresh_dashboard() # Loop del Dashboard

    def _center_window(self, width, height):
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _init_backend(self):
        try:
            # 1. Configuración (Lee yaml)
            self.config = Config()
            # 2. Base de Datos
            self.db_instance = DatabaseManager(db_name=self.config.db_name)
        except Exception as e:
            messagebox.showerror("Error Crítico", f"Fallo al iniciar backend:\n{e}")
            self.destroy()

    def _init_ui(self):
        self.grid_columnconfigure(0, weight=0) # Sidebar fija
        self.grid_columnconfigure(1, weight=1) # Contenido expandible
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_content()

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(10, weight=1)

        ctk.CTkLabel(self.sidebar, text="PySentinel\nEDR Core", 
                     font=("Roboto", 22, "bold")).pack(pady=25)

        # --- BOTONES DE ACCIÓN ---
        self.btn_scan = ctk.CTkButton(self.sidebar, text="ACTIVAR VIGILANCIA", 
                                      command=self.toggle_monitoring, 
                                      fg_color="#27ae60", hover_color="#2ecc71", 
                                      height=40, font=("Roboto", 12, "bold"))
        self.btn_scan.pack(pady=10, padx=20, fill="x")

        self.btn_baseline = ctk.CTkButton(self.sidebar, text="ACTUALIZAR BASELINE", 
                                          command=self.create_baseline, 
                                          fg_color="#2980b9", hover_color="#3498db",
                                          height=40)
        self.btn_baseline.pack(pady=5, padx=20, fill="x")

        # Barra de Carga (Oculta por defecto)
        self.lbl_progress = ctk.CTkLabel(self.sidebar, text="Analizando...", font=("Roboto", 10))
        self.progress_bar = ctk.CTkProgressBar(self.sidebar, width=160, progress_color="#3498db")
        self.progress_bar.set(0)

        # --- BOTONES DE AUDITORÍA ---
        ctk.CTkLabel(self.sidebar, text="HERRAMIENTAS FORENSES", 
                    font=("Roboto", 10, "bold"), text_color="gray").pack(pady=(20, 5))

        self.btn_ports = ctk.CTkButton(self.sidebar, text="🔍 AUDITORÍA PUERTOS", 
                                            command=self.show_port_audit, 
                                            fg_color="#8e44ad", hover_color="#9b59b6",
                                            height=35)
        self.btn_ports.pack(pady=5, padx=20, fill="x")

        self.btn_procs = ctk.CTkButton(self.sidebar, text="🔎 ESCÁNER PROCESOS", 
                                            command=self.show_process_audit, 
                                            fg_color="#e67e22", hover_color="#d35400",
                                            height=35)
        self.btn_procs.pack(pady=5, padx=20, fill="x")

        # --- RECURSOS ---
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
        
        # Pestañas Principales
        self.tab_dashboard = self.tabs.add("Dashboard")
        self.tab_live = self.tabs.add("Monitor en Vivo")
        self.tab_history = self.tabs.add("Historial")

        # ==========================
        # 1. PESTAÑA DASHBOARD (SOC)
        # ==========================
        self.tab_dashboard.grid_columnconfigure(0, weight=1)
        self.tab_dashboard.grid_columnconfigure(1, weight=1)
        self.tab_dashboard.grid_rowconfigure(0, weight=1) # Gráficos
        self.tab_dashboard.grid_rowconfigure(1, weight=0) # Stats texto

        # Frame Gráfico 1 (Donut)
        self.frame_chart1 = ctk.CTkFrame(self.tab_dashboard)
        self.frame_chart1.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Frame Gráfico 2 (Barras)
        self.frame_chart2 = ctk.CTkFrame(self.tab_dashboard)
        self.frame_chart2.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        # Panel de Salud (Abajo)
        self.frame_health = ctk.CTkFrame(self.tab_dashboard, height=100, fg_color="#1f1f1f")
        self.frame_health.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        
        self.lbl_health_score = ctk.CTkLabel(self.frame_health, text="SYSTEM HEALTH: CALCULANDO...", 
                                             font=("Roboto", 24, "bold"), text_color="gray")
        self.lbl_health_score.pack(pady=20)

        # ==========================
        # 2. PESTAÑA MONITOR EN VIVO
        # ==========================
        self.tab_live.grid_columnconfigure(0, weight=1)
        self.tab_live.grid_rowconfigure(0, weight=1)
        self.logs_tabs = ctk.CTkTabview(self.tab_live)
        self.logs_tabs.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        self.log_widgets = {}
        categories = {
            "GENERAL": "General", "NET": "🌐 Red", "PORT": "🚪 Puertos", 
            "FILE": "📂 Archivos", "SYS": "⚙️ Sistema"
        }
        for key, title in categories.items():
            tab = self.logs_tabs.add(title)
            tab.grid_columnconfigure(0, weight=1); tab.grid_rowconfigure(0, weight=1)
            textbox = ctk.CTkTextbox(tab, font=("Consolas", 11), activate_scrollbars=True)
            textbox.grid(row=0, column=0, sticky="nsew")
            textbox.insert("0.0", f"--- Log iniciado: {title} ---\n")
            textbox.configure(state="disabled")
            self.log_widgets[key] = textbox

        # ==========================
        # 3. PESTAÑA HISTORIAL
        # ==========================
        self.tab_history.grid_columnconfigure(0, weight=1)
        self.tab_history.grid_rowconfigure(1, weight=1)
        controls = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        controls.grid(row=0, column=0, sticky="e", padx=10, pady=5)
        
        ctk.CTkButton(controls, text="📄 Exportar PDF", command=self.export_report, width=140, fg_color="#d35400").pack(side="left", padx=5)
        ctk.CTkButton(controls, text="🔄 Refrescar", command=self.refresh_history, width=100).pack(side="left", padx=5)
        
        self.history_box = ctk.CTkTextbox(self.tab_history, font=("Consolas", 11), state="disabled")
        self.history_box.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

    # =====================================================
    # LÓGICA DASHBOARD (GRÁFICOS)
    # =====================================================
    def refresh_dashboard(self):
        if not self.db_instance: return
        
        # 1. Datos de la DB
        stats_sev = self.db_instance.get_stats_by_severity() 
        stats_type = self.db_instance.get_stats_by_type()    
        
        # 2. Algoritmo de Salud
        score = 100
        
        labels_sev = []
        sizes_sev = []
        colors_sev = []
        color_map = {"INFO": "#3498db", "WARNING": "#f1c40f", "CRITICAL": "#e74c3c"}
        
        for sev, count in stats_sev:
            labels_sev.append(f"{sev} ({count})")
            sizes_sev.append(count)
            colors_sev.append(color_map.get(sev, "gray"))
            
            if sev == "CRITICAL": score -= (count * 10)
            elif sev == "WARNING": score -= (count * 2)
        
        score = max(0, score)
        
        # Estado Visual
        color_score = "#27ae60" # Verde
        status_text = "SISTEMA SEGURO"
        if score < 80: 
            color_score = "#f1c40f"; status_text = "ATENCIÓN REQUERIDA"
        if score < 50: 
            color_score = "#e74c3c"; status_text = "PELIGRO CRÍTICO"
            
        self.lbl_health_score.configure(text=f"NIVEL DE SALUD: {score}% | ESTADO: {status_text}", text_color=color_score)

        # 3. Gráfico 1: Donut Chart (Severidad)
        self._draw_chart(self.frame_chart1, sizes_sev, labels_sev, colors_sev, "Amenazas por Severidad")

        # 4. Gráfico 2: Bar Chart (Tipos)
        types = [x[0] for x in stats_type]
        counts = [x[1] for x in stats_type]
        self._draw_bar_chart(self.frame_chart2, types, counts, "Actividad Reciente (Top 5)")

        self.after(10000, self.refresh_dashboard)

    def _draw_chart(self, parent_frame, sizes, labels, colors, title):
        for widget in parent_frame.winfo_children(): widget.destroy()
        if not sizes:
            ctk.CTkLabel(parent_frame, text="Sin datos de actividad").pack(expand=True); return

        plt.rcParams.update({"figure.facecolor": "#2b2b2b", "axes.facecolor": "#2b2b2b", 
                             "text.color": "white", "axes.labelcolor": "white"})

        fig, ax = plt.subplots(figsize=(5, 4))
        wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%', 
                                          startangle=90, colors=colors, pctdistance=0.85)
        centre_circle = plt.Circle((0,0),0.70,fc='#2b2b2b')
        fig.gca().add_artist(centre_circle)
        ax.set_title(title, color="white", fontsize=10)
        for text in texts + autotexts: text.set_color("white")

        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw(); canvas.get_tk_widget().pack(fill="both", expand=True)
        plt.close(fig)

    def _draw_bar_chart(self, parent_frame, x_data, y_data, title):
        for widget in parent_frame.winfo_children(): widget.destroy()
        if not x_data:
            ctk.CTkLabel(parent_frame, text="Recopilando métricas...").pack(expand=True); return

        fig, ax = plt.subplots(figsize=(5, 4))
        ax.bar(x_data, y_data, color="#3498db")
        ax.set_title(title, color="white", fontsize=10)
        ax.tick_params(axis='x', colors='white', rotation=45)
        ax.tick_params(axis='y', colors='white')
        
        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw(); canvas.get_tk_widget().pack(fill="both", expand=True)
        plt.close(fig)

    # =====================================================
    # LÓGICA FORENSE (TREEVIEWS)
    # =====================================================
    
    # --- PUERTOS ---
    def show_port_audit(self):
        if not self.db_instance: return
        win = ctk.CTkToplevel(self)
        win.title("Auditoría de Puertos"); win.geometry("900x500"); win.attributes("-topmost", True)

        top = ctk.CTkFrame(win, fg_color="transparent"); top.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(top, text="PUERTOS DE ESCUCHA", font=("Roboto", 18, "bold")).pack(side="left")
        ctk.CTkButton(top, text="🔄 Actualizar", command=lambda: self._refresh_port_tree(tree), width=100).pack(side="right")

        style = ttk.Style(); style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", rowheight=25)
        style.map("Treeview", background=[('selected', '#8e44ad')])

        cols = ("port", "proto", "service", "process", "pid")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for c in cols: tree.heading(c, text=c.upper())
        tree.column("port", width=80); tree.column("service", width=150)
        tree.pack(fill="both", expand=True, padx=10, pady=10)
        
        self._refresh_port_tree(tree)

    def _refresh_port_tree(self, tree):
        for i in tree.get_children(): tree.delete(i)
        pm = PortMonitor(self.db_instance, None)
        report = pm.get_full_report()
        for row in report:
            tag = "common" if row['port'] in [80,443,22,3389,21] else "normal"
            tree.insert("", "end", values=(row['port'], row['proto'], row['service'], row['process'], row['pid']), tags=(tag,))
        tree.tag_configure("common", foreground="#f1c40f")

    # --- PROCESOS (CON FILTRO Y VT) ---
    def show_process_audit(self):
        win = ctk.CTkToplevel(self)
        win.title("Análisis Forense de Procesos"); win.geometry("1100x650"); win.attributes("-topmost", True)
        
        self.show_safe_procs = ctk.BooleanVar(value=False)

        top = ctk.CTkFrame(win, fg_color="transparent"); top.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(top, text="PROCESOS ACTIVOS", font=("Roboto", 18, "bold")).pack(side="left")
        ctk.CTkSwitch(top, text="Mostrar Seguros", variable=self.show_safe_procs, command=lambda: self._refresh_proc_tree(tree)).pack(side="left", padx=30)
        
        ctk.CTkButton(top, text="🦠 Analizar (VT)", command=lambda: self._scan_selected_vt(tree), fg_color="#5865F2").pack(side="right", padx=10)
        ctk.CTkButton(top, text="🔄 Actualizar", command=lambda: self._refresh_proc_tree(tree)).pack(side="right")

        style = ttk.Style(); style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", rowheight=25)
        style.map("Treeview", background=[('selected', '#1f6aa5')])

        cols = ("pid", "name", "risk", "reason", "path")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for c in cols: tree.heading(c, text=c.upper())
        tree.column("path", width=300)
        tree.pack(fill="both", expand=True, padx=10, pady=10)
        
        tree.tag_configure("critical", background="#c0392b", foreground="white")
        tree.tag_configure("warning", background="#d35400", foreground="white")
        tree.tag_configure("privacy", background="#2980b9", foreground="white")
        tree.tag_configure("safe", background="#2b2b2b", foreground="gray70")

        self._refresh_proc_tree(tree)

    def _refresh_proc_tree(self, tree):
        for i in tree.get_children(): tree.delete(i)
        pm = ProcessMonitor()
        procs = pm.scan_processes()
        
        count = 0
        for p in procs:
            if p['risk'] == "SAFE" and not self.show_safe_procs.get(): continue
            tag = p['risk'].lower()
            tree.insert("", "end", values=(p['pid'], p['name'], p['risk'], p['reason'], p['path']), tags=(tag,))
            count += 1
        
        if count == 0 and not self.show_safe_procs.get():
            messagebox.showinfo("Sistema Limpio", "No se detectaron amenazas activas.")

    def _scan_selected_vt(self, tree):
        sel = tree.selection()
        if not sel: messagebox.showwarning("Selección", "Elige un proceso primero."); return
        
        vals = tree.item(sel[0])['values']
        path, name = vals[4], vals[1]
        
        pm = ProcessMonitor()
        fhash = pm.get_process_hash(path)
        if not fhash: messagebox.showerror("Error", "No se pudo leer el archivo"); return
            
        key = self.config.virustotal_api_key
        if not key: messagebox.showwarning("Falta API", "Configura tu API Key"); return

        ti = ThreatIntel(key)
        res = ti.check_hash(fhash)
        
        if res:
            mal = res.get('malicious', 0)
            icon = "error" if mal > 0 else "info"
            msg = f"Resultado VT: {mal}/{res.get('total', '?')} motores lo detectan."
            messagebox.showinfo(f"Reporte: {name}", msg, icon=icon)
        else:
            messagebox.showerror("Error", "Fallo conexión VirusTotal")

    # =====================================================
    # LÓGICA BASE Y SEGURIDAD
    # =====================================================
    def _redirect_stdout(self):
        app = self
        class LogRouter:
            def write(self, text):
                if not text.strip(): return
                app._safe_log_write(app.log_widgets["GENERAL"], text)
                target = None
                if "[NET]" in text: target = "NET"
                elif "[PORT]" in text: target = "PORT"
                elif "[USB]" in text or "[WIN]" in text or "[ALERTA REAL]" in text: target = "SYS"
                elif "[FIM]" in text or "ARCHIVO" in text or "RANSOMWARE" in text: target = "FILE"
                if target: app._safe_log_write(app.log_widgets[target], text)
            def flush(self): pass
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

    def verify_admin(self):
        if not self.config.admin_hash: return True
        dialog = ctk.CTkInputDialog(text="Contraseña Admin:", title="Seguridad")
        pwd = dialog.get_input()
        if not pwd: return False
        if hashlib.sha512(pwd.encode()).hexdigest() == self.config.admin_hash: return True
        messagebox.showerror("Acceso Denegado", "Contraseña incorrecta"); return False

    # --- BASELINE CON BARRA DE CARGA ---
    def count_total_files(self, directories):
        total = 0
        for folder in directories:
            folder = folder.strip('"').strip("'")
            if os.path.exists(folder):
                for _, _, files in os.walk(folder): total += len(files)
        return total

    def create_baseline(self):
        if not self.db_instance or not self.verify_admin(): return
        self.btn_baseline.configure(state="disabled", text="Procesando...")
        self.progress_bar.set(0); self.lbl_progress.pack(pady=(10,0)); self.progress_bar.pack(pady=5, padx=20)
        
        def _worker():
            fim = FileIntegrityMonitor(self.db_instance)
            dirs = self.config.directories
            self.after(0, lambda: self.lbl_progress.configure(text="Calculando archivos..."))
            total = self.count_total_files(dirs)
            
            count = 0
            def _cb():
                nonlocal count; count+=1
                if total > 0:
                    pct = count/total
                    self.after(0, lambda: self.progress_bar.set(pct))
                    if count % 10 == 0: self.after(0, lambda c=count: self.lbl_progress.configure(text=f"{c}/{total}"))

            for d in dirs:
                d = d.strip('"').strip("'")
                if os.path.exists(d): fim.scan_directory(d, mode="baseline", progress_callback=_cb)
            
            self.after(0, lambda: self.progress_bar.pack_forget())
            self.after(0, lambda: self.lbl_progress.pack_forget())
            self.after(0, lambda: self.btn_baseline.configure(state="normal", text="ACTUALIZAR BASELINE"))
            self.after(0, lambda: messagebox.showinfo("FIM", f"Snapshot finalizada.\n{total} archivos."))
        
        threading.Thread(target=_worker, daemon=True).start()

    # --- BUCLE DE VIGILANCIA ---
    def toggle_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.btn_scan.configure(text="DETENER VIGILANCIA", fg_color="#c0392b", hover_color="#e74c3c")
            threading.Thread(target=self._monitor_loop, daemon=True).start()
        else:
            self.monitoring = False
            self.btn_scan.configure(text="ACTIVAR VIGILANCIA", fg_color="#27ae60", hover_color="#2ecc71")

    def _monitor_loop(self):
        notifier = TelegramNotifier(self.config)
        fim = FileIntegrityMonitor(self.db_instance)
        net_mon = NetworkMonitor(self.db_instance, notifier, config=self.config)
        usb_mon = USBMonitor(self.db_instance, notifier)
        port_mon = PortMonitor(self.db_instance, notifier)
        
        # ### NUEVO: Inicializar Monitor de Registro ###
        reg_mon = None
        if sys.platform == "win32":
            try: 
                win_watcher = WindowsEventWatcher(self.db_instance, notifier)
                reg_mon = RegistryMonitor(self.db_instance, notifier) # <--- AQUÍ
            except: pass
        else:
            win_watcher = None

        canary = CanarySentry(on_detection_callback=self._handle_ransomware_alert)
        try: canary.start()
        except: pass

        print("[SYS] Sistema EDR en ejecución. Vigilancia activa.")

        while self.monitoring:
            try:
                # 1. FIM
                for d in self.config.directories:
                    d = d.strip('"').strip("'")
                    if os.path.exists(d): fim.scan_directory(d, mode="monitor")
                
                # 2. Logs Windows
                if win_watcher: win_watcher.check_security_logs()
                
                # 3. Registro (Persistencia)
                # ### NUEVO: Chequear Registro ###
                if reg_mon: reg_mon.check_registry_changes()
                
                # 4. Red y Hardware
                net_mon.scan_connections()
                port_mon.scan_ports()
                usb_mon.check_usb_changes()
                
                time.sleep(3)
            except Exception as e:
                print(f"[ERR] Excepción en bucle: {e}")

    def _handle_ransomware_alert(self, msg):
        print(f"\n[ALERTA REAL] !!! RANSOMWARE DETECTADO !!!\n{msg}")
        self.after(0, lambda: self.configure(fg_color="#8B0000"))
        self.after(0, lambda: messagebox.showwarning("AMENAZA CRÍTICA", f"RANSOMWARE DETECTADO\n\n{msg}"))

    def update_system_stats(self):
        try:
            stats = get_system_metrics()
            self.lbl_cpu.configure(text=f"CPU: {stats['cpu']}%")
            self.prog_cpu.set(stats['cpu']/100)
            self.lbl_ram.configure(text=f"RAM: {stats['ram']}%")
            self.prog_ram.set(stats['ram']/100)
        except: pass
        self.after(2000, self.update_system_stats)

    def refresh_history(self):
        if not self.db_instance: return
        events = self.db_instance.get_recent_events(limit=50)
        self.history_box.configure(state="normal"); self.history_box.delete("0.0", "end")
        self.history_box.insert("end", "HISTORIAL RECIENTE\n" + "-"*80 + "\n")
        for e in events:
            msg = e[3].replace('\n', ' ')[:90]
            self.history_box.insert("end", f"{e[0]} | {e[2]} | {msg}\n")
        self.history_box.configure(state="disabled")

    def export_report(self):
        if not self.db_instance: return
        events = self.db_instance.get_recent_events(limit=500)
        
        if PDF_AVAILABLE:
            fname = f"Reporte_Ejecutivo_{time.strftime('%Y%m%d_%H%M')}.pdf"
            success, msg = generate_pdf(events, fname)
            type_msg = "PDF"
        else:
            fname = f"reporte_{time.strftime('%Y%m%d')}.csv"
            success, msg = self.db_instance.export_events_to_csv(fname)
            type_msg = "CSV (Instala fpdf2 para PDF)"

        if success:
            messagebox.showinfo("Reporte Generado", f"Informe {type_msg} creado:\n{msg}")
            try: os.startfile(msg)
            except: pass
        else:
            messagebox.showerror("Error", msg)

    def destroy(self):
        if self.db_instance: self.db_instance.close()
        super().destroy()

# --- SPLASH SCREEN PROFESIONAL ---
class SplashScreen(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.overrideredirect(True); self.attributes('-topmost', True)
        
        w=500; h=300
        sw=self.winfo_screenwidth(); sh=self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw//2)-(w//2)}+{(sh//2)-(h//2)}")
        self.configure(fg_color="#1a1a1a")

        ctk.CTkLabel(self, text="PySentinel", font=("Roboto", 40, "bold"), text_color="#3498db").pack(pady=(70, 10))
        ctk.CTkLabel(self, text="EDR SECURITY SUITE", font=("Roboto", 12, "bold"), text_color="gray").pack(pady=5)
        
        self.label = ctk.CTkLabel(self, text="Inicializando...", font=("Consolas", 10))
        self.label.pack(pady=(50, 5))
        
        self.bar = ctk.CTkProgressBar(self, width=400, progress_color="#3498db")
        self.bar.pack(pady=10); self.bar.set(0)

        self.after(200, lambda: self._u(0.2, "Cargando Módulos IA..."))
        self.after(1000, lambda: self._u(0.6, "Conectando Base de Datos..."))
        self.after(2000, lambda: self._u(0.9, "Verificando Integridad..."))
        self.after(2500, self.finish)

    def _u(self, v, t):
        self.bar.set(v); self.label.configure(text=t)

    def finish(self):
        self.destroy(); self.parent.deiconify()

if __name__ == "__main__":
    app = PySentinelApp()
    app.withdraw() # Ocultar principal
    splash = SplashScreen(app) # Mostrar carga
    app.mainloop()