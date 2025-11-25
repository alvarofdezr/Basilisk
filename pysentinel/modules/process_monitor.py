# pysentinel/modules/process_monitor.py
import psutil
import os
import hashlib

class ProcessMonitor:
    def __init__(self):
        # 1. Rutas peligrosas (Malware)
        self.suspicious_paths = [
            os.environ.get('TEMP'),
            os.environ.get('APPDATA'),
            os.path.join(os.environ.get('USERPROFILE'), 'Downloads')
        ]
        
        # 2. Procesos críticos de Windows (Must be in System32)
        self.system32_processes = [
            "svchost.exe", "taskmgr.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe"
        ]

        # 3. LISTA NEGRA DE PRIVACIDAD Y BLOATWARE
        self.bloatware_list = {
            "compattelrunner.exe": "Microsoft Compatibility Telemetry (Espía)",
            "devicecensus.exe": "Webcam/Usage Telemetry",
            "smartscreen.exe": "Windows SmartScreen (Envía URLs a MS)",
            "wermgr.exe": "Windows Error Reporting",
            "yourphone.exe": "Enlace Móvil (Siempre activo)",
            "cortana.exe": "Asistente Cortana",
            "searchapp.exe": "Windows Search / Bing en inicio",
            "gamebar.exe": "Xbox Game Bar",
            "gamebarftserver.exe": "Xbox Telemetry",
            "onedrive.exe": "Microsoft OneDrive",
            "microsoftedgeupdate.exe": "Edge Auto-Updater",
            "googleupdate.exe": "Google Auto-Updater",
            "adobeupdate.exe": "Adobe Updater",
            "acrotray.exe": "Adobe Background Service",
            "steam.exe": "Steam",
            "discord.exe": "Discord",
            "teams.exe": "Microsoft Teams"
        }

    # --- ESTA ES LA FUNCIÓN QUE FALTABA ---
    def get_process_hash(self, path):
        """Calcula el SHA-256 del ejecutable para VirusTotal"""
        try:
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                # Leemos por bloques para no saturar memoria
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except Exception:
            # Si no podemos leerlo (acceso denegado), devolvemos None
            return None
    # --------------------------------------

    def scan_processes(self):
        process_list = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                info = proc.info
                if not info['name']: continue
                
                name = info['name'].lower()
                exe_path = info['exe']
                
                if not exe_path: continue
                
                exe_lower = exe_path.lower()
                
                risk_level = "SAFE"
                risk_reason = "Proceso legítimo"

                # LÓGICA DE DETECCIÓN
                
                # 1. Privacy
                if name in self.bloatware_list:
                    risk_level = "PRIVACY"
                    risk_reason = self.bloatware_list[name]

                # 2. Malware (Ubicación)
                for sus_path in self.suspicious_paths:
                    if sus_path and sus_path.lower() in exe_lower:
                        risk_level = "WARNING"
                        risk_reason = "Ejecutándose desde carpeta temporal"

                # 3. Critical (Impostores)
                if name == "explorer.exe":
                    if "c:\\windows\\explorer.exe" not in exe_lower:
                        risk_level = "CRITICAL"
                        risk_reason = "Explorer.exe fuera de C:\\Windows"
                elif name in self.system32_processes:
                    if "system32" not in exe_lower and "syswow64" not in exe_lower:
                        risk_level = "CRITICAL"
                        risk_reason = "Falso proceso de sistema (Masquerading)"

                process_list.append({
                    "pid": info['pid'],
                    "name": info['name'],
                    "path": exe_path,
                    "risk": risk_level,
                    "reason": risk_reason
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Ordenar: CRITICAL > WARNING > PRIVACY > SAFE
        priority = {"CRITICAL": 0, "WARNING": 1, "PRIVACY": 2, "SAFE": 3}
        process_list.sort(key=lambda x: priority.get(x['risk'], 3))
        
        return process_list