# pysentinel/modules/process_monitor.py
"""
Basilisk EDR - Process Monitor v6.5
[UPDATE] Zero Tolerance Policy for Telemetry.
[FIX] Kernel False Positives handling.
"""
import psutil
import os
import hashlib
from typing import List, Dict, Optional
from basilisk.modules.memory_scanner import MemoryScanner

class ProcessMonitor:
    def __init__(self):
        self.mem_scanner = MemoryScanner()

        self.suspicious_paths = [
            os.environ.get('TEMP'),
            os.environ.get('APPDATA'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')
        ]
        
        self.system32_processes = [
            "svchost.exe", "taskmgr.exe", "lsass.exe", "csrss.exe", 
            "winlogon.exe", "services.exe"
        ]

        # 1. Procesos del Kernel (NO TOCAR - Son el sistema operativo)
        self.kernel_processes = [
            "registry", "memcompression", "system", "secure system", 
            "smss.exe", "idle"
        ]

        # 2. LISTA NEGRA DE TELEMETRÍA Y BLOATWARE
        # Estos procesos serán marcados como AMENAZA (WARNING)
        self.telemetry_blacklist = {
            # Microsoft Telemetry
            "compattelrunner.exe": "MS Customer Experience Telemetry",
            "devicecensus.exe": "Device Census (Data Collection)",
            "smartscreen.exe": "Windows SmartScreen (Data Sending)",
            "wermgr.exe": "Windows Error Reporting",
            "diagtrack.exe": "Diagnostics Tracking Service",
            "dmclient.exe": "Data Management Client",
            
            # Apps "Espía" / Invasivas
            "cortana.exe": "Cortana Voice Data",
            "searchapp.exe": "Windows Indexing/Search Data",
            "yourphone.exe": "Phone Synchronization",
            "gamebar.exe": "Xbox Game Bar Telemetry",
            "teams.exe": "Teams Background Analytics",
            "onedrive.exe": "Cloud Sync (Data Exfiltration Risk)",
            "officeclicktorun.exe": "Office Telemetry"
        }

    def get_process_hash(self, path: str) -> Optional[str]:
        try:
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except (PermissionError, OSError):
            return None

    def scan_processes(self) -> List[Dict]:
        process_list = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                info = proc.info
                if not info['name']: continue
                
                name = info['name'].lower()
                
                # [PASO 1] Ignorar Kernel (Falsos Positivos)
                if name in self.kernel_processes:
                    continue # No los mostramos o los marcamos como SAFE internos

                # Si no es kernel y no tiene EXE, suele ser proceso protegido o zombie
                if not info['exe']: continue

                exe_path = info['exe']
                exe_lower = exe_path.lower()
                
                risk_level = "SAFE"
                risk_reason = "Process Verified"

                # --- [PASO 2] Detección de Telemetría (TOLERANCIA CERO) ---
                if name in self.telemetry_blacklist:
                    risk_level = "WARNING" # Escalado a Alerta
                    risk_reason = f"UNWANTED TELEMETRY: {self.telemetry_blacklist[name]}"

                # --- [PASO 3] Rutas Sospechosas ---
                elif any(sp in exe_lower for sp in self.suspicious_paths if sp):
                    risk_level = "WARNING"
                    risk_reason = "Executing from TEMP/Downloads"

                # --- [PASO 4] Forense de Memoria (Process Hollowing) ---
                # Solo analizamos si no hemos detectado ya que es basura de telemetría
                if risk_level != "CRITICAL":
                # Escaneamos PID
                    forensic = self.mem_scanner.detect_hollowing(info['pid'])
                
                if forensic['suspicious']:
                    risk_level = "CRITICAL"
                    risk_reason = f"FORENSIC: {forensic['technique']}"

                # --- [PASO 5] Masquerading Básico ---
                if risk_level == "SAFE":
                    if name == "explorer.exe" and "c:\\windows\\explorer.exe" not in exe_lower:
                        risk_level = "CRITICAL"
                        risk_reason = "Explorer.exe Masquerading"
                    elif name in self.system32_processes:
                        if "system32" not in exe_lower and "syswow64" not in exe_lower:
                            risk_level = "CRITICAL"
                            risk_reason = "System process outside System32"

                process_list.append({
                    "pid": info['pid'],
                    "name": info['name'],
                    "path": exe_path,
                    "risk": risk_level,
                    "reason": risk_reason
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Ordenar: CRITICAL > WARNING > SAFE
        priority = {"CRITICAL": 0, "WARNING": 1, "SAFE": 2}
        process_list.sort(key=lambda x: priority.get(x['risk'], 2))
        
        return process_list