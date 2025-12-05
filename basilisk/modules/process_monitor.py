# basilisk/modules/process_monitor.py
"""
Basilisk EDR - Process Monitor (Optimized v6.6)
Implements Delta Scanning to reduce CPU load.
"""
import psutil
import os
import hashlib
from typing import List, Dict, Optional, Set
from basilisk.modules.memory_scanner import MemoryScanner

class ProcessMonitor:
    def __init__(self):
        self.mem_scanner = MemoryScanner()
        self.known_pids: Set[int] = set() # Caché de procesos ya analizados
        
        self.suspicious_paths = [
            os.environ.get('TEMP'),
            os.environ.get('APPDATA'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')
        ]
        
        self.system32_processes = [
            "svchost.exe", "taskmgr.exe", "lsass.exe", "csrss.exe", 
            "winlogon.exe", "services.exe"
        ]

        self.kernel_processes = [
            "registry", "memcompression", "system", "secure system", 
            "smss.exe", "idle"
        ]

        self.telemetry_blacklist = {
            "compattelrunner.exe": "MS Customer Experience Telemetry",
            "devicecensus.exe": "Device Census (Data Collection)",
            "smartscreen.exe": "Windows SmartScreen (Data Sending)",
            "wermgr.exe": "Windows Error Reporting",
            "diagtrack.exe": "Diagnostics Tracking Service",
            "dmclient.exe": "Data Management Client",
            "cortana.exe": "Cortana Voice Data",
            "searchapp.exe": "Windows Indexing/Search Data",
            "yourphone.exe": "Phone Synchronization",
            "gamebar.exe": "Xbox Game Bar Telemetry",
            "teams.exe": "Teams Background Analytics",
            "onedrive.exe": "Cloud Sync (Data Exfiltration Risk)",
            "officeclicktorun.exe": "Office Telemetry"
        }

    def scan_processes(self) -> List[Dict]:
        """
        Retorna la lista completa de procesos, pero solo realiza
        análisis profundo (Deep Scan) sobre los NUEVOS procesos.
        """
        process_list = []
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                info = proc.info
                pid = info['pid']
                current_pids.add(pid)
                
                # Si ya conocemos este PID y no es sospechoso, saltamos el análisis pesado
                # (En un EDR real, re-escanearíamos periódicamente, aquí optimizamos)
                is_new = pid not in self.known_pids
                
                if not info['name']: continue
                name = info['name'].lower()
                
                # Ignorar Kernel
                if name in self.kernel_processes: continue
                if not info['exe']: continue

                exe_path = info['exe']
                exe_lower = exe_path.lower()
                
                risk_level = "SAFE"
                risk_reason = "Process Verified"

                # 1. Telemetría (Chequeo rápido)
                if name in self.telemetry_blacklist:
                    risk_level = "WARNING"
                    risk_reason = f"UNWANTED TELEMETRY: {self.telemetry_blacklist[name]}"

                # 2. Rutas (Chequeo rápido)
                elif any(sp in exe_lower for sp in self.suspicious_paths if sp):
                    risk_level = "WARNING"
                    risk_reason = "Executing from TEMP/Downloads"

                # 3. Masquerading (Chequeo rápido)
                elif risk_level == "SAFE":
                    if name == "explorer.exe" and "c:\\windows\\explorer.exe" not in exe_lower:
                        risk_level = "CRITICAL"
                        risk_reason = "Explorer.exe Masquerading"
                    elif name in self.system32_processes:
                        if "system32" not in exe_lower and "syswow64" not in exe_lower:
                            risk_level = "CRITICAL"
                            risk_reason = "System process outside System32"

                # 4. Forense de Memoria (Deep Scan) - SOLO EN NUEVOS PROCESOS
                # Esto es lo que más CPU consume, así que lo limitamos.
                if is_new and risk_level != "CRITICAL":
                    forensic = self.mem_scanner.detect_hollowing(pid)
                    if forensic['suspicious']:
                        risk_level = "CRITICAL"
                        risk_reason = f"FORENSIC: {forensic['technique']}"

                process_list.append({
                    "pid": pid,
                    "name": info['name'],
                    "path": exe_path,
                    "risk": risk_level,
                    "reason": risk_reason
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Actualizamos la caché de PIDs conocidos
        self.known_pids = current_pids
        
        # Ordenar por riesgo
        priority = {"CRITICAL": 0, "WARNING": 1, "SAFE": 2}
        process_list.sort(key=lambda x: priority.get(x['risk'], 2))
        
        return process_list