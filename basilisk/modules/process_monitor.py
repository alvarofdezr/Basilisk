"""
Basilisk Process Monitor v2.0
Real-time process telemetry with anomaly detection.
"""
import psutil
import os
from typing import List
from basilisk.core.schemas import ProcessModel
from basilisk.utils.logger import Logger

logger = Logger()

class ProcessMonitor:
    def __init__(self):
        self.suspicious_paths = [
            os.getenv("TEMP", "").lower(),
            os.getenv("APPDATA", "").lower(),
            "/tmp",
            "/var/tmp"
        ]
        self.critical_processes = ["lsass.exe", "svchost.exe", "csrss.exe", "winlogon.exe"]

    def scan_processes(self) -> List[dict]:
        """
        Retrieves the process list and returns serialized data ready for C2.
        Returns: List[dict] (Output of ProcessModel.dict())
        """
        process_list = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                exe_path = (pinfo['exe'] or "").lower()
                
                risk_level = "INFO"
                risk_score = 0
                
                if exe_path and any(sp in exe_path for sp in self.suspicious_paths if sp):
                    risk_level = "WARNING"
                    risk_score += 50
                
                if pinfo['name'] in self.critical_processes:
                    if "system32" not in exe_path and "syswow64" not in exe_path:
                        risk_level = "CRITICAL"
                        risk_score = 100

                model = ProcessModel(
                    pid=pinfo['pid'],
                    name=pinfo['name'],
                    username=pinfo['username'] or "UNKNOWN",
                    exe=pinfo['exe'],
                    cmdline=" ".join(pinfo['cmdline']) if pinfo['cmdline'] else "",
                    cpu_percent=pinfo['cpu_percent'] or 0.0,
                    memory_percent=pinfo['memory_percent'] or 0.0,
                    risk_level=risk_level,
                    risk_score=risk_score
                )
                
                process_list.append(model.dict())

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.info(f"Error processing PID {proc.pid}: {e}")

        return sorted(process_list, key=lambda x: x['cpu_percent'], reverse=True)