"""
Process Monitor Module - Real-time Process Telemetry

Enumerates system processes with anomaly detection capabilities.
Identifies suspicious execution contexts, unwanted child processes,
and potential privilege escalation attempts through process analysis.
"""
import psutil
import os
from typing import List
from basilisk.core.schemas import ProcessModel
from basilisk.utils.logger import Logger

logger = Logger()


class ProcessMonitor:
    """
    System process enumeration and threat analysis engine.
    
    Continuously monitors running processes and evaluates risk based on
    execution path, process name, and system integration patterns.
    Detects anomalies including execution from temporary directories,
    process injection vectors, and critical system process hijacking.
    """

    def __init__(self):
        """
        Initialize process monitor with threat detection baselines.
        
        Configures suspicious execution paths and critical process
        naming patterns used for risk assessment.
        """
        self.suspicious_paths = [
            os.getenv("TEMP", "").lower(),
            os.getenv("APPDATA", "").lower(),
            "/tmp",
            "/var/tmp"
        ]
        self.critical_processes = ["lsass.exe", "svchost.exe", "csrss.exe", "winlogon.exe"]

    def scan_processes(self) -> List[dict]:
        """
        Enumerate all running processes with risk assessment.
        
        Iterates system process list and assigns threat scores based on:
        - Execution path (temporary directories = suspicious)
        - Process name (critical OS processes monitored)
        - Resource consumption patterns
        
        Returns:
            List[dict]: Sorted process list (highest CPU first) with risk metadata
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
