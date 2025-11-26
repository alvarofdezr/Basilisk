# pysentinel/modules/process_monitor.py
import psutil
import os
import hashlib
from typing import List, Dict, Optional

class ProcessMonitor:
    """
    Analyzes running processes for suspicious behavior, known malware paths,
    and privacy-invasive telemetry (Bloatware).
    """
    def __init__(self):
        # High-risk directories often used by malware droppers
        self.suspicious_paths = [
            os.environ.get('TEMP'),
            os.environ.get('APPDATA'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')
        ]
        
        # System critical processes that must reside in System32
        self.system32_processes = [
            "svchost.exe", "taskmgr.exe", "lsass.exe", "csrss.exe", 
            "winlogon.exe", "services.exe"
        ]

        # Privacy & Telemetry Blacklist
        self.bloatware_list = {
            "compattelrunner.exe": "Microsoft Compatibility Telemetry",
            "devicecensus.exe": "Device Census Telemetry",
            "smartscreen.exe": "Windows SmartScreen",
            "wermgr.exe": "Windows Error Reporting",
            "yourphone.exe": "Your Phone / Phone Link",
            "cortana.exe": "Cortana Assistant",
            "searchapp.exe": "Windows Search Indexer",
            "gamebar.exe": "Xbox Game Bar",
            "onedrive.exe": "Microsoft OneDrive",
            "teams.exe": "Microsoft Teams Background Service"
        }

    def get_process_hash(self, path: str) -> Optional[str]:
        """Calculates SHA-256 hash of a file for Threat Intelligence analysis."""
        try:
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                # Read in chunks to avoid memory issues with large files
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except (PermissionError, OSError):
            return None

    def scan_processes(self) -> List[Dict]:
        """
        Scans all active processes and evaluates security risks.
        Returns a sorted list by risk severity.
        """
        process_list = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                info = proc.info
                if not info['name'] or not info['exe']: 
                    continue
                
                name = info['name'].lower()
                exe_path = info['exe']
                exe_lower = exe_path.lower()
                
                risk_level = "SAFE"
                risk_reason = "Legitimate process"

                # Risk Assessment Logic
                
                # 1. Privacy / Bloatware
                if name in self.bloatware_list:
                    risk_level = "PRIVACY"
                    risk_reason = self.bloatware_list[name]

                # 2. Suspicious Location (Temp/Downloads)
                for sus_path in self.suspicious_paths:
                    if sus_path and sus_path.lower() in exe_lower:
                        risk_level = "WARNING"
                        risk_reason = "Executing from temporary directory"

                # 3. Masquerading (Critical)
                if name == "explorer.exe":
                    if "c:\\windows\\explorer.exe" not in exe_lower:
                        risk_level = "CRITICAL"
                        risk_reason = "Explorer.exe path anomaly (Masquerading)"
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
        
        # Sort by Severity: CRITICAL > WARNING > PRIVACY > SAFE
        priority = {"CRITICAL": 0, "WARNING": 1, "PRIVACY": 2, "SAFE": 3}
        process_list.sort(key=lambda x: priority.get(x['risk'], 3))
        
        return process_list