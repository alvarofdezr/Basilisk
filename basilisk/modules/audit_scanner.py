# basilisk/modules/audit_scanner.py
import winreg
import psutil
import datetime
from typing import Dict, Any
from basilisk.utils.logger import Logger

class AuditScanner:
    """
    Performs system hardening checks using Windows Registry and Process list.
    """
    def __init__(self):
        self.logger = Logger()

    def _read_reg_value(self, hive, path: str, key_name: str) -> Any:
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, key_name)
                return value
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def check_firewall(self) -> Dict[str, str]:
        """Checks Firewall profiles via Registry (Language independent)."""
        base_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        profiles = {
            "Standard": f"{base_path}\\StandardProfile",
            "Public": f"{base_path}\\PublicProfile",
            "Domain": f"{base_path}\\DomainProfile"
        }
        
        status = {}
        active_count = 0
        
        for name, path in profiles.items():
            val = self._read_reg_value(winreg.HKEY_LOCAL_MACHINE, path, "EnableFirewall")
            # 1 = ON, 0 = OFF
            if val == 1:
                status[name] = "ACTIVE"
                active_count += 1
            else:
                status[name] = "DISABLED"

        status["Overall"] = "SECURE" if active_count >= 2 else "RISK"
        return status

    def check_uac(self) -> str:
        """Checks User Account Control level."""
        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        val = self._read_reg_value(winreg.HKEY_LOCAL_MACHINE, path, "EnableLUA")
        return "ENABLED" if val == 1 else "DISABLED (CRITICAL RISK)"

    def check_defender(self) -> str:
        """Verifies if MsMpEng.exe (Defender Core) is running."""
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == "msmpeng.exe":
                    return "ACTIVE"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return "INACTIVE/MISSING"

    def check_last_update(self) -> str:
        """Gets the timestamp of the last successful Windows Update."""
        # Intenta leer varias claves comunes de WU
        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install"
        last_time = self._read_reg_value(winreg.HKEY_LOCAL_MACHINE, path, "LastSuccessTime")
        
        if last_time:
            return str(last_time)
        return "Unknown (Check manually)"

    def perform_audit(self) -> Dict[str, Any]:
        self.logger.info("Running System Compliance Audit...")
        report = {
            "firewall": self.check_firewall(),
            "uac": self.check_uac(),
            "defender": self.check_defender(),
            "last_update": self.check_last_update(),
            "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        return report