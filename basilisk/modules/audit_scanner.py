"""
Audit Scanner Module - System Compliance Assessment

Evaluates Windows security posture through registry analysis, process enumeration,
and firewall configuration inspection. Generates compliance reports for detection
of security policy violations and hardening gaps.
"""

import winreg
import psutil
import datetime
from typing import Dict, Any
from basilisk.utils.logger import Logger
from basilisk.core.schemas import AuditModel, FirewallModel


class AuditScanner:
    """
    Windows system security compliance auditor.
    
    Inspects critical security controls including Windows Defender status,
    UAC enforcement, and firewall configuration. Performs registry queries
    for policy compliance assessment and generates structured audit reports.
    """

    def __init__(self):
        """Initialize audit scanner with logging."""
        self.logger = Logger()

    def _read_reg(self, path: str, key: str) -> Any:
        """
        Query Windows registry for policy configuration values.
        
        Safely reads registry entries with exception handling for
        missing keys or access denied scenarios.
        
        Args:
            path (str): Registry path under HKEY_LOCAL_MACHINE
            key (str): Value name to retrieve
            
        Returns:
            Any: Registry value or None if not found/inaccessible
        """
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as k:
                return winreg.QueryValueEx(k, key)[0]
        except BaseException:
            return None

    def perform_audit(self) -> Dict[str, Any]:
        """
        Execute comprehensive system compliance audit.
        
        Checks:
        - Firewall enabled on Domain/Standard/Public profiles
        - User Account Control (UAC) enforcement
        - Windows Defender/Antimalware Service Running
        - Last Windows Update installation timestamp
        
        Returns:
            Dict[str, Any]: Structured audit report with compliance status
        """
        self.logger.info("Running Compliance Audit...")

        fw_base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        fw_profiles = {
            "Standard": f"{fw_base}\\StandardProfile",
            "Public": f"{fw_base}\\PublicProfile",
            "Domain": f"{fw_base}\\DomainProfile"
        }
        fw_status = {}
        active_cnt = 0
        
        for name, path in fw_profiles.items():
            val = self._read_reg(path, "EnableFirewall")
            state = "ACTIVE" if val == 1 else "DISABLED"
            fw_status[name] = state
            if val == 1:
                active_cnt += 1

        fw_model = FirewallModel(
            Domain=fw_status["Domain"],
            Standard=fw_status["Standard"],
            Public=fw_status["Public"],
            Overall="SECURE" if active_cnt >= 2 else "RISK"
        )

        uac_val = self._read_reg(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
        uac_status = "ENABLED" if uac_val == 1 else "DISABLED (CRITICAL)"

        defender_status = "MISSING"
        for p in psutil.process_iter(['name']):
            if p.info['name'] == "MsMpEng.exe":
                defender_status = "ACTIVE"
                break

        audit = AuditModel(
            firewall=fw_model,
            uac=uac_status,
            defender=defender_status,
            last_update=str(
                self._read_reg(
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install",
                    "LastSuccessTime") or "Unknown"),
            scan_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        return audit.dict()
