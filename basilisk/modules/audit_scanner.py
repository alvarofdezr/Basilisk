"""
Audit Scanner Module - System Compliance Assessment

Evaluates Windows security posture through registry analysis, process enumeration,
and firewall configuration inspection. Generates compliance reports for detection
of security policy violations and hardening gaps.
"""

import sys
import psutil
import datetime
from typing import Dict, Any
from basilisk.utils.logger import Logger
from basilisk.core.schemas import AuditModel, FirewallModel

if sys.platform == "win32":
    import winreg  # type: ignore[import]
else:
    winreg = None  # type: ignore[assignment]


class AuditScanner:
    """
    Windows system security compliance auditor.
    Raises RuntimeError on non-Windows platforms.
    """

    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError(
                "AuditScanner requires Windows. "
                "It cannot run on Linux/macOS."
            )
        self.logger = Logger()

    def _read_reg(self, path: str, key: str) -> Any:
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ
            ) as k:
                return winreg.QueryValueEx(k, key)[0]
        except Exception:
            return None

    def perform_audit(self) -> Dict[str, Any]:
        self.logger.info("Running Compliance Audit...")
        fw_base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        fw_profiles = {
            "Standard": f"{fw_base}\\StandardProfile",
            "Public":   f"{fw_base}\\PublicProfile",
            "Domain":   f"{fw_base}\\DomainProfile",
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
            Overall="SECURE" if active_cnt >= 2 else "RISK",
        )
        uac_val = self._read_reg(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"
        )
        uac_status = "ENABLED" if uac_val == 1 else "DISABLED (CRITICAL)"
        defender_status = "MISSING"
        for p in psutil.process_iter(["name"]):
            if p.info["name"] == "MsMpEng.exe":
                defender_status = "ACTIVE"
                break

        audit = AuditModel(
            firewall=fw_model,
            uac=uac_status,
            defender=defender_status,
            last_update=str(
                self._read_reg(
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
                    r"\Auto Update\Results\Install",
                    "LastSuccessTime",
                ) or "Unknown"
            ),
            scan_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        return audit.dict()
