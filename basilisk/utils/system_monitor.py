"""
Basilisk System Metrics Collector
Real-time CPU, RAM, and disk usage monitoring.
"""
import sys
import psutil
from typing import Dict


def get_system_metrics() -> Dict[str, float]:
    """
    Capture current system resource utilization.

    Returns:
        Dict with keys: 'cpu', 'ram', 'disk' (percentage values 0-100).
        Returns zeros on error.
    """
    try:
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent

        if sys.platform == "win32":
            import os
            drive = os.path.splitdrive(os.getcwd())[0] or "C:\\"
            disk = psutil.disk_usage(drive).percent
        else:
            disk = psutil.disk_usage("/").percent

        return {"cpu": cpu, "ram": ram, "disk": disk}
    except Exception:
        return {"cpu": 0.0, "ram": 0.0, "disk": 0.0}
