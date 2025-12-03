# basilisk/utils/system_monitor.py
import psutil
from typing import Dict

def get_system_metrics() -> Dict[str, float]:
    """
    Captures real-time system resource usage.
    Returns: Dictionary with CPU, RAM, and Disk percentage usage.
    """
    try:
        # interval=None avoids blocking execution
        cpu = psutil.cpu_percent(interval=None) 
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        return {"cpu": cpu, "ram": ram, "disk": disk}
    except Exception:
        return {"cpu": 0.0, "ram": 0.0, "disk": 0.0}