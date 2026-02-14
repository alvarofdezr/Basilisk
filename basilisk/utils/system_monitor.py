"""
Basilisk System Metrics Collector
Real-time CPU, RAM, and disk usage monitoring.
"""
import psutil
from typing import Dict


def get_system_metrics() -> Dict[str, float]:
    """
    Capture current system resource utilization.
    
    Returns:
        Dict with keys: 'cpu', 'ram', 'disk' (percentage values)
    """
    try:
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        return {"cpu": cpu, "ram": ram, "disk": disk}
    except Exception:
        return {"cpu": 0.0, "ram": 0.0, "disk": 0.0}