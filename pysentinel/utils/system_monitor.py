# pysentinel/utils/system_monitor.py
import psutil

def get_system_metrics():
    """Devuelve un diccionario con el uso actual de CPU, RAM y Disco"""
    try:
        cpu = psutil.cpu_percent(interval=None) # interval=None para que no bloquee
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        return {"cpu": cpu, "ram": ram, "disk": disk}
    except Exception:
        return {"cpu": 0, "ram": 0, "disk": 0}