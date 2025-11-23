# pysentinel/core/active_response.py
import psutil
import logging

def kill_process_by_pid(pid: int) -> bool:
    """
    Intenta terminar un proceso malicioso dado su PID.
    Retorna True si tuvo éxito, False si falló.
    """
    try:
        process = psutil.Process(pid)
        process.terminate()  # Intento suave primero
        try:
            process.wait(timeout=3)
        except psutil.TimeoutExpired:
            process.kill()  # Forzar cierre (Kill -9)
        
        logging.info(f"[EDR] Amenaza neutralizada. PID: {pid}")
        return True
        
    except psutil.NoSuchProcess:
        logging.warning(f"[EDR] El proceso {pid} ya no existe.")
        return False
    except psutil.AccessDenied:
        logging.error(f"[EDR] Acceso denegado al intentar matar PID {pid}. ¿Faltan permisos de Admin?")
        return False
    except Exception as e:
        logging.error(f"[EDR] Error desconocido al matar proceso: {e}")
        return False