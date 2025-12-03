# basilisk/core/active_response.py
import psutil
from basilisk.utils.logger import Logger

def kill_process_by_pid(pid: int) -> bool:
    """
    Attempts to terminate a malicious process by its PID.
    Escalates from SIGTERM (soft kill) to SIGKILL (hard kill) if necessary.
    
    Returns:
        bool: True if operation successful, False otherwise.
    """
    logger = Logger()
    try:
        process = psutil.Process(pid)
        process.terminate()  # Attempt graceful shutdown
        try:
            process.wait(timeout=3)
        except psutil.TimeoutExpired:
            process.kill()  # Force execution halt (Kill -9)
        
        logger.success(f"Threat neutralized. PID {pid} terminated.")
        return True
        
    except psutil.NoSuchProcess:
        logger.warning(f"Process {pid} no longer exists.")
        return False
    except psutil.AccessDenied:
        logger.error(f"Access denied terminating PID {pid}. Admin privileges required.")
        return False
    except Exception as e:
        logger.error(f"Unexpected error terminating process: {e}")
        return False