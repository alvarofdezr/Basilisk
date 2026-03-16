"""
Basilisk Active Response
Process termination with SIGTERM → SIGKILL escalation.
"""
import psutil
from basilisk.utils.logger import Logger

_logger = Logger()


def kill_process_by_pid(pid: int) -> bool:
    """
    Terminate a process by PID. Escalates from SIGTERM to SIGKILL if needed.

    Returns:
        True if the process was terminated, False otherwise.
    """
    try:
        process = psutil.Process(pid)
        process.terminate()
        try:
            process.wait(timeout=3)
        except psutil.TimeoutExpired:
            process.kill()

        _logger.success(f"Threat neutralized. PID {pid} terminated.")
        return True

    except psutil.NoSuchProcess:
        _logger.warning(f"Process {pid} no longer exists.")
        return False
    except psutil.AccessDenied:
        _logger.error(f"Access denied terminating PID {pid}. Admin privileges required.")
        return False
    except Exception as e:
        _logger.error(f"Unexpected error terminating process: {e}")
        return False
