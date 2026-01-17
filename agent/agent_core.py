# agent/agent_core.py
"""
Basilisk EDR - Agent Core v6.7.1
This is the main agent module responsible for orchestrating
various security monitoring components and handling communication with the C2 server.
Author: Álvaro Fernández Ramos
Date: 2025-01-15
Last Modified v6.7.1 refactor of some functions for better performance and stability. (2025-01-15)

Notes: Uses venv to activate use .\venv\Scripts\Activate.ps1
"""
import sys
import time
import requests
import platform
import os
import urllib3
import threading
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

# Internal Imports
from basilisk.core.config import Config
from basilisk.core.database import DatabaseManager
from basilisk.core.active_response import kill_process_by_pid
from basilisk.modules.network_monitor import NetworkMonitor
from basilisk.modules.usb_monitor import USBMonitor
from basilisk.modules.port_monitor import PortMonitor
from basilisk.modules.process_monitor import ProcessMonitor
from basilisk.modules.fim import FileIntegrityMonitor
from basilisk.modules.threat_intel import ThreatIntel
from basilisk.modules.anti_ransomware import CanarySentry
from basilisk.modules.yara_scanner import YaraScanner
from basilisk.modules.network_isolation import NetworkIsolator
from basilisk.modules.audit_scanner import AuditScanner  
from basilisk.utils.system_monitor import get_system_metrics
from basilisk.utils.logger import Logger

print ("[+] Starting Basilisk Agent Core...")
print ("[+] Loading modules and configurations...")

# Global Settings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disable SSL warnings for self-signed certificates
HOSTNAME = platform.node()
logger = Logger()

class C2Client:
    """Handles secure HTTP/HTTPS communication with the C2 server.

    This class manages the persistent session, SSL verification settings
    and payload formatting for all outgoing requests from the agent.
    """
    def __init__(self, config: Config):
        self.session = requests.Session()
        self.session.verify = False 
        self.agent_id = f"AGENT_{HOSTNAME}"
        self.server_url = config.c2_url

    def send_heartbeat(self, status: str) -> Dict[str, Any]:
        """Sends a periodic heartbeat to the C2 server with system metrics.

        Captures current CPU and RAM usage, along with the agent's identifier and status,
        and transmists this data to the server.

        Args:
            status (str): Current status of the agent 
            (e.g., "ONLINE", "IDle", "BUSY").

        Returns:
            Dict[str, Any]: A dictionary containing the server's response, which may 
                include queued commands to be executed. Returns an empty dict if 
                the connection fails. Server response containing any commands or updates.    
        """
        metrics = get_system_metrics()
        try:
            payload = {
                "agent_id": self.agent_id,
                "hostname": HOSTNAME,
                "os": platform.system(),
                "status": status,
                "timestamp": time.time(),
                "cpu_percent": metrics.get("cpu", 0.0),
                "ram_percent": metrics.get("ram", 0.0)
            }
            res = self.session.post(f"{self.server_url}/api/v1/heartbeat", json=payload, timeout=2)
            if res.status_code == 200:
                return res.json()
            return {}
        except Exception:
            return {}

    def send_alert(self, msg: str, severity: str = "WARNING", alert_type: str = "GENERAL") -> None:
        """Transmits a security alert or operational event to the C2 server.

        This method is fire-and-forget; it attempts to send the alert immediately
        but suppresses any connection errors to prevent interrupting the calling thread.

        Args:
            msg (str): The content of the alert message.
            severity (str, optional): The urgency level (e.g., "INFO", "CRITICAL"). 
                Defaults to "WARNING".
            alert_type (str, optional): The category of the event (e.g., "RANSOMWARE", 
                "PROCESS_ALERT"). Defaults to "GENERAL".
        """
        try:
            logger.info(f"📤 Alert: {msg}")
            payload = {
                "agent_id": self.agent_id,
                "type": alert_type,
                "message": msg,
                "severity": severity
            }
            self.session.post(f"{self.server_url}/api/v1/alert", json=payload, timeout=3)
        except Exception:
            pass

    def upload_report(self, dtype: str, content: Any) -> None:
        """Uploads bulky data reports (audit logs, process lists) to the server.

        Unlike alerts, this method uses a longer timeout to accommodate larger payloads.

        Args:
            dtype (str): The type of report being uploaded (e.g., "processes", "ports", "audit").
                This matches the endpoint expected by the C2 API.
            content (Any): The structured data payload (usually a List or Dict) 
                to be serialized and stored.
        """
        try:
            logger.info(f"📤 Report upload: {dtype} ({len(content)} items)")
            self.session.post(f"{self.server_url}/api/v1/report/{dtype}", json={
                "agent_id": self.agent_id, "content": content
            }, timeout=10)
        except Exception as e:
            logger.error(f"Report upload failed ({dtype}): {e}")

class BasiliskAgent:
    """The central orchestration engine for the Basilisk Endpoint Detection & Response (EDR).

    This class initializes all security modules, manages threading for non-blocking 
    operations, and handles the command execution lifecycle received from the C2 server.
    
    NOTE: Silent Mode active. All alerts are sent exclusively to the C2 Dashboard.
    """

    def __init__(self):
        """Initializes the agent, loads configuration, and prepares the execution pool."""
        logger.info("🛡️ Initializing Basilisk Agent v6.7.1 (Silent Mode)...")
        self.running = False
        
        # 1. Configuration & Core
        self.config = Config()
        self.db = DatabaseManager(db_name=self.config.db_name)
        self.c2 = C2Client(self.config)
        
        # 2. Security Modules
        self.yara = YaraScanner()
        self.audit = AuditScanner()
        self.isolator = NetworkIsolator(self.config.c2_url)
        self.proc_mon = ProcessMonitor()
        self.ti = ThreatIntel(self.config.virustotal_api_key)
        
        # Modules with dependencies
        self.net_mon = NetworkMonitor(self.db, c2_client=self.c2, notifier=None, config=self.config)
        self.usb_mon = USBMonitor(self.db, c2_client=self.c2)
        self.port_mon = PortMonitor(self.db, c2_client=self.c2)
        self.fim = FileIntegrityMonitor(self.db)
        self.ransomware_mon = CanarySentry(on_detection_callback=self._handle_ransomware_alert)

        # 3. Execution Pool
        self.command_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="AsyncWorker")

    def _handle_ransomware_alert(self, msg: str) -> None:
        """High-priority callback triggered when ransomware behavior is detected."""
        logger.error(f"⚠️ RANSOMWARE DETECTED: {msg}")
        self.c2.send_alert(msg, "CRITICAL", "RANSOMWARE")

    # --- COMMAND HANDLERS ---

    def _handle_kill_process(self, pid_str: str) -> None:
        """Attempts to terminate a process by PID."""
        try:
            pid = int(pid_str)
            if kill_process_by_pid(pid):
                self.c2.send_alert(f"Threat neutralized: PID {pid}", "INFO", "RESPONSE")
            else:
                self.c2.send_alert(f"Failed to kill PID {pid}", "ERROR", "RESPONSE")
        except ValueError:
            logger.error(f"Invalid PID format: {pid_str}")

    def _handle_yara_scan(self, path: str) -> None:
        """Executes a YARA signature scan on a specific file path."""
        matches = self.yara.scan_file(path)
        if matches:
            self.c2.send_alert(f"YARA Match found: {path}", "CRITICAL", "YARA_DETECTION")
        else:
            self.c2.send_alert(f"Scan clean: {path}", "INFO", "SECURITY_AUDIT")

    def _process_async_command(self, cmd_str: str) -> None:
        """Parses and executes commands received from the C2 server."""
        try:
            logger.info(f"⚡ Executing async task: {cmd_str}")

            # 1. Parameterized Commands (Cmd:Arg)
            if ":" in cmd_str:
                action, arg = cmd_str.split(":", 1)
                arg = arg.strip()
                
                if action == "KILL":
                    self._handle_kill_process(arg)
                elif action == "SCAN_YARA":
                    self._handle_yara_scan(arg)
                return

            # 2. Static Commands
            if cmd_str == "REPORT_PROCESSES":
                self.c2.upload_report("processes", self.proc_mon.scan_processes())
                
            elif cmd_str == "REPORT_PORTS":
                self.c2.upload_report("ports", self.port_mon.get_full_report())

            elif cmd_str == "ISOLATE_HOST":
                if self.isolator.isolate_host():
                    self.c2.send_alert("HOST ISOLATED. Network lockdown active.", "CRITICAL", "NET_DEFENSE")

            elif cmd_str == "UNISOLATE_HOST":
                if self.isolator.restore_connection():
                    self.c2.send_alert("Connectivity restored.", "INFO", "NET_ALLOW")

            elif cmd_str == "RUN_AUDIT":
                self.c2.upload_report("audit", self.audit.perform_audit())
                self.c2.send_alert("Compliance Audit uploaded.", "INFO", "SECURITY_AUDIT")

            elif cmd_str == "REPORT_NETWORK_MAP":
                self.c2.upload_report("network_map", self.net_mon.get_network_snapshot())

            elif cmd_str == "CREATE_BASELINE":
                target = self.config.directories[0] if self.config.directories else "."
                self.fim.scan_directory(target, mode="baseline")
                self.c2.send_alert("FIM Baseline updated successfully.", "INFO", "SECURITY_AUDIT")
            
            logger.success(f"Task completed: {cmd_str}")

        except Exception as e:
            logger.error(f"Async command error ({cmd_str}): {e}")
            self.c2.send_alert(f"Execution error: {e}", "ERROR", "DEBUG")

    def execute_command(self, cmd_data: Any) -> None:
        """Delegates a command to the thread pool."""
        cmd = cmd_data.get("cmd") if isinstance(cmd_data, dict) else cmd_data
        cmd_str = str(cmd)
        self.command_executor.submit(self._process_async_command, cmd_str)

    # --- BACKGROUND WORKERS ---

    def _worker_process_monitor(self) -> None:
        """Background thread: Monitors process list for critical threats."""
        while self.running:
            try:
                procesos = self.proc_mon.scan_processes()
                for p in procesos:
                    if p.get('risk') == 'CRITICAL':
                        self.c2.send_alert(f"Critical Process: {p['name']}", "CRITICAL", "PROCESS_ALERT")
                time.sleep(20) 
            except Exception:
                time.sleep(5)

    def _worker_fim(self) -> None:
        """Background thread: Monitors file integrity in configured directories."""
        targets = self.config.directories
        while self.running:
            try:
                for folder in targets:
                    if os.path.exists(folder):
                        self.fim.scan_directory(folder, mode="monitor")
                time.sleep(30)
            except Exception:
                time.sleep(10)

    def _worker_network(self) -> None:
        """Background thread: Monitors active network connections."""
        while self.running:
            try:
                if self.net_mon:
                    self.net_mon.scan_connections()
                time.sleep(5)
            except Exception:
                time.sleep(5)

    def start(self) -> None:
        """Starts the agent's main loop and background services."""
        self.running = True
        
        # 1. Start Anti-Ransomware (High Priority)
        if self.ransomware_mon:
            self.ransomware_mon.start()

        # 2. Start Background Threads
        threads = [
            threading.Thread(target=self._worker_process_monitor, name="T-Proc", daemon=True),
            threading.Thread(target=self._worker_fim, name="T-FIM", daemon=True),
            threading.Thread(target=self._worker_network, name="T-Net", daemon=True)
        ]
        for t in threads: t.start()

        logger.success(f"🚀 Agent active (Silent Mode). ID: {self.c2.agent_id}")

        # 3. Main Heartbeat Loop
        try:
            while True:
                if self.usb_mon: self.usb_mon.check_usb_changes()
                
                response = self.c2.send_heartbeat("ONLINE")
                if response and "command" in response and response["command"]:
                    self.execute_command(response["command"])
                
                time.sleep(3) 

        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """Performs a graceful shutdown of all services and threads."""
        logger.info("Stopping agent services...")
        self.running = False
        self.command_executor.shutdown(wait=False)
        if self.ransomware_mon:
            self.ransomware_mon.stop()
        sys.exit(0)

if __name__ == "__main__":
    BasiliskAgent().start()