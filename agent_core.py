# pysentinel/agent_core.py
import time
import requests
import platform
import logging
import os
import hashlib
from typing import Dict, Any, Optional

# Core Imports
from pysentinel.core.config import Config
from pysentinel.core.database import DatabaseManager
from pysentinel.core.active_response import kill_process_by_pid
from pysentinel.utils.logger import Logger
from pysentinel.utils.notifier import TelegramNotifier

# Module Imports
from pysentinel.modules.network_monitor import NetworkMonitor
from pysentinel.modules.usb_monitor import USBMonitor
from pysentinel.modules.port_monitor import PortMonitor
from pysentinel.modules.process_monitor import ProcessMonitor
from pysentinel.modules.fim import FileIntegrityMonitor
from pysentinel.modules.threat_intel import ThreatIntel
from pysentinel.modules.anti_ransomware import CanarySentry

# Constants
SERVER_URL = "http://localhost:8000/api/v1"
HOSTNAME = platform.node()

# Initialize Global Logger
logger = Logger()

class C2Client:
    """
    Handles HTTP communication with the Command & Control (C2) server.
    """
    def __init__(self, config: Config):
        self.session = requests.Session()
        self.agent_id = f"AGENT_{HOSTNAME}"
        self.server_url = SERVER_URL

    def send_heartbeat(self, status: str) -> Dict[str, Any]:
        """Sends periodic keep-alive signal and retrieves pending commands."""
        try:
            payload = {
                "agent_id": self.agent_id,
                "hostname": HOSTNAME,
                "os": platform.system(),
                "status": status,
                "timestamp": time.time()
            }
            res = self.session.post(f"{self.server_url}/heartbeat", json=payload, timeout=3)
            return res.json() if res.status_code == 200 else {}
        except Exception: 
            return {}

    def send_alert(self, msg: str, severity: str = "WARNING", alert_type: str = "GENERAL") -> None:
        """Transmits security alerts to the C2 server."""
        try:
            logger.info(f"Dispatching alert: {msg}")
            payload = {
                "agent_id": self.agent_id,
                "type": alert_type,
                "message": msg, 
                "severity": severity,
                "timestamp": time.time()
            }
            self.session.post(f"{self.server_url}/alert", json=payload)
        except Exception as e: 
            logger.error(f"Failed to send alert to C2: {e}")

    def upload_report(self, dtype: str, content: Any) -> None:
        """Uploads structured data reports (processes, ports, etc.)."""
        try: 
            self.session.post(f"{self.server_url}/report/{dtype}", json={
                "agent_id": self.agent_id, "content": content
            })
        except Exception: 
            pass

class PySentinelAgent:
    """
    Main Agent Controller. Initializes modules and manages the execution loop.
    """
    def __init__(self):
        logger.info("Initializing PySentinel Agent...")
        self.config = Config()
        self.db = DatabaseManager(db_name=self.config.db_name)
        self.notifier = TelegramNotifier(self.config)
        self.c2 = C2Client(self.config)
        
        # Module Initialization
        self.net_mon = NetworkMonitor(self.db, self.c2, self.config)
        self.usb_mon = USBMonitor(self.db, self.c2)
        self.port_mon = PortMonitor(self.db, self.c2)
        self.proc_mon = ProcessMonitor()
        self.fim = FileIntegrityMonitor(self.db)
        self.ti = ThreatIntel(self.config.virustotal_api_key)
        
        # Reactive Modules
        self.ransomware_mon = CanarySentry(on_detection_callback=self._handle_ransomware_alert)

    def _handle_ransomware_alert(self, msg: str) -> None:
        """Callback for high-priority ransomware detection events."""
        logger.error(f"CRITICAL THREAT: {msg}")
        self.c2.send_alert(msg, "CRITICAL", "RANSOMWARE")
        self.notifier.send_alert(f"☣️ {msg}")

    def execute_command(self, cmd_data: Any) -> None:
        """
        Parses and executes commands received from C2.
        Supports simple strings or dictionary objects with authentication.
        """
        cmd = cmd_data
        auth = ""
        
        if isinstance(cmd_data, dict):
            cmd = cmd_data.get("cmd")
            auth = cmd_data.get("auth", "")

        logger.info(f"Executing command: {cmd}")
        
        # Authenticated Commands (Admin)
        if cmd == "CREATE_BASELINE":
            input_hash = hashlib.sha512(auth.encode()).hexdigest()
            if input_hash == self.config.admin_hash:
                logger.success("Admin authentication successful. Updating FIM baseline...")
                for folder in self.config.directories:
                    if os.path.exists(folder):
                        self.fim.scan_directory(folder, mode="baseline")
                self.c2.send_alert("FIM Baseline updated by Administrator.", "INFO", "FIM")
            else:
                logger.warning("Baseline update failed: Invalid password.")
                self.c2.send_alert("Unauthorized attempt to modify Baseline.", "WARNING", "SECURITY")

        # Operational Commands
        elif cmd == "REPORT_PROCESSES":
            data = self.proc_mon.scan_processes()
            self.c2.upload_report("processes", data)
            
        elif cmd == "REPORT_PORTS":
            data = self.port_mon.get_full_report()
            self.c2.upload_report("ports", data)
            
        elif cmd.startswith("SCAN_VT:"):
            try:
                path = cmd.split(":", 1)[1]
                fhash = self.proc_mon.get_process_hash(path)
                if fhash:
                    logger.info(f"Querying VirusTotal for: {os.path.basename(path)}")
                    res = self.ti.check_hash(fhash)
                    if res:
                        mal = res.get('malicious', 0)
                        total = res.get('total', 0)
                        msg = f"VT Result [{os.path.basename(path)}]: {mal}/{total} engines detected malicious behavior."
                        severity = "CRITICAL" if mal > 0 else "INFO"
                        self.c2.send_alert(msg, severity, "THREAT_INTEL")
                else:
                    self.c2.send_alert(f"Hashing failed for: {path}", "WARNING", "ERROR")
            except Exception as e:
                logger.error(f"VirusTotal integration error: {e}")

        elif cmd.startswith("KILL:"):
            try:
                pid = int(cmd.split(":")[1])
                success = kill_process_by_pid(pid)
                status = "TERMINATED" if success else "FAILED"
                self.c2.send_alert(f"KILL PID {pid} result: {status}", "WARNING", "RESPONSE")
            except ValueError:
                logger.error("Invalid PID format received.")

    def run(self) -> None:
        """Main execution loop."""
        logger.success(f"Agent Active on: {HOSTNAME}")
        
        # Start background threads
        self.ransomware_mon.start()

        while True:
            try:
                # Passive Monitoring
                self.net_mon.scan_connections() 
                self.usb_mon.check_usb_changes()
                
                for d in self.config.directories:
                    if os.path.exists(d): 
                        self.fim.scan_directory(d, mode="monitor")

                self.port_mon.scan_ports()

                # C2 Communication
                data = self.c2.send_heartbeat("ONLINE")
                
                if data and "command" in data and data["command"]:
                    self.execute_command(data["command"])

                time.sleep(3)

            except KeyboardInterrupt:
                logger.info("Stopping agent...")
                self.ransomware_mon.stop()
                break
            except Exception as e: 
                logger.error(f"Main loop error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    PySentinelAgent().run()