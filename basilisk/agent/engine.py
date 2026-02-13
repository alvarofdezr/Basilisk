
# agent/agent_core.py
"""
Basilisk EDR - Agent Core v7.1.0 (Refactored & Modular)
Enterprise-grade endpoint agent with Command Dispatcher architecture.
Author: Álvaro Fernández Ramos
"""

import sys
import time
import requests
import platform
import os
import urllib3
import threading
from typing import Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor

# Internal Imports (Legacy path support)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PACKAGE_ROOT = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT = os.path.dirname(PACKAGE_ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

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


# Global Settings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HOSTNAME = platform.node()
logger = Logger()

print("[+] Starting Basilisk Agent Core v7.1.0...")


class C2Client:
    """Handles secure HTTP/HTTPS communication with the C2 server."""

    def __init__(self, config: Config):
        self.session = requests.Session()
        self.session.verify = False
        self.agent_id = f"AGENT_{HOSTNAME}"
        self.server_url = config.c2_url
        self.timeout = 5

    def send_heartbeat(self, status: str) -> Dict[str, Any]:
        """Sends periodic telemetry and retrieves commands."""
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
            res = self.session.post(
                f"{self.server_url}/api/v1/heartbeat",
                json=payload,
                timeout=2
            )
            return res.json() if res.status_code == 200 else {}
        except Exception:
            return {}

    def send_alert(self, msg: str, severity: str = "WARNING", alert_type: str = "GENERAL") -> None:
        """Transmits security alerts (Fire & Forget)."""
        try:
            logger.info(f"📤 Alert: {msg}")
            payload = {
                "agent_id": self.agent_id,
                "type": alert_type,
                "message": msg,
                "severity": severity
            }
            self.session.post(
                f"{self.server_url}/api/v1/alert",
                json=payload,
                timeout=3
            )
        except Exception:
            pass

    def upload_report(self, dtype: str, content: Any) -> None:
        """Uploads large datasets (reports)."""
        try:
            logger.info(f"📤 Uploading report: {dtype} ({len(content)} items)")
            self.session.post(
                f"{self.server_url}/api/v1/report/{dtype}",
                json={
                    "agent_id": self.agent_id,
                    "content": content
                },
                timeout=15
            )
        except Exception as e:
            logger.error(f"Report upload failed ({dtype}): {e}")


class BasiliskAgent:
    """
    Central orchestration engine with Dispatcher Pattern.
    """

    def __init__(self):
        logger.info("🛡️ Initializing Basilisk Agent v7.1.0 (Dispatcher Mode)...")
        self.running = False
        self.config = Config()
        self.db = DatabaseManager(db_name=self.config.db_name)
        self.c2 = C2Client(self.config)

        # --- MODULE INITIALIZATION ---
        self.modules = {
            'yara': YaraScanner(),
            'audit': AuditScanner(),
            'isolator': NetworkIsolator(self.config.c2_url),
            'proc_mon': ProcessMonitor(),
            'ti': ThreatIntel(self.config.virustotal_api_key),
            'net_mon': NetworkMonitor(self.db, c2_client=self.c2, notifier=None, config=self.config),
            'usb_mon': USBMonitor(self.db, c2_client=self.c2),
            'port_mon': PortMonitor(self.db, c2_client=self.c2),
            'fim': FileIntegrityMonitor(self.db),
            'ransom': CanarySentry(on_detection_callback=self._handle_ransomware_alert)
        }

        # --- COMMAND DISPATCHER MAP ---
        # Maps command strings to method references for O(1) execution
        self.COMMAND_HANDLERS: Dict[str, Callable[[str], None]] = {
            'KILL': self._cmd_kill_process,
            'SCAN_YARA': self._cmd_yara_scan,
            'REPORT_PROCESSES': self._cmd_report_processes,
            'REPORT_PORTS': self._cmd_report_ports,
            'ISOLATE_HOST': self._cmd_isolate_host,
            'UNISOLATE_HOST': self._cmd_unisolate_host,
            'RUN_AUDIT': self._cmd_run_audit,
            'REPORT_NETWORK_MAP': self._cmd_report_network,
            'CREATE_BASELINE': self._cmd_create_baseline
        }

        self.command_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="CmdWorker")

    # --- CALLBACKS & HANDLERS ---
    def _handle_ransomware_alert(self, msg: str) -> None:
        logger.error(f"⚠️ RANSOMWARE DETECTED: {msg}")
        self.c2.send_alert(msg, "CRITICAL", "RANSOMWARE")

    # --- COMMAND IMPLEMENTATIONS (Clean & Isolated) ---
    def _cmd_kill_process(self, arg: str) -> None:
        try:
            pid = int(arg)
            if kill_process_by_pid(pid):
                self.c2.send_alert(
                    f"Threat neutralized: PID {pid}", "INFO", "RESPONSE"
                )
            else:
                self.c2.send_alert(
                    f"Failed to kill PID {pid}", "ERROR", "RESPONSE"
                )
        except ValueError:
            logger.error(f"Invalid PID: {arg}")

    def _cmd_yara_scan(self, path: str) -> None:
        matches = self.modules['yara'].scan_file(path)
        if matches:
            self.c2.send_alert(
                f"YARA Match: {path}", "CRITICAL", "YARA_DETECTION"
            )

    def _cmd_report_processes(self, _: str) -> None:
        data = self.modules['proc_mon'].scan_processes()
        self.c2.upload_report("processes", data)

    def _cmd_report_ports(self, _: str) -> None:
        data = self.modules['port_mon'].get_full_report()
        self.c2.upload_report("ports", data)

    def _cmd_isolate_host(self, _: str) -> None:
        if self.modules['isolator'].isolate_host():
            self.c2.send_alert(
                "HOST ISOLATED via Firewall.", "CRITICAL", "NET_DEFENSE"
            )

    def _cmd_unisolate_host(self, _: str) -> None:
        if self.modules['isolator'].restore_connection():
            self.c2.send_alert("Connectivity restored.", "INFO", "NET_ALLOW")

    def _cmd_run_audit(self, _: str) -> None:
        report = self.modules['audit'].perform_audit()
        self.c2.upload_report("audit", report)
        self.c2.send_alert(
            "Compliance Audit uploaded.", "INFO", "SECURITY_AUDIT"
        )

    def _cmd_report_network(self, _: str) -> None:
        data = self.modules['net_mon'].get_network_snapshot()
        self.c2.upload_report("network_map", data)

    def _cmd_create_baseline(self, _: str) -> None:
        target = self.config.directories[0] if self.config.directories else "."
        self.modules['fim'].scan_directory(target, mode="baseline")
        self.c2.send_alert("FIM Baseline updated.", "INFO", "SECURITY_AUDIT")

    # --- CORE LOGIC ---
    def _process_command_payload(self, raw_cmd: str) -> None:
        """
        Parses command string and routes to the correct handler.
        Format: "ACTION" or "ACTION:ARGUMENT"
        """
        try:
            logger.info(f"⚡ Received Task: {raw_cmd}")
            action = raw_cmd
            arg = ""
            if ":" in raw_cmd:
                action, arg = raw_cmd.split(":", 1)
                action = action.strip()
                arg = arg.strip()
            handler = self.COMMAND_HANDLERS.get(action)
            if handler:
                handler(arg)
                logger.success(f"Task completed: {action}")
            else:
                logger.warning(f"Unknown command received: {action}")
        except Exception as e:
            logger.error(f"Execution failed ({raw_cmd}): {e}")
            self.c2.send_alert(f"Agent Execution Error: {e}", "ERROR", "DEBUG")

    # --- MAIN LOOP & WORKERS ---
    def start(self) -> None:
        self.running = True
        # Start Background Services
        if self.modules['ransom']:
            self.modules['ransom'].start()
        # Helper for starting threads

        def run_thread(target, name):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            return t
        run_thread(self._worker_process, "T-Proc")
        run_thread(self._worker_fim, "T-FIM")
        run_thread(self._worker_net, "T-Net")
        logger.success(f"🚀 Agent Online. ID: {self.c2.agent_id}")
        # Main Heartbeat Loop
        try:
            while self.running:
                if self.modules['usb_mon']:
                    self.modules['usb_mon'].check_usb_changes()
                resp = self.c2.send_heartbeat("ONLINE")
                cmd = resp.get("command")
                if cmd:
                    # Offload command execution to thread pool to keep heartbeat steady
                    self.command_executor.submit(self._process_command_payload, str(cmd))
                time.sleep(3)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        logger.info("Stopping agent...")
        self.running = False
        self.command_executor.shutdown(wait=False)
        if self.modules['ransom']:
            self.modules['ransom'].stop()
        sys.exit(0)

    # --- WORKER WRAPPERS ---
    def _worker_process(self):
        while self.running:
            try:
                for p in self.modules['proc_mon'].scan_processes():
                    if p.get('risk') == 'CRITICAL':
                        self.c2.send_alert(
                            f"Critical Process: {p['name']}",
                            "CRITICAL",
                            "PROCESS_ALERT"
                        )
                time.sleep(20)
            except Exception:
                time.sleep(5)

    def _worker_fim(self):
        while self.running:
            try:
                for f in self.config.directories:
                    if os.path.exists(f):
                        self.modules['fim'].scan_directory(f, mode="monitor")
                time.sleep(30)
            except Exception:
                time.sleep(10)

    def _worker_net(self):
        while self.running:
            try:
                self.modules['net_mon'].scan_connections()
                time.sleep(5)
            except Exception:
                time.sleep(5)


if __name__ == "__main__":
    BasiliskAgent().start()
