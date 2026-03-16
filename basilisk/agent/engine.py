"""
Basilisk EDR Agent - Enterprise Endpoint Defense Platform

Core orchestration engine implementing Command Dispatcher pattern for
server-directed threat response. Three-tier architecture:

1. C2 Communication: Asynchronous heartbeat + command polling
2. Module Dispatcher: Maps commands to threat-specific handlers
3. Worker Threads: Background continuous monitoring (processes, FIM, network)

Heartbeat Cycle (3 seconds):
- Send telemetry (CPU, RAM, hostname, OS)
- Receive command batch from server
- Submit commands to thread pool for async execution
- Process results and upload reports

Supported Commands:
- KILL: Terminate process by PID
- REPORT_*: Enumerate and upload (processes, ports, network, audit)
- SCAN_YARA: Malware signature scanning
- ISOLATE_HOST: Firewall-based network containment
- RUN_AUDIT: Windows compliance verification (Windows only)
- CREATE_BASELINE: Initialize filesystem baseline
"""

import sys
import time
import requests
import platform
import os
import urllib3
import threading
from typing import Dict, Any, Callable, Optional
from concurrent.futures import ThreadPoolExecutor

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
from basilisk.utils.system_monitor import get_system_metrics
from basilisk.utils.logger import Logger

# Windows-only modules — imported conditionally to avoid crashes on Linux
if sys.platform == "win32":
    from basilisk.modules.audit_scanner import AuditScanner
else:
    AuditScanner = None  # type: ignore[assignment,misc]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HOSTNAME = platform.node()
logger = Logger()

print("[+] Starting Basilisk Agent Core v7.1.0...")


class C2Client:
    """HTTPS client for secure C2 server communication.

    Implements three-endpoint protocol:
    - POST /api/v1/heartbeat: Send telemetry, receive commands
    - POST /api/v1/alert: Fire-and-forget security events
    - POST /api/v1/report/{type}: Upload large enumeration results

    Sends X-Agent-Token header on every request so the server can verify
    the caller is a legitimate agent. Token is read from BASILISK_AGENT_TOKEN
    environment variable.
    """

    def __init__(self, config: Config):
        self.session = requests.Session()
        self.session.verify = False
        self.agent_id = f"AGENT_{HOSTNAME}"
        self.server_url = config.c2_url
        self.timeout = 5

        agent_token = os.getenv("BASILISK_AGENT_TOKEN", "").strip()
        if not agent_token:
            logger.warning(
                "⚠️  BASILISK_AGENT_TOKEN not set. "
                "All requests to the server will be rejected with 401. "
                "Add BASILISK_AGENT_TOKEN to your .env file."
            )
        self.session.headers.update({"X-Agent-Token": agent_token})

    def send_heartbeat(self, status: str) -> Dict[str, Any]:
        """Send periodic telemetry and receive command batch."""
        metrics = get_system_metrics()
        try:
            payload = {
                "agent_id": self.agent_id,
                "hostname": HOSTNAME,
                "os": platform.system(),
                "status": status,
                "timestamp": time.time(),
                "cpu_percent": metrics.get("cpu", 0.0),
                "ram_percent": metrics.get("ram", 0.0),
            }
            res = self.session.post(
                f"{self.server_url}/api/v1/heartbeat",
                json=payload,
                timeout=2,
            )
            return res.json() if res.status_code == 200 else {}
        except Exception:
            return {}

    def send_alert(
        self,
        msg: str,
        severity: str = "WARNING",
        alert_type: str = "GENERAL",
    ) -> None:
        """Transmit security alert to C2 (fire-and-forget pattern)."""
        try:
            logger.info(f"📤 Alert: {msg}")
            payload = {
                "agent_id": self.agent_id,
                "type": alert_type,
                "message": msg,
                "severity": severity,
            }
            self.session.post(
                f"{self.server_url}/api/v1/alert",
                json=payload,
                timeout=3,
            )
        except Exception: #nosec B110
            pass

    def upload_report(self, dtype: str, content: Any) -> None:
        """Upload enumeration report (processes, ports, network, audit)."""
        try:
            logger.info(f"📤 Uploading report: {dtype} ({len(content)} items)")
            self.session.post(
                f"{self.server_url}/api/v1/report/{dtype}",
                json={"agent_id": self.agent_id, "content": content},
                timeout=15,
            )
        except Exception as e:
            logger.error(f"Report upload failed ({dtype}): {e}")


class BasiliskAgent:
    """Agent orchestration engine with Command Dispatcher architecture."""

    def __init__(self):
        logger.info("🛡️ Initializing Basilisk Agent v7.1.0 (Dispatcher Mode)...")
        self.running = False
        self.config = Config()
        self.db = DatabaseManager(db_name=self.config.db_name)
        self.c2 = C2Client(self.config)

        # AuditScanner is Windows-only. On Linux it is None and RUN_AUDIT
        # commands will be skipped gracefully.
        audit_module: Optional[Any] = AuditScanner() if AuditScanner is not None else None

        self.modules = {
            "yara":     YaraScanner(),
            "audit":    audit_module,
            "isolator": NetworkIsolator(self.config.c2_url),
            "proc_mon": ProcessMonitor(),
            "ti":       ThreatIntel(self.config.virustotal_api_key),
            "net_mon":  NetworkMonitor(self.db, c2_client=self.c2, notifier=None, config=self.config),
            "usb_mon":  USBMonitor(self.db, c2_client=self.c2),
            "port_mon": PortMonitor(self.db, c2_client=self.c2),
            "fim":      FileIntegrityMonitor(self.db),
            "ransom":   CanarySentry(on_detection_callback=self._handle_ransomware_alert),
        }

        self.COMMAND_HANDLERS: Dict[str, Callable[[str], None]] = {
            "KILL":               self._cmd_kill_process,
            "SCAN_YARA":          self._cmd_yara_scan,
            "REPORT_PROCESSES":   self._cmd_report_processes,
            "REPORT_PORTS":       self._cmd_report_ports,
            "ISOLATE_HOST":       self._cmd_isolate_host,
            "UNISOLATE_HOST":     self._cmd_unisolate_host,
            "RUN_AUDIT":          self._cmd_run_audit,
            "REPORT_NETWORK_MAP": self._cmd_report_network,
            "CREATE_BASELINE":    self._cmd_create_baseline,
        }

        self.command_executor = ThreadPoolExecutor(
            max_workers=3, thread_name_prefix="CmdWorker"
        )

    def _handle_ransomware_alert(self, msg: str) -> None:
        logger.error(f"⚠️ RANSOMWARE DETECTED: {msg}")
        self.c2.send_alert(msg, "CRITICAL", "RANSOMWARE")

    def _cmd_kill_process(self, arg: str = "") -> None:
        if not arg:
            logger.error("No PID provided for KILL command.")
            return
        try:
            pid = int(arg)
            if kill_process_by_pid(pid):
                self.c2.send_alert(f"Threat neutralized: PID {pid}", "INFO", "RESPONSE")
            else:
                self.c2.send_alert(f"Failed to kill PID {pid}", "ERROR", "RESPONSE")
        except ValueError:
            logger.error(f"Invalid PID: {arg}")

    def _cmd_yara_scan(self, arg: str = "") -> None:
        if not arg:
            logger.error("No path provided for SCAN_YARA command.")
            return
        matches = self.modules["yara"].scan_file(arg)
        if matches:
            self.c2.send_alert(f"YARA Match: {arg}", "CRITICAL", "YARA_DETECTION")

    def _cmd_report_processes(self, arg: str = "") -> None:
        logger.info("🔍 [PROCESSES] Starting scan...")
        data = self.modules["proc_mon"].scan_processes()
        logger.info(f"🔍 [PROCESSES] Found {len(data)} processes, uploading...")
        self.c2.upload_report("processes", data)
        logger.info(f"✅ [PROCESSES] Uploaded {len(data)} items")

    def _cmd_report_ports(self, arg: str = "") -> None:
        logger.info("🔌 [PORTS] Starting scan...")
        data = self.modules["port_mon"].get_full_report()
        logger.info(f"🔌 [PORTS] Found {len(data)} ports, uploading...")
        self.c2.upload_report("ports", data)
        logger.info(f"✅ [PORTS] Uploaded {len(data)} items")

    def _cmd_isolate_host(self, arg: str = "") -> None:
        if self.modules["isolator"].isolate_host():
            self.c2.send_alert("HOST ISOLATED via Firewall.", "CRITICAL", "NET_DEFENSE")

    def _cmd_unisolate_host(self, arg: str = "") -> None:
        if self.modules["isolator"].restore_connection():
            self.c2.send_alert("Connectivity restored.", "INFO", "NET_ALLOW")

    def _cmd_run_audit(self, arg: str = "") -> None:
        if self.modules["audit"] is None:
            logger.warning("RUN_AUDIT skipped — AuditScanner requires Windows.")
            self.c2.send_alert("Audit skipped: Windows-only module.", "WARNING", "SECURITY_AUDIT")
            return
        logger.info("📋 [AUDIT] Starting audit scan...")
        report = self.modules["audit"].perform_audit()
        self.c2.upload_report("audit", report)
        self.c2.send_alert("Compliance Audit uploaded.", "INFO", "SECURITY_AUDIT")
        logger.info("✅ [AUDIT] Uploaded")

    def _cmd_report_network(self, arg: str = "") -> None:
        data = self.modules["net_mon"].get_network_snapshot()
        self.c2.upload_report("network_map", data)

    def _cmd_create_baseline(self, arg: str = "") -> None:
        target = self.config.directories[0] if self.config.directories else "."
        self.modules["fim"].scan_directory(target, mode="baseline")
        self.c2.send_alert("FIM Baseline updated.", "INFO", "SECURITY_AUDIT")

    def _process_command_payload(self, raw_cmd: str) -> None:
        """Parse and execute single command string (format: ACTION or ACTION:ARG)."""
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
                logger.info(f"📍 [ACTION] Executing: {action}")
                handler(arg)
                logger.info(f"✅ Task completed: {action}")
            else:
                logger.warning(f"❌ Unknown command: {action}")
                logger.warning(f"Available commands: {list(self.COMMAND_HANDLERS.keys())}")
        except Exception as e:
            logger.error(f"Execution failed ({raw_cmd}): {e}")
            self.c2.send_alert(f"Agent Execution Error: {e}", "ERROR", "DEBUG")

    def start(self) -> None:
        """Start agent: spawn workers, enter main heartbeat loop."""
        self.running = True
        if self.modules["ransom"]:
            self.modules["ransom"].start()

        def run_thread(target, name):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            return t

        run_thread(self._worker_process, "T-Proc")
        run_thread(self._worker_fim, "T-FIM")
        run_thread(self._worker_net, "T-Net")
        logger.info(f"🚀 Agent Online. ID: {self.c2.agent_id}")

        try:
            while self.running:
                if self.modules["usb_mon"]:
                    self.modules["usb_mon"].check_usb_changes()

                logger.info(f"💓 Heartbeat #{int(time.time() % 10000)} -> Server")
                resp = self.c2.send_heartbeat("ONLINE")

                commands = resp.get("commands", [])
                if commands and isinstance(commands, list):
                    logger.info(f"⚡ Received {len(commands)} commands: {commands}")
                    for cmd in commands:
                        if cmd:
                            self.command_executor.submit(
                                self._process_command_payload, str(cmd)
                            )
                elif resp.get("command"):
                    cmd = resp.get("command")
                    self.command_executor.submit(
                        self._process_command_payload, str(cmd)
                    )

                time.sleep(3)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """Graceful shutdown."""
        logger.info("Stopping agent...")
        self.running = False
        self.command_executor.shutdown(wait=False)
        if self.modules["ransom"]:
            self.modules["ransom"].stop()
        sys.exit(0)

    def _worker_process(self) -> None:
        """Background worker: continuous process monitoring every 20s."""
        while self.running:
            try:
                for p in self.modules["proc_mon"].scan_processes():
                    if p.get("risk") == "CRITICAL":
                        self.c2.send_alert(
                            f"Critical Process: {p['name']}", "CRITICAL", "PROCESS_ALERT"
                        )
                time.sleep(20)
            except Exception:
                time.sleep(5)

    def _worker_fim(self) -> None:
        """Background worker: continuous file integrity monitoring every 30s."""
        while self.running:
            try:
                for f in self.config.directories:
                    if os.path.exists(f):
                        self.modules["fim"].scan_directory(f, mode="monitor")
                time.sleep(30)
            except Exception:
                time.sleep(10)

    def _worker_net(self) -> None:
        """Background worker: continuous network monitoring every 5s."""
        while self.running:
            try:
                self.modules["net_mon"].scan_connections()
                time.sleep(5)
            except Exception:
                time.sleep(5)


def main() -> None:
    """Entry point for `basilisk-agent` CLI command (defined in pyproject.toml)."""
    BasiliskAgent().start()


if __name__ == "__main__":
    main()
