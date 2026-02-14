
# agent/agent_core.py
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
- RUN_AUDIT: Windows compliance verification
- CREATE_BASELINE: Initialize filesystem baseline
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
    
    Disables SSL verification for lab environments with self-signed certs.
    Implements 5-second timeout for network-resilient agent operation.
    """

    def __init__(self, config: Config):
        """Initialize C2 client with server connection parameters.
        
        Args:
            config: Config instance with c2_url and api endpoint
        """
        self.session = requests.Session()
        self.session.verify = False
        self.agent_id = f"AGENT_{HOSTNAME}"
        self.server_url = config.c2_url
        self.timeout = 5

    def send_heartbeat(self, status: str) -> Dict[str, Any]:
        """Send periodic telemetry and receive command batch.
        
        Heartbeat payload includes system metrics (CPU, RAM) and agent
        metadata (ID, hostname, OS). Server responds with command array.
        
        Args:
            status: Agent status string (e.g., "ONLINE")
            
        Returns:
            Dict: Server response with "commands" array or empty dict on failure
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
            res = self.session.post(
                f"{self.server_url}/api/v1/heartbeat",
                json=payload,
                timeout=2
            )
            return res.json() if res.status_code == 200 else {}
        except Exception:
            return {}

    def send_alert(self, msg: str, severity: str = "WARNING", alert_type: str = "GENERAL") -> None:
        """Transmit security alert to C2 (fire-and-forget pattern).
        
        Asynchronously sends event without blocking. Used for:
        - Malware detections (YARA, threat intel, ransomware)
        - Process anomalies (unauthorized process execution)
        - Network anomalies (suspicious connections)
        
        Args:
            msg: Human-readable alert message
            severity: Level (INFO, WARNING, CRITICAL, ERROR)
            alert_type: Category (PROCESS_ALERT, RANSOMWARE, NET_ANOMALY, etc.)
        """
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
        """Upload enumeration report (processes, ports, network, audit).
        
        Large dataset endpoint for REPORT_* commands. Logs item count.
        Timeouts set to 15 seconds for large dataset uploads.
        
        Args:
            dtype: Report type (processes, ports, network_map, audit)
            content: List of dictionaries containing enumeration results
        """
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
    """Agent orchestration engine with Command Dispatcher architecture.
    
    Lifecycle:
    1. __init__: Load config, initialize all modules, map commands
    2. start(): Spawn background workers, enter heartbeat loop
    3. Main loop: Poll C2, dispatch commands to thread pool
    4. Workers: Continuous monitoring for anomalies
    
    Threading Model:
    - Main thread: Heartbeat loop + USB polling
    - Command thread pool (3 workers): Async command execution
    - Background workers (3 threads): Process, FIM, Network monitoring
    - Ransomware CanarySentry: Event-driven thread
    
    Resilience:
    - Network timeouts don't crash agent (try/except at heartbeat)
    - Failed commands logged but don't block heartbeat
    - Thread pool rejects handled gracefully
    """

    def __init__(self):
        """Initialize agent: Load config, setup modules, map commands.
        
        Creates DatabaseManager for baseline storage, initializes all
        threat detection modules (YARA, audit, process monitor, etc.),
        and populates command dispatcher map.
        """
        logger.info("🛡️ Initializing Basilisk Agent v7.1.0 (Dispatcher Mode)...")
        self.running = False
        self.config = Config()
        self.db = DatabaseManager(db_name=self.config.db_name)
        self.c2 = C2Client(self.config)

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

    def _handle_ransomware_alert(self, msg: str) -> None:
        """Callback from CanarySentry when canary file modification detected.
        
        Args:
            msg: Alert message describing canary file activity
        """
        logger.error(f"⚠️ RANSOMWARE DETECTED: {msg}")
        self.c2.send_alert(msg, "CRITICAL", "RANSOMWARE")

    def _cmd_kill_process(self, arg: str) -> None:
        """Handler for KILL command: Terminate process by PID.
        
        Parses PID argument and calls active_response module.
        Sends result alert to C2.
        
        Args:
            arg: Process ID as string (e.g., "1234")
        """
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
        """Handler for SCAN_YARA: Execute YARA malware scans.
        
        Args:
            path: Target path (file or directory) to scan
        """
        matches = self.modules['yara'].scan_file(path)
        if matches:
            self.c2.send_alert(
                f"YARA Match: {path}", "CRITICAL", "YARA_DETECTION"
            )

    def _cmd_report_processes(self, _: str) -> None:
        """Handler for REPORT_PROCESSES: Enumerate and upload process list.
        
        Scans all running processes with risk scoring, uploads array.
        """
        logger.info("🔍 [PROCESSES] Starting scan...")
        data = self.modules['proc_mon'].scan_processes()
        logger.info(f"🔍 [PROCESSES] Found {len(data)} processes, uploading...")
        self.c2.upload_report("processes", data)
        logger.success(f"✅ [PROCESSES] Uploaded {len(data)} items")

    def _cmd_report_ports(self, _: str) -> None:
        """Handler for REPORT_PORTS: Enumerate and upload listening services.
        
        Scans all open ports with service enumeration and risk assessment.
        """
        logger.info("🔌 [PORTS] Starting scan...")
        data = self.modules['port_mon'].get_full_report()
        logger.info(f"🔌 [PORTS] Found {len(data)} ports, uploading...")
        self.c2.upload_report("ports", data)
        logger.success(f"✅ [PORTS] Uploaded {len(data)} items")

    def _cmd_isolate_host(self, _: str) -> None:
        """Handler for ISOLATE_HOST: Apply firewall-based network containment.
        
        Implements emergency isolation blocking all traffic except C2.
        """
        if self.modules['isolator'].isolate_host():
            self.c2.send_alert(
                "HOST ISOLATED via Firewall.", "CRITICAL", "NET_DEFENSE"
            )

    def _cmd_unisolate_host(self, _: str) -> None:
        """Handler for UNISOLATE_HOST: Restore normal network connectivity.
        
        Removes all Basilisk isolation firewall rules.
        """
        if self.modules['isolator'].restore_connection():
            self.c2.send_alert("Connectivity restored.", "INFO", "NET_ALLOW")

    def _cmd_run_audit(self, _: str) -> None:
        """Handler for RUN_AUDIT: Windows compliance verification.
        
        Checks firewall, UAC, Windows Defender, updates status.
        """
        logger.info("📋 [AUDIT] Starting audit scan...")
        report = self.modules['audit'].perform_audit()
        logger.info(f"📋 [AUDIT] Completed, uploading...")
        self.c2.upload_report("audit", report)
        self.c2.send_alert(
            "Compliance Audit uploaded.", "INFO", "SECURITY_AUDIT"
        )
        logger.success("✅ [AUDIT] Uploaded")

    def _cmd_report_network(self, _: str) -> None:
        """Handler for REPORT_NETWORK_MAP: Upload active connections.
        
        Enumerates ESTABLISHED TCP/UDP connections with process mapping.
        """
        data = self.modules['net_mon'].get_network_snapshot()
        self.c2.upload_report("network_map", data)

    def _cmd_create_baseline(self, _: str) -> None:
        """Handler for CREATE_BASELINE: Initialize FIM baseline.
        
        Hashes first configured directory and stores baseline in database.
        """
        target = self.config.directories[0] if self.config.directories else "."
        self.modules['fim'].scan_directory(target, mode="baseline")
        self.c2.send_alert("FIM Baseline updated.", "INFO", "SECURITY_AUDIT")

    def _process_command_payload(self, raw_cmd: str) -> None:
        """Parse and execute single command string.
        
        Format: "ACTION" or "ACTION:ARGUMENT"
        Supports legacy single-command and new array-based formats.
        
        Args:
            raw_cmd: Raw command string from server (e.g., "KILL:1234")
        """
        try:
            logger.info(f"⚡ Received Task: {raw_cmd}")
            action = raw_cmd
            arg = ""
            if ":" in raw_cmd:
                action, arg = raw_cmd.split(":", 1)
                action = action.strip()
                arg = arg.strip()
            
            logger.info(f"🎯 [ACTION] Looking for handler for: {action}")
            handler = self.COMMAND_HANDLERS.get(action)
            
            if handler:
                logger.info(f"📍 [ACTION] Found handler, executing...")
                handler(arg)
                logger.success(f"✅ Task completed: {action}")
            else:
                logger.warning(f"❌ Unknown command received: {action}")
                logger.warning(f"Available commands: {list(self.COMMAND_HANDLERS.keys())}")
        except Exception as e:
            logger.error(f"Execution failed ({raw_cmd}): {e}")
            self.c2.send_alert(f"Agent Execution Error: {e}", "ERROR", "DEBUG")

    def start(self) -> None:
        """Start agent: Spawn workers, enter main heartbeat loop.
        
        Lifecycle:
        1. Start ransomware canary monitor
        2. Spawn 3 background worker threads
        3. Enter infinite heartbeat loop (3-second cycle)
        4. On exit, graceful shutdown of all threads
        """
        self.running = True
        if self.modules['ransom']:
            self.modules['ransom'].start()

        def run_thread(target, name):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            return t
        
        run_thread(self._worker_process, "T-Proc")
        run_thread(self._worker_fim, "T-FIM")
        run_thread(self._worker_net, "T-Net")
        logger.success(f"🚀 Agent Online. ID: {self.c2.agent_id}")
        
        try:
            while self.running:
                if self.modules['usb_mon']:
                    self.modules['usb_mon'].check_usb_changes()
                
                logger.info(f"💓 Heartbeat #{int(time.time() % 10000)} -> Server")
                resp = self.c2.send_heartbeat("ONLINE")
                
                commands = resp.get("commands", [])
                if commands and isinstance(commands, list):
                    logger.info(f"⚡ Received {len(commands)} commands: {commands}")
                    for cmd in commands:
                        if cmd:
                            logger.info(f"▶️ Processing: {cmd}")
                            self.command_executor.submit(self._process_command_payload, str(cmd))
                
                elif resp.get("command"):
                    cmd = resp.get("command")
                    logger.info(f"▶️ Processing: {cmd}")
                    self.command_executor.submit(self._process_command_payload, str(cmd))
                
                time.sleep(3)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """Graceful shutdown: Cleanup threads and exit.
        
        Stops ransomware monitor, shuts down command thread pool,
        and exits process cleanly.
        """
        logger.info("Stopping agent...")
        self.running = False
        self.command_executor.shutdown(wait=False)
        if self.modules['ransom']:
            self.modules['ransom'].stop()
        sys.exit(0)

    def _worker_process(self) -> None:
        """Background worker: Continuous process monitoring.
        
        Scans all processes every 20 seconds, alerts on critical processes.
        Runs in separate thread to avoid blocking heartbeat.
        """
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

    def _worker_fim(self) -> None:
        """Background worker: Continuous file integrity monitoring.
        
        Scans all monitored directories every 30 seconds for file changes.
        Runs in separate thread to avoid blocking heartbeat.
        """
        while self.running:
            try:
                for f in self.config.directories:
                    if os.path.exists(f):
                        self.modules['fim'].scan_directory(f, mode="monitor")
                time.sleep(30)
            except Exception:
                time.sleep(10)

    def _worker_net(self) -> None:
        """Background worker: Continuous network monitoring.
        
        Scans active connections every 5 seconds for suspicious anomalies.
        Runs in separate thread to avoid blocking heartbeat.
        """
        while self.running:
            try:
                self.modules['net_mon'].scan_connections()
                time.sleep(5)
            except Exception:
                time.sleep(5)


if __name__ == "__main__":
    BasiliskAgent().start()
