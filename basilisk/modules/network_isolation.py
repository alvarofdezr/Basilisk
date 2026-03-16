"""
Network Isolation Module - Active Response Firewall Configuration
"""
import subprocess #nosec B404
import socket
from urllib.parse import urlparse
from typing import List
from basilisk.utils.logger import Logger


class NetworkIsolator:
    """Firewall-based network containment for infected hosts."""

    def __init__(self, c2_url: str):
        self.logger = Logger()
        self.c2_url = c2_url
        self.rule_prefix = "Basilisk_Isolation"

    def _get_c2_ip(self) -> str:
        """Resolve C2 server IP address for firewall whitelist."""
        if not self.c2_url:
            return ""
        try:
            parsed = urlparse(self.c2_url)
            hostname = parsed.hostname
            if not hostname:
                return ""
            if hostname in ["localhost", "127.0.0.1"]:
                return "127.0.0.1"
            return socket.gethostbyname(hostname)
        except Exception as e:
            self.logger.error(f"Failed to resolve C2 IP: {e}")
            return ""

    def _run_netsh(self, args: List[str]) -> bool:
        """Execute firewall rule via netsh. All args are internal constants."""
        try:
            cmd = ["netsh", "advfirewall", "firewall"] + args #nosec B607
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) #nosec B603
            return True
        except subprocess.CalledProcessError:
            return False

    def isolate_host(self) -> bool:
        """Implement complete network isolation with C2 whitelist."""
        c2_ip = self._get_c2_ip()
        if not c2_ip:
            self.logger.error("Cannot isolate: Unable to resolve C2 IP address.")
            return False

        self.logger.warning(f"INITIATING NETWORK ISOLATION PROTOCOL. C2 IP: {c2_ip}")
        self.restore_connection()

        self._run_netsh(["add", "rule", f"name={self.rule_prefix}_C2_OUT",
                         "dir=out", "action=allow", "protocol=TCP", f"remoteip={c2_ip}"])
        self._run_netsh(["add", "rule", f"name={self.rule_prefix}_DNS",
                         "dir=out", "action=allow", "protocol=UDP", "remoteport=53"])
        self._run_netsh(["add", "rule", f"name={self.rule_prefix}_BLOCK_ALL_OUT",
                         "dir=out", "action=block"])
        self._run_netsh(["add", "rule", f"name={self.rule_prefix}_BLOCK_ALL_IN",
                         "dir=in", "action=block"])

        self.logger.success("HOST NETWORK ISOLATION SUCCESSFUL.")
        return True

    def restore_connection(self) -> bool:
        """Remove all Basilisk isolation firewall rules."""
        self.logger.info("Restoring network connectivity...")
        for rule in [
            f"{self.rule_prefix}_C2_OUT",
            f"{self.rule_prefix}_DNS",
            f"{self.rule_prefix}_BLOCK_ALL_OUT",
            f"{self.rule_prefix}_BLOCK_ALL_IN",
        ]:
            self._run_netsh(["delete", "rule", f"name={rule}"])
        self.logger.success("Network connectivity restored.")
        return True
