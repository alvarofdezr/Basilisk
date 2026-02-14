"""
Network Isolation Module - Active Response Firewall Configuration

Implements emergency network containment via Windows Firewall rules.
Blocks all outbound/inbound traffic while maintaining lifeline to C2
for continued monitoring and command reception.

Isolation Rules Priority:
1. Allow TCP to C2 server (command channel)
2. Allow UDP 53 (DNS for basic resolution)
3. Block ALL outbound traffic
4. Block ALL inbound traffic
"""

import subprocess
import socket
from urllib.parse import urlparse
from typing import List
from basilisk.utils.logger import Logger


class NetworkIsolator:
    """Firewall-based network containment for infected hosts.
    
    Uses netsh (Windows Firewall CLI) to implement complete network
    isolation while preserving C2 communication channel. Rules are
    uniquely named with "Basilisk_Isolation" prefix for safe removal.
    
    DNS Access:
    Allows UDP 53 to enable basic hostname resolution (for C2 callback).
    """

    def __init__(self, c2_url: str):
        """Initialize network isolator with C2 endpoint.
        
        Parses C2 URL to determine safe IP address to whitelist during
        isolation. Stores rule naming prefix for rule enumeration.
        
        Args:
            c2_url: C2 server URL (e.g., "https://192.168.1.100:8443")
        """
        self.logger = Logger()
        self.c2_url = c2_url
        self.rule_prefix = "Basilisk_Isolation"

    def _get_c2_ip(self) -> str:
        """Resolve C2 server IP address for firewall whitelist.
        
        Parses hostname from URL and performs DNS lookup to get IP.
        Returns "127.0.0.1" for localhost references. Gracefully fails
        if DNS resolution fails.
        
        Returns:
            str: IPv4 address of C2 server or empty string if resolution fails
        """
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
        """Execute firewall rule command via netsh.
        
        Constructs "netsh advfirewall firewall" command with provided
        arguments. Silences stdout/stderr and suppresses exceptions.
        
        Args:
            args: List of netsh arguments after "advfirewall firewall" base
            
        Returns:
            bool: True if command succeeded, False otherwise
        """
        try:
            cmd = ["netsh", "advfirewall", "firewall"] + args
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    def isolate_host(self) -> bool:
        """Implement complete network isolation with C2 whitelist.
        
        Execution Order:
        1. Restore any previous isolation rules
        2. Allow outbound TCP to C2 (command reception)
        3. Allow outbound UDP 53 (DNS resolution)
        4. Block all other outbound traffic
        5. Block all inbound traffic
        
        Returns:
            bool: True if isolation successful, False if C2 IP unresolvable
        """
        c2_ip = self._get_c2_ip()

        if not c2_ip:
            self.logger.error("Cannot isolate: Unable to resolve C2 IP address.")
            return False

        self.logger.warning(f"INITIATING NETWORK ISOLATION PROTOCOL. C2 IP: {c2_ip}")

        self.restore_connection()

        self._run_netsh([
            "add", "rule", f"name={self.rule_prefix}_C2_OUT",
            "dir=out", "action=allow", "protocol=TCP",
            f"remoteip={c2_ip}"
        ])

        self._run_netsh([
            "add", "rule", f"name={self.rule_prefix}_DNS",
            "dir=out", "action=allow", "protocol=UDP", "remoteport=53"
        ])

        self._run_netsh([
            "add", "rule", f"name={self.rule_prefix}_BLOCK_ALL_OUT",
            "dir=out", "action=block"
        ])
        self._run_netsh([
            "add", "rule", f"name={self.rule_prefix}_BLOCK_ALL_IN",
            "dir=in", "action=block"
        ])

        self.logger.success("HOST NETWORK ISOLATION SUCCESSFUL.")
        return True

    def restore_connection(self) -> bool:
        """Remove all Basilisk isolation firewall rules.
        
        Deletes all rules prefixed with "Basilisk_Isolation" to restore
        normal network connectivity. Called before new isolation or during
        remediation.
        
        Returns:
            bool: True if restoration commands executed
        """
        self.logger.info("Restoring network connectivity...")

        rules = [
            f"{self.rule_prefix}_C2_OUT",
            f"{self.rule_prefix}_DNS",
            f"{self.rule_prefix}_BLOCK_ALL_OUT",
            f"{self.rule_prefix}_BLOCK_ALL_IN"
        ]

        for rule in rules:
            self._run_netsh(["delete", "rule", f"name={rule}"])

        self.logger.success("Network connectivity restored.")
        return True
