"""
Threat Intelligence Module - External File Reputation Lookup

Queries VirusTotal API for file hash reputation analysis.
Provides local caching to reduce API quota consumption for repeated lookups.
"""

import requests
import time
from typing import Optional, Dict


class ThreatIntel:
    """
    VirusTotal API v3 integration with reputation caching.
    
    Queries file hashes against VirusTotal's malware detection engine.
    Caches results locally to minimize API quota usage and improve response time
    for repeated lookups against the same file hashes.
    """

    def __init__(self, api_key: str):
        """
        Initialize threat intelligence client.
        
        Args:
            api_key: VirusTotal API v3 key for authentication
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/files/"
        self.cache: Dict[str, Dict] = {}

    def check_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Query file hash against VirusTotal malware database.
        
        Implements local caching to reduce API calls. Returns detection
        statistics including count of malicious detections and total
        antivirus engines that analyzed the file.
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash of target file
            
        Returns:
            Dict with keys:
            - malicious: Count of AV engines detecting as malicious
            - total: Total AV engines in scan
            - scan_date: Timestamp of last analysis
            - status: "UNKNOWN_HASH" if not in VirusTotal
            Or None if API error
        """
        if not self.api_key:
            return None

        if file_hash in self.cache:
            return self.cache[file_hash]

        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(f"{self.base_url}{file_hash}", headers=headers, timeout=5)

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

                result = {
                    "malicious": stats.get('malicious', 0),
                    "total": sum(stats.values()),
                    "scan_date": time.time()
                }
                self.cache[file_hash] = result
                return result

            elif response.status_code == 404:
                return {"malicious": 0, "total": 0, "status": "UNKNOWN_HASH"}

        except Exception:
            pass

        return None
