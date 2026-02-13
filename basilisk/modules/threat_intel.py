# basilisk/modules/threat_intel.py
import requests
import time
from typing import Optional, Dict


class ThreatIntel:
    """
    Interface for VirusTotal API v3.
    Includes local caching to minimize API quota usage.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/files/"
        self.cache: Dict[str, Dict] = {}

    def check_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Queries VirusTotal for file reputation.
        Returns: Dict with malicious count and total engines.
        """
        if not self.api_key:
            return None

        # Check Cache
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
                # Hash not found (Potential Zero-day or unique file)
                return {"malicious": 0, "total": 0, "status": "UNKNOWN_HASH"}

        except Exception:
            pass

        return None
