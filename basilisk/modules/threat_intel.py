"""
Threat Intelligence Module — VirusTotal hash reputation lookup.

Changes vs original:
  - Cache entries now have a TTL (default 1 hour).
  - Cache has a max size (default 1000 entries) with LRU-style eviction
    so it cannot grow unbounded during long-running scans.
"""

import time
import requests
from typing import Optional, Dict, Any
from collections import OrderedDict


_DEFAULT_TTL = 3600       # seconds — results older than this are re-queried
_DEFAULT_MAX_SIZE = 1000  # max cached hashes before LRU eviction


class _CacheEntry:
    __slots__ = ("result", "expires_at")

    def __init__(self, result: Dict[str, Any], ttl: int):
        self.result = result
        self.expires_at = time.time() + ttl


class ThreatIntel:
    """
    VirusTotal API v3 integration with TTL-bounded LRU cache.

    The original implementation stored results in a plain dict with no
    expiry or size limit. A large directory scan could fill RAM over time.
    This version evicts entries older than `cache_ttl` seconds and caps
    the cache at `max_cache_size` entries.
    """

    def __init__(
        self,
        api_key: str,
        cache_ttl: int = _DEFAULT_TTL,
        max_cache_size: int = _DEFAULT_MAX_SIZE,
    ):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/files/"
        self._cache: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._cache_ttl = cache_ttl
        self._max_cache_size = max_cache_size

    # ── Cache helpers ─────────────────────────────────────────────────────────

    def _get_cached(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Return cached result if present and not expired, else None."""
        entry = self._cache.get(file_hash)
        if entry is None:
            return None
        if time.time() > entry.expires_at:
            del self._cache[file_hash]
            return None
        # Move to end (LRU touch)
        self._cache.move_to_end(file_hash)
        return entry.result

    def _set_cached(self, file_hash: str, result: Dict[str, Any]) -> None:
        """Insert result into cache, evicting oldest entry if at capacity."""
        if file_hash in self._cache:
            self._cache.move_to_end(file_hash)
        self._cache[file_hash] = _CacheEntry(result, self._cache_ttl)
        if len(self._cache) > self._max_cache_size:
            # Evict least-recently-used entry
            self._cache.popitem(last=False)

    # ── Public API ────────────────────────────────────────────────────────────

    def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Query file hash against VirusTotal malware database.

        Returns cached result if fresh (< TTL seconds old).
        Evicts stale entries automatically.

        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash of target file.

        Returns:
            Dict with keys:
                - malicious: count of AV engines detecting as malicious
                - total: total AV engines in scan
                - scan_date: epoch timestamp of last VT analysis
                - status: "UNKNOWN_HASH" if not in VirusTotal
            None on API error or missing API key.
        """
        if not self.api_key:
            return None

        cached = self._get_cached(file_hash)
        if cached is not None:
            return cached

        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(
                f"{self.base_url}{file_hash}",
                headers=headers,
                timeout=5,
            )

            if response.status_code == 200:
                data = response.json()
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                result: Dict[str, Any] = {
                    "malicious": stats.get("malicious", 0),
                    "total": sum(stats.values()),
                    "scan_date": time.time(),
                }
                self._set_cached(file_hash, result)
                return result

            if response.status_code == 404:
                not_found: Dict[str, Any] = {
                    "malicious": 0,
                    "total": 0,
                    "status": "UNKNOWN_HASH",
                }
                self._set_cached(file_hash, not_found)
                return not_found

        except Exception: #nosec B110
            pass

        return None

    @property
    def cache_size(self) -> int:
        """Current number of entries in the cache (for monitoring/tests)."""
        return len(self._cache)
