"""
YARA Malware Scanner - Signature-Based Threat Detection

Compiles and executes YARA rules against files on disk to identify
known malware signatures, backdoors, and suspicious code patterns.
Monitors compliance with 100MB file size limits to prevent resource
exhaustion from processing archive files or disk images.
"""
import yara
import os
from typing import List, Dict, Any
from basilisk.utils.logger import Logger

MAX_SCAN_SIZE = 100 * 1024 * 1024


class YaraScanner:
    """YARA signature engine for filesystem malware scanning.
    
    Loads and compiles YARA rules from index.yar. Provides file scanning
    with results mapping rule name to metadata (severity, description).
    
    Features:
    - Lazy rule compilation with error handling
    - 10-second match timeout per file (prevents hangs on large files)
    - File size filtering (skips files >100MB)
    - Metadata extraction (severity, description) from rule headers
    """

    def __init__(self, rules_path="basilisk/rules/index.yar"):
        """Initialize YARA scanner and compile rules from file.
        
        Attempts to load and compile rules at startup. Logs success/failure
        with rule count. If rules fail to load, scanner returns empty results
        gracefully without crashing agent.
        
        Args:
            rules_path: Path to YARA rules file (.yar or .yara format)
        """
        self.logger = Logger()
        self.rules = None
        self.rules_path = os.path.abspath(rules_path)
        self._compile_rules()

    def _compile_rules(self) -> None:
        """Compile YARA rules from disk into memory.
        
        Validates file existence and catches YARA syntax errors gracefully.
        Logs rule count on success or error details on failure.
        """
        try:
            if os.path.exists(self.rules_path):
                self.rules = yara.compile(filepath=self.rules_path)
                num_rules = sum(1 for _ in self.rules)
                self.logger.success(f"Basilisk Engine Loaded: {num_rules} active signatures.")
            else:
                self.logger.error(f"Signatures not found at: {self.rules_path}")
        except yara.Error as e:
            self.logger.error(f"Error compiling rules: {e}")

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Scan single file against compiled YARA rules.
        
        Checks file existence, applies size filter, and executes match
        with 10-second timeout. Extracts match metadata (rule name,
        severity, description) for reporting.
        
        Args:
            filepath: Absolute path to file to scan
            
        Returns:
            List[Dict]: Array of matches, each containing:
                - rule: YARA rule name that matched
                - severity: Rule severity level from metadata (WARNING, CRITICAL)
                - description: Human-readable threat description
                - file: Path to matched file
                Returns empty list if rules not compiled, file missing,
                or size exceeds 100MB limit.
        """
        if not self.rules:
            return []

        if not os.path.exists(filepath):
            return []

        try:
            size = os.path.getsize(filepath)
            if size > MAX_SCAN_SIZE:
                self.logger.warning(f"File skipped (size limit {size/1024/1024:.2f} MB): {filepath}")
                return []

            if size == 0:
                return []

        except Exception as e:
            self.logger.error(f"Error accessing file: {e}")
            return []

        matches = []
        try:
            yara_matches = self.rules.match(filepath, timeout=10)

            for match in yara_matches:
                threat_info = {
                    "rule": match.rule,
                    "severity": match.meta.get('severity', 'WARNING'),
                    "description": match.meta.get('description', 'Unknown Threat'),
                    "file": filepath
                }
                matches.append(threat_info)
                self.logger.error(f"Threat confirmed [{match.rule}] in {os.path.basename(filepath)}")

        except Exception as e:
            self.logger.error(f"Scanner engine error: {e}")

        return matches
