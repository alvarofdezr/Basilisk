import yara
import os
from typing import List, Dict, Any
from basilisk.utils.logger import Logger

MAX_SCAN_SIZE = 100 * 1024 * 1024


class YaraScanner:
    def __init__(self, rules_path="basilisk/rules/index.yar"):
        self.logger = Logger()
        self.rules = None
        self.rules_path = os.path.abspath(rules_path)
        self._compile_rules()

    def _compile_rules(self):
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
