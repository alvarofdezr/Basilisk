# pysentinel/modules/yara_scanner.py
import yara
import os
from typing import List, Dict, Any
from pysentinel.utils.logger import Logger

class YaraScanner:
    """
    Motor de detección de malware basado en reglas YARA.
    Analiza archivos en busca de patrones de bytes maliciosos.
    """
    def __init__(self, rules_path="pysentinel/rules/index.yar"):
        self.logger = Logger()
        self.rules = None
        self.rules_path = os.path.abspath(rules_path)
        
        self._compile_rules()

    def _compile_rules(self):
        """Compila las reglas YARA al iniciar."""
        try:
            if os.path.exists(self.rules_path):
                self.rules = yara.compile(filepath=self.rules_path)
                self.logger.success(f"YARA Rules loaded from: {self.rules_path}")
            else:
                self.logger.error(f"YARA rules file not found: {self.rules_path}")
        except yara.Error as e:
            self.logger.error(f"YARA Compilation Error: {e}")

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Escanea un archivo específico contra las reglas cargadas.
        Retorna una lista de diccionarios con las amenazas encontradas.
        """
        if not self.rules:
            return []

        if not os.path.exists(filepath):
            return []

        matches = []
        try:
            # Escaneo con timeout para no congelar el agente con archivos gigantes
            yara_matches = self.rules.match(filepath, timeout=10)
            
            for match in yara_matches:
                threat_info = {
                    "rule": match.rule,
                    "severity": match.meta.get('severity', 'WARNING'),
                    "description": match.meta.get('description', 'Unknown Threat'),
                    "file": filepath
                }
                matches.append(threat_info)
                self.logger.warning(f"🛡️ YARA MATCH: {match.rule} in {os.path.basename(filepath)}")
                
        except Exception as e:
            self.logger.error(f"Error scanning file {filepath}: {e}")

        return matches