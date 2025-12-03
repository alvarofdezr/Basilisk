# basilisk/modules/yara_scanner.py
"""
Basilisk EDR - Detection Engine (YARA)
v6.5 Stable
"""
import yara
import os
from typing import List, Dict, Any
from basilisk.utils.logger import Logger

# [SEGURIDAD] Límite de escaneo para evitar DoS por consumo de RAM
# 100 MB Límite duro
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
                # DEBUG: Conteo de reglas
                num_rules = sum(1 for _ in self.rules)
                self.logger.success(f"👁️ Basilisk Engine Loaded: {num_rules} firmas activas.")
            else:
                self.logger.error(f"❌ Firmas no encontradas en: {self.rules_path}")
        except yara.Error as e:
            self.logger.error(f"❌ Error compilando reglas: {e}")

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        if not self.rules:
            return []

        if not os.path.exists(filepath):
            return []

        # [FIX C5] Validación de tamaño antes de leer el archivo
        try:
            size = os.path.getsize(filepath)
            if size > MAX_SCAN_SIZE:
                self.logger.warning(f"⚠️ Archivo omitido por tamaño excesivo ({size/1024/1024:.2f} MB): {filepath}")
                return []
                
            if size == 0:
                return [] # Archivos vacíos o bloqueados
                
        except Exception as e:
            self.logger.error(f"Error accediendo archivo: {e}")
            return []

        matches = []
        try:
            # Timeout de 10s para evitar congelamientos
            yara_matches = self.rules.match(filepath, timeout=10)
            
            for match in yara_matches:
                threat_info = {
                    "rule": match.rule,
                    "severity": match.meta.get('severity', 'WARNING'),
                    "description": match.meta.get('description', 'Unknown Threat'),
                    "file": filepath
                }
                matches.append(threat_info)
                self.logger.error(f"🐍 BASILISK GAZE: Amenaza confirmada [{match.rule}] en {os.path.basename(filepath)}")
                
        except Exception as e:
            self.logger.error(f"Error en motor de escaneo: {e}")

        return matches