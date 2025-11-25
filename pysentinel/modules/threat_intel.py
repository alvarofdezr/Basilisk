# pysentinel/modules/threat_intel.py
import requests
import time
import json

class ThreatIntel:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/files/"
        self.cache = {} # Guardamos resultados para no gastar peticiones a la API

    def check_hash(self, file_hash):
        """
        Consulta el Hash en VirusTotal.
        Retorna: (malicious_count, total_engines, link)
        """
        if not self.api_key or self.api_key == "TU_API_KEY_AQUI":
            return None # No configurado

        # 1. Mirar caché local primero (Ahorro de API y tiempo)
        if file_hash in self.cache:
            return self.cache[file_hash]

        headers = {"x-apikey": self.api_key}
        
        try:
            # Hacemos la petición GET
            response = requests.get(self.base_url + file_hash, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats['malicious']
                total = sum(stats.values())
                link = data['data']['links']['self'] # Link al reporte
                
                result = {"malicious": malicious, "total": total, "scan_date": time.time()}
                self.cache[file_hash] = result
                return result
            
            elif response.status_code == 404:
                # El archivo es tan nuevo (o único) que VirusTotal no lo conoce.
                # ¡ESTO ES SOSPECHOSO EN SÍ MISMO!
                return {"malicious": 0, "total": 0, "status": "UNKNOWN_HASH"}
                
        except Exception as e:
            print(f"[THREAT INTEL ERROR] {e}")
            return None
            
        return None