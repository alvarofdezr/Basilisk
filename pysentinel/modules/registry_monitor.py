# pysentinel/modules/registry_monitor.py
import winreg
import logging
from pysentinel.core.database import DatabaseManager

class RegistryMonitor:
    def __init__(self, db_manager: DatabaseManager, notifier):
        self.db = db_manager
        self.notifier = notifier
        
        # Claves críticas donde el malware suele buscar persistencia
        # Tupla: (HIVE_ROOT, Ruta_Clave)
        self.monitored_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            # Opcional: Clave de inicio de Winlogon (Avanzado)
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") 
        ]
        
        # "Foto" inicial del registro para comparar cambios
        self.baseline = self._scan_all_keys()
        print(f"[*] RegistryMonitor: Vigilando {len(self.baseline)} puntos de persistencia.")

    def _get_values_from_key(self, hive, subkey):
        """Lee todos los valores de una clave de registro específica"""
        values = {}
        try:
            # Abrimos la clave en modo lectura
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key_handle:
                # Iteramos sobre los valores
                i = 0
                while True:
                    try:
                        # name: nombre del valor (ej: "OneDrive")
                        # data: contenido (ej: "C:\Users\...\OneDrive.exe")
                        # type: tipo de dato
                        name, data, _ = winreg.EnumValue(key_handle, i)
                        
                        # Creamos una firma única: RUTA_CLAVE + NOMBRE
                        # Usamos str() para asegurar compatibilidad
                        full_id = f"{subkey}\\{name}"
                        values[full_id] = str(data)
                        i += 1
                    except OSError:
                        break # Fin de la lista
        except PermissionError:
            # print(f"[REG] Permiso denegado para: {subkey}") # Ruido innecesario
            pass
        except FileNotFoundError:
            pass
            
        return values

    def _scan_all_keys(self):
        """Recorre todas las claves configuradas y devuelve un diccionario maestro"""
        snapshot = {}
        for hive, subkey in self.monitored_keys:
            data = self._get_values_from_key(hive, subkey)
            snapshot.update(data)
        return snapshot

    def check_registry_changes(self):
        """Compara la foto actual con la anterior"""
        current_snapshot = self._scan_all_keys()
        
        # Detectar NUEVAS entradas (Persistencia de Malware)
        # Lógica: Claves que están en 'current' pero NO en 'baseline'
        new_entries = set(current_snapshot.keys()) - set(self.baseline.keys())
        
        # Detectar entradas MODIFICADAS (Malware secuestrando programa legítimo)
        # Lógica: Misma clave, diferente comando
        for key in current_snapshot:
            if key in self.baseline:
                if current_snapshot[key] != self.baseline[key]:
                    msg = f"PERSISTENCIA MODIFICADA: {key}\nAntes: {self.baseline[key]}\nAhora: {current_snapshot[key]}"
                    self._trigger_alert(msg, "WARNING")

        # Procesar nuevas
        for key in new_entries:
            cmd = current_snapshot[key]
            msg = f"NUEVA PERSISTENCIA DETECTADA (Auto-Arranque):\nClave: {key}\nComando: {cmd}"
            self._trigger_alert(msg, "CRITICAL")

        # Actualizar baseline si hubo cambios (para no alertar en bucle)
        if new_entries or (current_snapshot != self.baseline):
            self.baseline = current_snapshot

    def _trigger_alert(self, msg, severity):
        print(f"[REGISTRY] ⚠️ {msg.replace(chr(10), ' ')}") # chr(10) es salto de línea
        self.db.log_event("REG_CHANGE", msg, severity)
        if self.notifier:
            self.notifier.send_alert(f"🛡️ PySentinel Registro: {msg}")