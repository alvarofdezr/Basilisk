import psutil
import time
from pysentinel.utils.logger import Logger

class PortMonitor:
    def __init__(self, db_manager, notifier=None):
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        
        # Escaneamos los puertos abiertos al iniciar para tener una "Línea Base"
        # No alertaremos de lo que ya estaba abierto al arrancar el programa.
        self.known_ports = self._get_listening_ports()
        print(f"[*] PortMonitor: Línea base establecida con {len(self.known_ports)} puertos abiertos.")

    def _get_listening_ports(self):
        """Devuelve un conjunto (Set) de puertos 'LISTEN' y sus procesos"""
        current_ports = set()
        try:
            # kind='inet' -> Solo IPv4 (para simplificar)
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'LISTEN':
                    # Guardamos una firma única: "PUERTO-PROTOCOLO"
                    # Para identificarlo luego.
                    port = conn.laddr.port
                    pid = conn.pid
                    
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name().lower()
                    except:
                        proc_name = "unknown"

                    # Guardamos una tupla (puerto, nombre_proceso)
                    current_ports.add((port, proc_name))
        except Exception as e:
            print(f"[ERROR PORT MON] {e}")
        
        return current_ports

    def scan_ports(self):
        """Busca puertos NUEVOS que no estaban antes"""
        current_ports = self._get_listening_ports()
        
        # Lógica de Conjuntos: Lo que hay AHORA menos lo que había ANTES
        new_ports = current_ports - self.known_ports
        
        # Detectar puertos CERRADOS (opcional, pero útil)
        closed_ports = self.known_ports - current_ports

        # ALERTA POR PUERTOS NUEVOS (CRÍTICO)
        for port, proc_name in new_ports:
            msg = f"🚪 ALERTA PUERTO: Se ha abierto una nueva puerta trasera.\nPuerto: {port}\nProceso: {proc_name}"
            print(f"[PORT] {msg}")
            
            self.db.log_event("PORT_OPEN", msg, "CRITICAL")
            if self.notifier:
                self.notifier.send_alert(msg)

        # Si se cierran puertos, solo actualizamos la lista, no hace falta alertar tanto
        if new_ports or closed_ports:
            self.known_ports = current_ports