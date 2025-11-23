# pysentinel/modules/port_monitor.py
import psutil
import socket
import time
from pysentinel.core.database import DatabaseManager

class PortMonitor:
    def __init__(self, db_manager: DatabaseManager, notifier):
        self.db = db_manager
        self.notifier = notifier
        self.previous_ports = set()
        
        # Inicializamos la línea base silenciosamente
        self._initialize_baseline()

    def _initialize_baseline(self):
        """Toma la foto inicial sin alertar"""
        self.previous_ports = self._get_current_ports()
        print(f"[*] PortMonitor: Línea base establecida con {len(self.previous_ports)} puertos abiertos.")

    def _get_current_ports(self):
        """Devuelve un set de tuplas (puerto, tipo_protocolo) para comparación rápida"""
        open_ports = set()
        try:
            # net_connections('inet') trae TCP y UDP
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' or conn.type == socket.SOCK_DGRAM:
                    port = conn.laddr.port
                    # Determinamos protocolo
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    open_ports.add((port, proto))
        except Exception:
            pass
        return open_ports

    def get_service_name(self, port, proto):
        """Traduce puerto 80 -> 'http', 443 -> 'https', etc."""
        try:
            return socket.getservbyport(port, proto.lower())
        except:
            return "Desconocido"

    def get_full_report(self):
        """
        Genera un reporte DETALLADO de todos los puertos.
        Devuelve una lista de diccionarios para la GUI (Auditoría).
        """
        report = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                # Filtramos solo lo que está escuchando (Listening) o UDP
                if conn.status == 'LISTEN' or conn.type == socket.SOCK_DGRAM:
                    port = conn.laddr.port
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    pid = conn.pid
                    
                    # 1. Obtener nombre del proceso
                    process_name = "System/Restricted"
                    try:
                        if pid:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied): 
                        pass

                    # 2. Obtener nombre del servicio estándar
                    service_name = self.get_service_name(port, proto)

                    # Añadimos al reporte
                    report.append({
                        "port": port,
                        "proto": proto,
                        "service": service_name,
                        "process": process_name,
                        "pid": pid if pid else "?"
                    })
            
            # Ordenamos por número de puerto para que se vea bonito
            report.sort(key=lambda x: x['port'])
            
        except Exception as e:
            print(f"[ERROR PORTS] {e}")
            
        return report

    def scan_ports(self):
        """Bucle de vigilancia (Solo avisa cambios, no reporta todo)"""
        current_ports = self._get_current_ports()
        
        # Detectar NUEVOS
        new_ports = current_ports - self.previous_ports
        for port, proto in new_ports:
            # Intentamos identificar quién lo abrió
            proc_name = "Desconocido"
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr.port == port:
                        if conn.pid: proc_name = psutil.Process(conn.pid).name()
                        break
            except: pass
            
            msg = f"NUEVO PUERTO ABIERTO: {port} ({proto}) - Proc: {proc_name}"
            print(f"[PORT] ⚠️ {msg}")
            
            self.db.log_event("PORT_OPEN", msg, "WARNING")
            if self.notifier:
                self.notifier.send_alert(f"⚠️ {msg}")

        # Detectar CERRADOS
        closed_ports = self.previous_ports - current_ports
        for port, proto in closed_ports:
            msg = f"Puerto cerrado: {port} ({proto})"
            print(f"[PORT] ℹ️ {msg}")
            self.db.log_event("PORT_CLOSE", msg, "INFO")

        self.previous_ports = current_ports