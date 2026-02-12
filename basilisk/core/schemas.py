"""
Basilisk Data Contracts
Defines the strict structure of telemetry data shared across modules.
"""
from typing import Optional
from pydantic import BaseModel

class ProcessModel(BaseModel):
    pid: int
    name: str
    username: Optional[str] = "SYSTEM"
    exe: Optional[str] = None
    cmdline: Optional[str] = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    risk_score: int = 0
    risk_level: str = "INFO"  # INFO, WARNING, CRITICAL

class NetworkConnModel(BaseModel):
    """Snapshot de una conexión activa para el mapa de red."""
    src: str
    dst: str
    process: str
    pid: int
    status: str = "ESTABLISHED"

class PortRiskModel(BaseModel):
    """Análisis de riesgo de un puerto abierto."""
    port: int
    ip_bind: str
    proto: str
    service: str
    process: str
    pid: int
    risk: str  # CRITICAL, HIGH, WARNING, INFO
    explanation: Optional[str] = None

class FirewallModel(BaseModel):
    Domain: str
    Standard: str
    Public: str
    Overall: str

class AuditModel(BaseModel):
    """Informe de cumplimiento del sistema."""
    firewall: FirewallModel
    uac: str
    defender: str
    last_update: str
    scan_time: str