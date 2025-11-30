# server_persistence.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Usamos un archivo SQLite para que los datos persistan
DATABASE_URL = "sqlite:///c2_server.db" 

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELOS DE DATOS ---

class Agent(Base):
    """Tabla para almacenar el estado y las métricas de los agentes."""
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, unique=True, index=True)
    hostname = Column(String)
    os_info = Column(String)
    last_seen = Column(DateTime, default=datetime.utcnow)
    cpu_percent = Column(Float, default=0.0)
    ram_percent = Column(Float, default=0.0)

class IncidentLog(Base):
    """Tabla para almacenar logs de seguridad."""
    __tablename__ = "incident_logs"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String)
    received_at = Column(DateTime, default=datetime.utcnow)
    type = Column(String) 
    message = Column(String)
    severity = Column(String)

class PendingCommand(Base):
    """[NUEVO v6.4] Cola de comandos persistente."""
    __tablename__ = "pending_commands"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    command = Column(String)
    issued_at = Column(DateTime, default=datetime.utcnow)
    # Si quisieras historial, podrías usar un flag 'executed', 
    # pero para una cola simple, borraremos el registro al enviarlo.

# --- FUNCIONES DE UTILIDAD ---

def init_db():
    """Crea las tablas si no existen."""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Dependencia para FastAPI."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()