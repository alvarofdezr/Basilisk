# PySentinel_Server/server_persistence.py

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float
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


# --- MODELOS DE DATOS (Tablas) ---

class Agent(Base):
    """Tabla para almacenar el estado y las métricas de los agentes."""
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, unique=True, index=True)
    hostname = Column(String)
    os_info = Column(String)
    # Nuevas métricas asumidas en el Heartbeat
    last_seen = Column(DateTime, default=datetime.utcnow)
    cpu_percent = Column(Float, default=0.0)
    ram_percent = Column(Float, default=0.0)

class IncidentLog(Base):
    """Tabla para almacenar todos los logs de incidentes."""
    __tablename__ = "incident_logs"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String)
    received_at = Column(DateTime, default=datetime.utcnow)
    type = Column(String) # USB, FILE_MOD, NET_ALERT, etc.
    message = Column(String)
    severity = Column(String)

# --- FUNCIONES DE UTILIDAD ---

def init_db():
    """Crea las tablas si no existen."""
    Base.metadata.create_all(bind=engine)

# Dependencia para las rutas de FastAPI
def get_db():
    """Obtiene y cierra la sesión de BBDD al finalizar la ruta."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()