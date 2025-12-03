# server_persistence.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///c2_server.db" 

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELOS DE DATOS ---

class Agent(Base):
    __tablename__ = "agents"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, unique=True, index=True)
    hostname = Column(String)
    os_info = Column(String)
    last_seen = Column(DateTime, default=datetime.utcnow)
    cpu_percent = Column(Float, default=0.0)
    ram_percent = Column(Float, default=0.0)

class IncidentLog(Base):
    __tablename__ = "incident_logs"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String)
    received_at = Column(DateTime, default=datetime.utcnow)
    type = Column(String) 
    message = Column(String)
    severity = Column(String)

class PendingCommand(Base):
    __tablename__ = "pending_commands"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    command = Column(String)
    issued_at = Column(DateTime, default=datetime.utcnow)

class AgentReport(Base):
    """[NUEVO] Persistencia de reportes (Procesos/Puertos) para evitar 404."""
    __tablename__ = "agent_reports"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    report_type = Column(String) # "processes", "ports"
    content = Column(Text)       # JSON crudo
    generated_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()