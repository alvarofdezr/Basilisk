"""
Basilisk Database Layer
Handles all SQLite interactions using SQLAlchemy ORM.
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from datetime import datetime
from typing import Any
import os

# Base y Engine
Base: Any = declarative_base()
DB_PATH = os.path.join(os.getcwd(), "basilisk.db") 
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# --- MODELOS ORM ---
class Agent(Base):
    __tablename__ = "agents"
    agent_id = Column(String, primary_key=True, index=True)
    hostname = Column(String)
    os_info = Column(String)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="OFFLINE")
    cpu_percent = Column(Float, default=0.0)
    ram_percent = Column(Float, default=0.0)

class IncidentLog(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    type = Column(String)
    severity = Column(String)
    message = Column(Text)
    received_at = Column(DateTime, default=datetime.utcnow)

class AgentReport(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    report_type = Column(String) # 'processes', 'network', 'audit'
    content = Column(Text)       # JSON string content
    generated_at = Column(DateTime, default=datetime.utcnow)

class PendingCommand(Base):
    __tablename__ = "commands"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    command = Column(String)
    executed = Column(Boolean, default=False)
    issued_at = Column(DateTime, default=datetime.utcnow)

# --- FUNCIONES HELPER ---
def init_db():
    print(f"🗄️  Database initialized at: {DB_PATH}")
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()