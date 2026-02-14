"""
Basilisk Database Layer
SQLAlchemy ORM models and session management for SQLite persistence.
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
from typing import Any, Generator
import os

Base: Any = declarative_base()
DB_PATH = os.path.join(os.getcwd(), "basilisk.db")
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Agent(Base):
    """Endpoint agent registration and health metrics."""
    __tablename__ = "agents"
    
    agent_id = Column(String, primary_key=True, index=True)
    hostname = Column(String)
    os_info = Column(String)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="OFFLINE")
    cpu_percent = Column(Float, default=0.0)
    ram_percent = Column(Float, default=0.0)


class IncidentLog(Base):
    """Security alerts and threat detections."""
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    type = Column(String)
    severity = Column(String)
    message = Column(Text)
    received_at = Column(DateTime, default=datetime.utcnow)


class AgentReport(Base):
    """Structured telemetry reports (processes, ports, audit)."""
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    report_type = Column(String)
    content = Column(Text)
    generated_at = Column(DateTime, default=datetime.utcnow)


class PendingCommand(Base):
    """Command queue for remote execution."""
    __tablename__ = "commands"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    command = Column(String)
    executed = Column(Boolean, default=False)
    issued_at = Column(DateTime, default=datetime.utcnow)


def init_db() -> None:
    """Initialize database schema and create all tables."""
    print(f"🗄️  Database initialized at: {DB_PATH}")
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator:
    """FastAPI dependency for database session injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()