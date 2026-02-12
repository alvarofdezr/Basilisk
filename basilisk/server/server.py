"""
Basilisk C2 Server v6.7.1 (Fixed & Refactored)
Enterprise-grade Command & Control Server.
Compatible con index.html v6.6
"""
import sys
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Any, List, Optional, Dict
from collections import defaultdict

# --- CONFIGURACIÓN DE ENTORNO ---
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SERVER_DIR, '..'))
if SERVER_DIR not in sys.path: sys.path.insert(0, SERVER_DIR)
if PROJECT_ROOT not in sys.path: sys.path.insert(0, PROJECT_ROOT)

import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from basilisk.core.config import Config
from basilisk.core.security import verify_password
from basilisk.utils.cert_manager import CertManager
from basilisk.server.database import init_db, get_db, Agent, IncidentLog, PendingCommand, AgentReport

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("BasiliskC2")

# --- CARGA DE CONFIGURACIÓN ---
CONFIG = Config(config_path=os.path.join(PROJECT_ROOT, 'config.yaml'))
ADMIN_USER = os.getenv("BASILISK_ADMIN_USER", "admin").strip()
SECRET_KEY = CONFIG.server_secret_key
ADMIN_HASH = CONFIG.admin_hash

if not ADMIN_HASH or not SECRET_KEY:
    logger.critical("❌ CRITICAL: Missing Admin Hash or Secret Key in Config.")
    sys.exit(1)

# --- STATE & CONSTANTS ---
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300
SESSION_LIFETIME = 8 # Hours
login_attempts: Dict[str, List[datetime]] = defaultdict(list)
last_heartbeats: Dict[str, datetime] = defaultdict(lambda: datetime.min)

# --- PYDANTIC MODELS ---
class HeartbeatSchema(BaseModel):
    agent_id: str
    hostname: str
    os: str
    status: Any 
    timestamp: float
    cpu_percent: float
    ram_percent: float

class AlertSchema(BaseModel):
    agent_id: str
    message: str
    severity: str = "INFO"
    type: str = "GENERIC"

class ReportSchema(BaseModel):
    agent_id: str
    content: Any 

class CommandSchema(BaseModel):
    target_agent_id: str
    command: Any
    
class LoginSchema(BaseModel):
    username: str
    password: str

# --- APP FACTORY ---
app = FastAPI(title="Basilisk C2", version="6.7.1", docs_url=None, redoc_url=None)

# CORS Policy
origins = [
    "https://localhost:8443", "http://localhost:8443",
    "https://127.0.0.1:8443", "http://127.0.0.1:8443"
]
if hasattr(CONFIG, 'c2_url'): origins.append(CONFIG.c2_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=True, same_site='lax')

# --- SECURITY MIDDLEWARE ---
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    
    public_routes = ["/login", "/static", "/favicon.ico", "/api/v1/auth/login"]
    agent_routes = ["/api/v1/heartbeat", "/api/v1/alert", "/api/v1/report"]
    
    if request.url.path in public_routes or any(request.url.path.startswith(p) for p in agent_routes):
        return response

    user = request.session.get("user")
    if not user:
        if request.url.path == "/" or request.url.path.endswith(".html"):
            return RedirectResponse("/login")
        return JSONResponse(status_code=403, content={"detail": "Unauthorized"})
        
    return response

# --- AUTHENTICATION ---
@app.post("/api/v1/auth/login")
async def login(data: LoginSchema, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = datetime.now()
    
    attempts = [t for t in login_attempts[client_ip] if now - t < timedelta(seconds=LOCKOUT_TIME)]
    login_attempts[client_ip] = attempts
    
    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        logger.warning(f"🔒 Lockout triggered for IP: {client_ip}")
        raise HTTPException(status_code=429, detail="Too many attempts")

    if data.username == ADMIN_USER and verify_password(ADMIN_HASH, data.password):
        login_attempts.pop(client_ip, None)
        request.session["user"] = ADMIN_USER
        request.session["expires_at"] = (now + timedelta(hours=SESSION_LIFETIME)).timestamp()
        logger.info(f"✅ Admin logged in from {client_ip}")
        return {"status": "ok", "redirect": "/"}

    login_attempts[client_ip].append(now)
    logger.warning(f"❌ Failed login attempt from {client_ip}")
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return {"status": "ok"}

# --- AGENT ENDPOINTS ---
@app.post("/api/v1/heartbeat")
async def heartbeat(data: HeartbeatSchema, db: Session = Depends(get_db)):
    aid = data.agent_id
    now = datetime.now()
    
    if (now - last_heartbeats[aid]).total_seconds() < 1.0:
        return {"status": "throttled"}
    last_heartbeats[aid] = now

    agent = db.query(Agent).filter(Agent.agent_id == aid).first()
    if not agent:
        agent = Agent(agent_id=aid)
        db.add(agent)
    
    agent.last_seen = now                     #type: ignore
    agent.hostname = data.hostname            #type: ignore
    agent.os_info = data.os                   #type: ignore
    agent.cpu_percent = data.cpu_percent      #type: ignore
    agent.ram_percent = data.ram_percent      #type: ignore
    
    cmd_str = None
    pending_cmd = db.query(PendingCommand).filter(PendingCommand.agent_id == aid)\
                    .order_by(asc(PendingCommand.issued_at)).first()
    if pending_cmd:
        cmd_str = pending_cmd.command
        db.delete(pending_cmd)
        logger.info(f"⚡ Command sent to {aid}: {cmd_str[:20]}...")
    
    db.commit()
    return {"status": "ok", "command": cmd_str}

@app.post("/api/v1/alert")
async def receive_alert(data: AlertSchema, db: Session = Depends(get_db)):
    logger.warning(f"🔥 ALERT [{data.severity}] {data.agent_id}: {data.message}")
    db.add(IncidentLog(
        agent_id=data.agent_id, 
        received_at=datetime.now(),
        type=data.type, 
        message=data.message, 
        severity=data.severity
    ))
    db.commit()
    return {"status": "received"}

@app.post("/api/v1/report/{report_type}")
async def receive_report(report_type: str, data: ReportSchema, db: Session = Depends(get_db)):
    try:
        content_json = json.dumps(data.content)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid JSON content")
        
    report = db.query(AgentReport).filter(
        AgentReport.agent_id == data.agent_id, 
        AgentReport.report_type == report_type
    ).first()
    
    if report:
        report.content = content_json         #type: ignore
        report.generated_at = datetime.now()  #type: ignore
    else:
        db.add(AgentReport(agent_id=data.agent_id, report_type=report_type, content=content_json))
        
    db.commit()
    logger.info(f"📂 Report '{report_type}' updated for {data.agent_id}")
    return {"status": "stored"}

# --- ADMIN ENDPOINTS ---
@app.get("/api/v1/dashboard")
def dashboard_stats(db: Session = Depends(get_db)):
    agents = db.query(Agent).all()
    incidents = db.query(IncidentLog).order_by(desc(IncidentLog.received_at)).limit(50).all()
    
    return {
        "agents": {
            a.agent_id: {
                "hostname": a.hostname,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                "status": "ONLINE" if a.last_seen and (datetime.now() - a.last_seen).total_seconds() < 30 else "OFFLINE",
                "os": a.os_info,
                "cpu_percent": a.cpu_percent,
                "ram_percent": a.ram_percent
            } for a in agents
        },
        "recent_incidents": [
            {
                "received_at": l.received_at.isoformat(), 
                "agent_id": l.agent_id,                   
                "severity": l.severity,
                "message": l.message,
                "type": l.type
            } for l in incidents
        ]
    }

@app.post("/api/v1/admin/command")
async def queue_command(data: CommandSchema, db: Session = Depends(get_db)):
    cmd_str = data.command if isinstance(data.command, str) else json.dumps(data.command)
    
    if len(cmd_str) > 4096:
        raise HTTPException(status_code=413, detail="Command payload too large")
        
    db.add(PendingCommand(agent_id=data.target_agent_id, command=cmd_str))
    db.commit()
    logger.info(f"⚙️ Command queued for {data.target_agent_id}")
    return {"status": "queued"}

@app.get("/api/v1/agent/{agent_id}/{report_type}")
def get_agent_report(agent_id: str, report_type: str, db: Session = Depends(get_db)):
    report = db.query(AgentReport).filter(
        AgentReport.agent_id == agent_id, 
        AgentReport.report_type == report_type
    ).first()
    return JSONResponse(content=json.loads(str(report.content)) if report and report.content else [])

# --- STATIC FILES ---
STATIC_DIR = os.path.join(SERVER_DIR, "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def root(): return FileResponse(os.path.join(STATIC_DIR, 'index.html'))
@app.get("/login")
async def login_page(): return FileResponse(os.path.join(STATIC_DIR, 'login.html'))

if __name__ == "__main__":
    print("🔒 Initializing Basilisk C2 Enterprise v6.7.1...")
    init_db()
    cert_mgr = CertManager(cert_dir="certs")
    cert, key = cert_mgr.ensure_certificates()
    uvicorn.run(app, host="0.0.0.0", port=8443, ssl_keyfile=key, ssl_certfile=cert, log_level="info")