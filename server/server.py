# server/server.py
"""
PySentinel EDR - Command & Control (C2) Server
Versión: 6.4 (Stable Enterprise Architecture)

CHANGELOG v6.4 Final:
- [FIX #8] Persistencia de Comandos: COMMAND_QUEUE migrado a SQL.
- [FIX #7] Heartbeat Throttling (Mantenido).
- [FIX #5] HTTPS/TLS (Mantenido).
"""

import sys
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List
from collections import defaultdict

# --- CONFIGURACIÓN DE ENTORNO ---
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SERVER_DIR, '..'))

if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# --- IMPORTS ---
import uvicorn  
from fastapi import FastAPI, Request, Depends, status, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from pysentinel.core.config import Config
from server_persistence import init_db, get_db, Agent, IncidentLog, PendingCommand

# --- CARGA DE CONFIGURACIÓN ---
try:
    CONFIG = Config(config_path=os.path.join(PROJECT_ROOT, 'config.yaml'))
    
    ADMIN_HASH = getattr(CONFIG, 'admin_hash', None) or hashlib.sha512("admin123".encode()).hexdigest()
    ADMIN_USER = getattr(CONFIG, 'admin_user', "admin")
    SECRET_KEY = getattr(CONFIG, 'secret_key', "SUPER_SECRET_SESSION_KEY_DEFAULT")
    MAX_LOGIN_ATTEMPTS = getattr(CONFIG, 'max_login_attempts', 5)
    LOCKOUT_TIME = getattr(CONFIG, 'lockout_time', 300)
    SESSION_LIFETIME_HOURS = getattr(CONFIG, 'session_lifetime', 8)

except Exception as e:
    print(f"[ERROR] Config fallback: {e}")
    ADMIN_HASH = hashlib.sha512("admin123".encode()).hexdigest()
    ADMIN_USER = "admin"
    SECRET_KEY = "EMERGENCY_KEY"
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME = 300
    SESSION_LIFETIME_HOURS = 8

# --- ESTRUCTURAS EN MEMORIA ---
login_attempts: Dict[str, List[datetime]] = defaultdict(list)
# COMMAND_QUEUE removido: ahora usamos BBDD
TEMPORARY_REPORTS: Dict[str, Dict[str, Any]] = {}

# Throttling
MIN_HEARTBEAT_INTERVAL = 1.0 
last_heartbeats: Dict[str, datetime] = defaultdict(lambda: datetime.min)

STATIC_FILES_DIR = os.path.join(SERVER_DIR, "static")

# --- APP ---
app = FastAPI(title="PySentinel C2", version="6.4 Persistent")

@app.on_event("startup")
def on_startup():
    init_db()
    print(f"✨ [SYSTEM] C2 Server Online (HTTPS + SQL Persistence). User: {ADMIN_USER}")

# --- MIDDLEWARE ---
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    public_routes = [
        "/login", "/api/v1/auth/login", "/static", "/favicon.ico",
        "/api/v1/heartbeat", "/api/v1/alert", "/api/v1/report"
    ]
    path = request.url.path
    
    if any(path.startswith(r) for r in public_routes):
        return await call_next(request)

    user = request.session.get("user")
    expires_at = request.session.get("expires_at")
    
    if not user: return _handle_unauthorized(path)
    if expires_at and datetime.utcnow().timestamp() > expires_at:
        request.session.clear()
        return _handle_unauthorized(path)
    
    return await call_next(request)

def _handle_unauthorized(path: str):
    if path == "/" or path == "/index.html": return RedirectResponse(url="/login")
    return JSONResponse(status_code=403, content={"error": "Unauthorized"})

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=True, same_site='lax')
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --- AUTH ---
@app.get("/login")
async def login_page(): return FileResponse(os.path.join(STATIC_FILES_DIR, 'login.html'))

@app.post("/api/v1/auth/login")
async def login(request: Request):
    client_ip = request.client.host
    now = datetime.utcnow()
    login_attempts[client_ip] = [t for t in login_attempts[client_ip] if now - t < timedelta(seconds=LOCKOUT_TIME)]

    if len(login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        return JSONResponse(status_code=429, content={"status": "error", "message": "Locked out."})

    data = await request.json()
    if data.get("username") != ADMIN_USER:
        login_attempts[client_ip].append(now)
        return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid"})

    input_hash = hashlib.sha512(data.get("password", "").encode()).hexdigest()
    if input_hash == ADMIN_HASH:
        if client_ip in login_attempts: del login_attempts[client_ip]
        request.session["user"] = ADMIN_USER
        request.session["expires_at"] = (now + timedelta(hours=SESSION_LIFETIME_HOURS)).timestamp()
        return {"status": "ok", "redirect": "/"}
    
    login_attempts[client_ip].append(now)
    return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid"})

@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return {"status": "ok"}

# --- AGENT CORE ---

class HeartbeatData(BaseModel):
    agent_id: str
    hostname: str
    os: str
    status: Any 
    timestamp: float
    cpu_percent: float
    ram_percent: float

@app.post("/api/v1/heartbeat")
async def hb(data: HeartbeatData, db: Session = Depends(get_db)):
    aid = data.agent_id
    now = datetime.utcnow()

    # Throttling
    if (now - last_heartbeats[aid]).total_seconds() < MIN_HEARTBEAT_INTERVAL:
        return JSONResponse(status_code=429, content={"error": "Throttling active"})
    last_heartbeats[aid] = now

    # Update Agent Info
    agent = db.query(Agent).filter(Agent.agent_id == aid).first()
    if agent:
        agent.last_seen = now
        agent.hostname = data.hostname
        agent.os_info = data.os
        agent.cpu_percent = data.cpu_percent
        agent.ram_percent = data.ram_percent
    else:
        db.add(Agent(agent_id=aid, hostname=data.hostname, os_info=data.os,
                     cpu_percent=data.cpu_percent, ram_percent=data.ram_percent))
    
    # [FIX #8] Fetch pending commands from DB (FIFO)
    cmd_str = None
    pending_cmd = db.query(PendingCommand).filter(PendingCommand.agent_id == aid)\
                    .order_by(asc(PendingCommand.issued_at)).first()
    
    if pending_cmd:
        cmd_str = pending_cmd.command
        db.delete(pending_cmd) # Remove from queue once picked up
    
    db.commit()
    return {"status": "ok", "command": cmd_str}

class AlertData(BaseModel):
    agent_id: str
    message: str
    severity: str = "INFO"
    type: str = "GENERIC"

@app.post("/api/v1/alert")
async def alrt(data: AlertData, db: Session = Depends(get_db)):
    print(f"🔥 ALERTA [{data.severity}] {data.agent_id}: {data.message}")
    db.add(IncidentLog(agent_id=data.agent_id, received_at=datetime.utcnow(),
                        type=data.type, message=data.message, severity=data.severity))
    db.commit()
    return {"status": "ok"}

# --- DASHBOARD & COMMANDS ---

@app.get("/api/v1/dashboard")
def dash(db: Session = Depends(get_db)):
    agents = db.query(Agent).all()
    agents_data = {
        a.agent_id: {
            "hostname": a.hostname,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "status": "ONLINE" if a.last_seen and (datetime.utcnow() - a.last_seen).total_seconds() < 30 else "OFFLINE",
            "os": a.os_info, "cpu_percent": a.cpu_percent, "ram_percent": a.ram_percent
        } for a in agents
    }
    logs = db.query(IncidentLog).order_by(desc(IncidentLog.received_at)).limit(50).all()
    return {"agents": agents_data, "recent_incidents": [{
        "received_at": l.received_at.isoformat(), 
        "agent_id": l.agent_id, 
        "message": l.message, "severity": l.severity, "type": l.type
    } for l in logs]}

@app.post("/api/v1/report/{dtype}")
async def rep(dtype: str, req: Request):
    data = await req.json()
    aid = data["agent_id"]
    if aid not in TEMPORARY_REPORTS: TEMPORARY_REPORTS[aid] = {}
    TEMPORARY_REPORTS[aid][dtype] = data["content"]
    return {"status": "ok"}

@app.get("/api/v1/agent/{agent_id}/{dtype}")
def get_report(agent_id: str, dtype: str):
    if agent_id in TEMPORARY_REPORTS and dtype in TEMPORARY_REPORTS[agent_id]:
        return JSONResponse(content=TEMPORARY_REPORTS[agent_id][dtype])
    raise HTTPException(status_code=404, detail="Report not found")

@app.post("/api/v1/admin/command")
async def cmd(data: dict, db: Session = Depends(get_db)):
    """
    [FIX #8] Persist command to DB instead of memory.
    """
    tgt, cmd_str = data["target_agent_id"], data["command"]
    
    # Save to DB
    new_cmd = PendingCommand(agent_id=tgt, command=cmd_str if isinstance(cmd_str, str) else str(cmd_str))
    db.add(new_cmd)
    db.commit()
    
    print(f"⚙️ [DB] Comando persistido para {tgt}: {cmd_str}")
    return {"status": "queued", "command": cmd_str}

# --- STATIC ---
app.mount("/static", StaticFiles(directory=STATIC_FILES_DIR), name="static")

@app.get("/")
async def index(request: Request):
    return FileResponse(os.path.join(STATIC_FILES_DIR, 'index.html'))

if __name__ == "__main__":
    cert_path = "cert.pem" if os.path.exists("cert.pem") else os.path.join(PROJECT_ROOT, "cert.pem")
    key_path = "key.pem" if os.path.exists("key.pem") else os.path.join(PROJECT_ROOT, "key.pem")
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print("❌ ERROR: Certificados SSL no encontrados.")
        sys.exit(1)

    print(f"🔒 Server Secure v6.4 (Port 8443)...")
    uvicorn.run(app, host="0.0.0.0", port=8443, ssl_keyfile=key_path, ssl_certfile=cert_path)