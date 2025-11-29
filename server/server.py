# server/server.py
"""
PySentinel EDR - Command & Control (C2) Server
Versión: 6.2 (Stable Enterprise Architecture)

Refactorización Completa:
- Security Hardening: HTTPS/TLS Obligatorio (Puerto 8443) [FIX CRÍTICO #5]
- Rate Limiting y Session Management [FIX CRÍTICO #1, #2]
- Configuración centralizada
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
from sqlalchemy import desc

from pysentinel.core.config import Config
from server_persistence import init_db, get_db, Agent, IncidentLog

# --- CARGA DE CONFIGURACIÓN Y SECRETOS ---
try:
    CONFIG = Config(config_path=os.path.join(PROJECT_ROOT, 'config.yaml'))
    
    ADMIN_HASH = getattr(CONFIG, 'admin_hash', None)
    if not ADMIN_HASH:
        print("[WARNING] Hash no encontrado en config. Usando default de emergencia.")
        ADMIN_HASH = hashlib.sha512("admin123".encode()).hexdigest()

    ADMIN_USER = getattr(CONFIG, 'admin_user', "admin")
    SECRET_KEY = getattr(CONFIG, 'secret_key', "SUPER_SECRET_SESSION_KEY_DEFAULT")

    # Políticas de Seguridad
    MAX_LOGIN_ATTEMPTS = getattr(CONFIG, 'max_login_attempts', 5)
    LOCKOUT_TIME = getattr(CONFIG, 'lockout_time', 300)
    SESSION_LIFETIME_HOURS = getattr(CONFIG, 'session_lifetime', 8)

except Exception as e:
    print(f"[ERROR] Fallo crítico cargando configuración: {e}. Usando valores por defecto.")
    ADMIN_HASH = hashlib.sha512("admin123".encode()).hexdigest()
    ADMIN_USER = "admin"
    SECRET_KEY = "EMERGENCY_KEY"
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME = 300
    SESSION_LIFETIME_HOURS = 8

# --- ESTRUCTURAS EN MEMORIA ---
login_attempts: Dict[str, List[datetime]] = defaultdict(list)
COMMAND_QUEUE: Dict[str, List[Any]] = {}
TEMPORARY_REPORTS: Dict[str, Dict[str, Any]] = {}
STATIC_FILES_DIR = os.path.join(SERVER_DIR, "static")

# --- INICIALIZACIÓN APP ---
app = FastAPI(title="PySentinel C2", version="6.2 Secure")

@app.on_event("startup")
def on_startup():
    init_db()
    print(f"✨ [SYSTEM] C2 Server Online (HTTPS). User: {ADMIN_USER}")

# --- MIDDLEWARES DE SEGURIDAD ---

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
    
    if not user:
        return _handle_unauthorized(path)

    if expires_at and datetime.utcnow().timestamp() > expires_at:
        request.session.clear()
        return _handle_unauthorized(path)
    
    return await call_next(request)

def _handle_unauthorized(path: str):
    if path == "/" or path == "/index.html":
        return RedirectResponse(url="/login")
    return JSONResponse(status_code=403, content={"error": "Unauthorized"})

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=True, same_site='lax')
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --- ENDPOINTS ---

@app.get("/login")
async def login_page():
    return FileResponse(os.path.join(STATIC_FILES_DIR, 'login.html'))

@app.post("/api/v1/auth/login")
async def login(request: Request):
    client_ip = request.client.host
    now = datetime.utcnow()

    # Rate Limiting
    login_attempts[client_ip] = [t for t in login_attempts[client_ip] if now - t < timedelta(seconds=LOCKOUT_TIME)]

    if len(login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        remaining = LOCKOUT_TIME - (now - login_attempts[client_ip][0]).seconds
        return JSONResponse(status_code=429, content={"status": "error", "message": f"Locked out. Retry in {remaining}s"})

    data = await request.json()
    
    if data.get("username") != ADMIN_USER:
        login_attempts[client_ip].append(now)
        return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid credentials"})

    input_hash = hashlib.sha512(data.get("password", "").encode()).hexdigest()
    
    if input_hash == ADMIN_HASH:
        if client_ip in login_attempts: del login_attempts[client_ip]
        request.session["user"] = ADMIN_USER
        request.session["expires_at"] = (now + timedelta(hours=SESSION_LIFETIME_HOURS)).timestamp()
        return {"status": "ok", "redirect": "/"}
    
    login_attempts[client_ip].append(now)
    return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid credentials"})

@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return {"status": "ok"}

# --- API AGENTE ---

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
    agent = db.query(Agent).filter(Agent.agent_id == aid).first()

    if agent:
        agent.last_seen = datetime.utcnow()
        agent.hostname = data.hostname
        agent.os_info = data.os
        agent.cpu_percent = data.cpu_percent
        agent.ram_percent = data.ram_percent
    else:
        agent = Agent(agent_id=aid, hostname=data.hostname, os_info=data.os,
                        cpu_percent=data.cpu_percent, ram_percent=data.ram_percent)
        db.add(agent)
    db.commit()

    cmd = None
    if aid in COMMAND_QUEUE and COMMAND_QUEUE[aid]:
        cmd = COMMAND_QUEUE[aid].pop(0)
        if not COMMAND_QUEUE[aid]: del COMMAND_QUEUE[aid]
    
    return {"status": "ok", "command": cmd}

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

# --- DASHBOARD & ADMIN ---

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
        "message": l.message,                    
        "severity": l.severity,                
        "type": l.type
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
async def cmd(data: dict):
    tgt, cmd_str = data["target_agent_id"], data["command"]
    if tgt not in COMMAND_QUEUE: COMMAND_QUEUE[tgt] = []
    COMMAND_QUEUE[tgt].append(cmd_str)
    return {"status": "queued", "command": cmd_str}

# --- STATIC & STARTUP ---
app.mount("/static", StaticFiles(directory=STATIC_FILES_DIR), name="static")

@app.get("/")
async def index(request: Request):
    return FileResponse(os.path.join(STATIC_FILES_DIR, 'index.html'))

if __name__ == "__main__":
    cert_path = "cert.pem" if os.path.exists("cert.pem") else os.path.join(PROJECT_ROOT, "cert.pem")
    key_path = "key.pem" if os.path.exists("key.pem") else os.path.join(PROJECT_ROOT, "key.pem")
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print("❌ ERROR: No se encontraron certificados SSL (cert.pem, key.pem).")
        print("   Ejecuta: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
        sys.exit(1)

    print(f"🔒 Iniciando servidor seguro en port 8443...")
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8443, 
        ssl_keyfile=key_path, 
        ssl_certfile=cert_path
    )