# server/server.py
"""
Basilisk C2 Server v6.6.0 (Argon2 Enabled)
"""
import sys
import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List
from collections import defaultdict

# --- CONFIGURACIÓN DE ENTORNO ---
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SERVER_DIR, '..'))

if SERVER_DIR not in sys.path: sys.path.insert(0, SERVER_DIR)
if PROJECT_ROOT not in sys.path: sys.path.insert(0, PROJECT_ROOT)

import uvicorn  
from fastapi import FastAPI, Request, Depends, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from basilisk.core.config import Config
from basilisk.core.security import verify_password
from basilisk.utils.cert_manager import CertManager
from server_persistence import init_db, get_db, Agent, IncidentLog, PendingCommand, AgentReport

# --- CARGA DE CONFIGURACIÓN ---
CONFIG = Config(config_path=os.path.join(PROJECT_ROOT, 'config.yaml'))

ADMIN_HASH = CONFIG.admin_hash
SECRET_KEY = CONFIG.server_secret_key

if ADMIN_HASH:
    ADMIN_HASH = ADMIN_HASH.strip()

if not ADMIN_HASH or not SECRET_KEY:
    print("❌ CRITICAL ERROR: BASILISK_ADMIN_PASSWORD_HASH or BASILISK_SERVER_SECRET_KEY not found in .env")
    sys.exit(1)

ADMIN_USER = os.getenv("BASILISK_ADMIN_USER", "admin").strip()
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300
SESSION_LIFETIME_HOURS = 8

# --- ESTRUCTURAS EN MEMORIA ---
login_attempts: Dict[str, List[datetime]] = defaultdict(list)
MIN_HEARTBEAT_INTERVAL = 1.0 
last_heartbeats: Dict[str, datetime] = defaultdict(lambda: datetime.min)
STATIC_FILES_DIR = os.path.join(SERVER_DIR, "static")

app = FastAPI(title="Basilisk C2", version="6.6.0")

@app.on_event("startup")
def on_startup():
    VERDE = "\033[92m"
    RESET = "\033[0m"
    
    banner = r"""
    ██████╗  █████╗ ███████╗██╗██╗     ██╗███████╗██╗  ██╗
    ██╔══██╗██╔══██╗██╔════╝██║██║     ██║██╔════╝██║ ██╔╝
    ██████╔╝███████║███████╗██║██║     ██║███████╗█████╔╝ 
    ██╔══██╗██╔══██║╚════██║██║██║     ██║╚════██║██╔═██╗ 
    ██████╔╝██║  ██║███████║██║███████╗██║███████║██║  ██╗
    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
                                        v6.6.0 Enterprise
    """
    
    print(f"{VERDE}{banner}{RESET}")
    init_db()
    print(f"🐍 [SYSTEM] Basilisk C2 Online (Argon2 Security). User: {ADMIN_USER}")

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

# --- MIDDLEWARE ---
origins = [
    "https://localhost:8443",
    "http://localhost:8443",
    "https://127.0.0.1:8443",
    "http://127.0.0.1:8443"
]
if hasattr(CONFIG, 'c2_url'):
    origins.append(CONFIG.c2_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    try:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
    except Exception as e:
        raise e

    public_routes = [
        "/login", "/api/v1/auth/login", "/static", "/favicon.ico",
        "/api/v1/heartbeat", "/api/v1/alert", "/api/v1/report"
    ]
    path = request.url.path
    
    if any(path.startswith(r) for r in public_routes):
        return response

    user = request.session.get("user")
    expires_at = request.session.get("expires_at")
    
    if not user: return _handle_unauthorized(path)
    if expires_at and datetime.now().timestamp() > expires_at:
        request.session.clear()
        return _handle_unauthorized(path)
    
    return response

def _handle_unauthorized(path: str):
    if path == "/" or path == "/index.html": return RedirectResponse(url="/login")
    return JSONResponse(status_code=403, content={"error": "Unauthorized"})

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=True, same_site='lax')

# --- AUTH ---
@app.get("/login")
async def login_page(): return FileResponse(os.path.join(STATIC_FILES_DIR, 'login.html'))

@app.post("/api/v1/auth/login")
async def login(request: Request):
    client_ip = get_client_ip(request)
    now = datetime.now()
    
    login_attempts[client_ip] = [t for t in login_attempts[client_ip] if now - t < timedelta(seconds=LOCKOUT_TIME)]
    if len(login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        remaining = LOCKOUT_TIME - (now - login_attempts[client_ip][0]).seconds
        return JSONResponse(status_code=429, content={"status": "error", "message": f"Locked out ({remaining}s)"})

    try:
        data = await request.json()
        input_user = data.get("username", "")
        input_pass = data.get("password", "")
        
        # [MODIFICADO] Verificación con Argon2
        if input_user == ADMIN_USER:
            if verify_password(ADMIN_HASH, input_pass):
                if client_ip in login_attempts: del login_attempts[client_ip]
                request.session["user"] = ADMIN_USER
                request.session["expires_at"] = (now + timedelta(hours=SESSION_LIFETIME_HOURS)).timestamp()
                return {"status": "ok", "redirect": "/"}
    
    except Exception:
        pass 

    login_attempts[client_ip].append(now)
    return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid credentials"})

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
    now = datetime.now()
    if (now - last_heartbeats[aid]).total_seconds() < MIN_HEARTBEAT_INTERVAL:
        return JSONResponse(status_code=429, content={"error": "Throttling active"})
    last_heartbeats[aid] = now

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
    
    cmd_str = None
    pending_cmd = db.query(PendingCommand).filter(PendingCommand.agent_id == aid)\
                    .order_by(asc(PendingCommand.issued_at)).first()
    if pending_cmd:
        cmd_str = pending_cmd.command
        db.delete(pending_cmd)
    
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
    db.add(IncidentLog(agent_id=data.agent_id, received_at=datetime.now(),
                        type=data.type, message=data.message, severity=data.severity))
    db.commit()
    return {"status": "ok"}

@app.get("/api/v1/dashboard")
def dash(db: Session = Depends(get_db)):
    agents = db.query(Agent).all()
    agents_data = {
        a.agent_id: {
            "hostname": a.hostname,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "status": "ONLINE" if a.last_seen and (datetime.now() - a.last_seen).total_seconds() < 30 else "OFFLINE",
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
async def rep(dtype: str, req: Request, db: Session = Depends(get_db)):
    data = await req.json()
    aid = data["agent_id"]
    content_json = json.dumps(data["content"])
    
    existing_report = db.query(AgentReport).filter(
        AgentReport.agent_id == aid, 
        AgentReport.report_type == dtype
    ).first()
    
    if existing_report:
        existing_report.content = content_json
        existing_report.generated_at = datetime.now()
    else:
        new_report = AgentReport(agent_id=aid, report_type=dtype, content=content_json)
        db.add(new_report)
        
    db.commit()
    return {"status": "ok"}

@app.get("/api/v1/agent/{agent_id}/{dtype}")
def get_report(agent_id: str, dtype: str, db: Session = Depends(get_db)):
    report = db.query(AgentReport).filter(
        AgentReport.agent_id == agent_id, 
        AgentReport.report_type == dtype
    ).first()
    
    if report:
        return JSONResponse(content=json.loads(report.content))
    return JSONResponse(content=[])

@app.post("/api/v1/admin/command")
async def cmd(data: dict, db: Session = Depends(get_db)):
    tgt = data["target_agent_id"]
    cmd_raw = data["command"]

    if isinstance(cmd_raw, dict):
        cmd_str = json.dumps(cmd_raw)
    elif isinstance(cmd_raw, str):
        cmd_str = cmd_raw
    else:
        raise HTTPException(status_code=400, detail="Invalid command format")

    if len(cmd_str) > 4096:
        raise HTTPException(status_code=413, detail="Command too large")
    
    new_cmd = PendingCommand(agent_id=tgt, command=cmd_str)
    db.add(new_cmd)
    db.commit()
    
    print(f"⚙️ [DB] Comando para {tgt}: {cmd_str}")
    return {"status": "queued", "command": cmd_str}

app.mount("/static", StaticFiles(directory=STATIC_FILES_DIR), name="static")

@app.get("/")
async def index(request: Request):
    return FileResponse(os.path.join(STATIC_FILES_DIR, 'index.html'))

if __name__ == "__main__":
    cert_mgr = CertManager(cert_dir="certs")
    cert_path, key_path = cert_mgr.ensure_certificates()

    print(f"🔒 Basilisk Server Secure v6.6 (Port 8443)...")
    try:
        uvicorn.run(app, host="0.0.0.0", port=8443, ssl_keyfile=key_path, ssl_certfile=cert_path)
    except FileNotFoundError as e:
        print(f"❌ CRITICAL SSL ERROR: {e}")
        print("   Ensure 'certs' directory is writable.")