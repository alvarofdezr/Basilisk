# server/server.py
# -----------------------------------------------------------------------
# CORE DE MANDO Y CONTROL (C2) CON PERSISTENCIA SQL (SQLAlchemy/SQLite)
# -----------------------------------------------------------------------

# --- AJUSTE DE RUTA DE BÚSQUEDA (CRÍTICO) ---
import sys
import os
import hashlib
from datetime import datetime
from typing import Dict, Any, List

# Configuramos sys.path para encontrar módulos del proyecto
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SERVER_DIR, '..'))

sys.path.insert(0, SERVER_DIR) 
sys.path.insert(0, PROJECT_ROOT)
# -------------------------------------------------------------------

# --- LIBRERÍAS ---
from fastapi import FastAPI, Request, Depends, status, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
# Módulos del proyecto (ahora accesibles)
from pysentinel.core.config import Config 
from server_persistence import init_db, get_db, Agent, IncidentLog 


# --- CONFIGURACIÓN E INICIALIZACIÓN ---
ADMIN_USER = "admin"
SECRET_KEY = "SUPER_SECRET_SESSION_KEY" 

# Variables Volátiles (Comandos y Reportes Temporales)
COMMAND_QUEUE: Dict[str, List[Any]] = {} 
TEMPORARY_REPORTS: Dict[str, Dict[str, Any]] = {}

# --- RUTA DE ARCHIVOS ESTÁTICOS (CRÍTICA) ---
STATIC_FILES_DIR = os.path.join(SERVER_DIR, "static")

# --- CARGA UNIFICADA DE SEGURIDAD (SHA-512) ---
try:
    CONFIG = Config(config_path=os.path.join(PROJECT_ROOT, 'config.yaml'))
    ADMIN_HASH = CONFIG.admin_hash
    
    if not ADMIN_HASH:
        print("[WARNING] 'admin_password_hash' vacío. Usando hash de emergencia.")
        ADMIN_HASH = hashlib.sha512("admin123".encode()).hexdigest()
except Exception as e:
    print(f"[ERROR] Fallo al cargar config.yaml: {e}. Usando hash de emergencia.")
    ADMIN_HASH = hashlib.sha512("admin123".encode()).hexdigest()
    
# --- INICIALIZACIÓN DE LA APP ---
app = FastAPI(title="PySentinel C2", version="6.2 Persistente")


# --- STARTUP HOOK ---
@app.on_event("startup")
def on_startup():
    init_db() 
    print("✨ Servidor C2 iniciado con BBDD persistente (SQLite).")

# --- MIDDLEWARES (EN ORDEN CORRECTO) ---

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Lista de rutas públicas
    public_routes = [
        "/login", "/api/v1/auth/login", "/static", "/favicon.ico",
        "/api/v1/heartbeat", "/api/v1/alert", "/api/v1/report"
    ]
    
    path = request.url.path
    
    if any(path.startswith(r) for r in public_routes):
        return await call_next(request)

    # El SessionMiddleware ya se ejecutó, por lo que 'request.session' existe.
    user = request.session.get("user")
    
    if not user:
        if path == "/" or path == "/index.html":
            return RedirectResponse(url="/login")
        if path.startswith("/api/v1/admin"):
            return JSONResponse(status_code=403, content={"error": "Unauthorized"})

    response = await call_next(request)
    return response

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
# --- 1. ENDPOINTS DE AUTENTICACIÓN ---

@app.get("/login")
async def login_page():
    # CORRECCIÓN: Usar STATIC_FILES_DIR para la ruta absoluta
    return FileResponse(os.path.join(STATIC_FILES_DIR, 'login.html'))

@app.post("/api/v1/auth/login")
async def login(request: Request):
    data = await request.json()
    
    if data.get("username") != ADMIN_USER:
        return JSONResponse(status_code=401, content={"status": "error", "message": "Credenciales inválidas"})

    input_password = data.get("password", "")
    input_hash = hashlib.sha512(input_password.encode()).hexdigest()
    
    if input_hash == ADMIN_HASH:
        request.session["user"] = ADMIN_USER 
        return {"status": "ok", "redirect": "/"}
    
    return JSONResponse(status_code=401, content={"status": "error", "message": "Credenciales inválidas"})

@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return {"status": "ok"}

# --- 2. ENDPOINTS DE AGENTE (PERSISTENTES) ---

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
        agent = Agent(
            agent_id=aid, 
            hostname=data.hostname, 
            os_info=data.os,
            cpu_percent=data.cpu_percent,
            ram_percent=data.ram_percent
        )
        db.add(agent)

    db.commit()

    cmd = None
    if aid in COMMAND_QUEUE and COMMAND_QUEUE[aid]:
        cmd = COMMAND_QUEUE[aid].pop(0) 
        if not COMMAND_QUEUE[aid]:
            del COMMAND_QUEUE[aid]
    
    return {"status": "ok", "command": cmd}


class AlertData(BaseModel):
    agent_id: str
    message: str
    severity: str = "INFO"
    type: str = "GENERIC"

@app.post("/api/v1/alert")
async def alrt(data: AlertData, db: Session = Depends(get_db)):
    print(f"🔥 ALERTA DE {data.agent_id}: {data.message}")
    
    new_log = IncidentLog(
        agent_id=data.agent_id,
        received_at=datetime.utcnow(),
        type=data.type,
        message=data.message,
        severity=data.severity
    )
    db.add(new_log)
    db.commit()
    
    return {"status": "ok"}

# --- 3. ENDPOINTS DE DASHBOARD Y ADMIN ---

@app.get("/api/v1/dashboard")
def dash(db: Session = Depends(get_db)):
    agents_list = db.query(Agent).all()
    
    agents_data = {}
    for agent in agents_list:
        is_online = (datetime.utcnow() - agent.last_seen).total_seconds() < 30 if agent.last_seen else False
        
        agents_data[agent.agent_id] = {
            "hostname": agent.hostname, 
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
            "status": "ONLINE" if is_online else "OFFLINE",
            "os": agent.os_info,
            "cpu_percent": agent.cpu_percent,
            "ram_percent": agent.ram_percent,
        }
        
    recent_logs = db.query(IncidentLog).order_by(desc(IncidentLog.received_at)).limit(50).all()
    
    logs_data = [{
        "received_at": log.received_at.isoformat(), 
        "agent_id": log.agent_id, 
        "message": log.message, 
        "severity": log.severity,
        "type": log.type
    } for log in recent_logs]
    
    return {"agents": agents_data, "recent_incidents": logs_data}

@app.post("/api/v1/report/{dtype}")
async def rep(dtype: str, req: Request):
    data = await req.json()
    aid = data["agent_id"]
    
    if aid not in TEMPORARY_REPORTS:
        TEMPORARY_REPORTS[aid] = {}
        
    TEMPORARY_REPORTS[aid][dtype] = data["content"] 
    return {"status": "ok"}

@app.get("/api/v1/agent/{agent_id}/{dtype}")
def get_agent_report(agent_id: str, dtype: str):
    if agent_id in TEMPORARY_REPORTS and dtype in TEMPORARY_REPORTS[agent_id]:
        return JSONResponse(content=TEMPORARY_REPORTS[agent_id][dtype]) 
    
    raise HTTPException(status_code=404, detail="Reporte no encontrado o no generado.")

@app.post("/api/v1/admin/command")
async def cmd(data: dict):
    tgt = data["target_agent_id"]
    cmd_str = data["command"]
    
    if tgt not in COMMAND_QUEUE: 
        COMMAND_QUEUE[tgt] = []
        
    COMMAND_QUEUE[tgt].append(cmd_str)
    
    print(f"⚙️ Comando '{cmd_str}' encolado para {tgt}")
    return {"status": "queued", "command": cmd_str}

# --- 4. ENDPOINTS ESTÁTICOS ---

# CRÍTICO: Montar la carpeta estática con la ruta absoluta
app.mount("/static", StaticFiles(directory=STATIC_FILES_DIR), name="static")

@app.get("/")
async def index(request: Request):
    # CRÍTICO: Servir index.html con la ruta absoluta
    return FileResponse(os.path.join(STATIC_FILES_DIR, 'index.html'))