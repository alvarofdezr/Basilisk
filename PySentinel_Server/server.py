# PySentinel_Server/server.py (v6.2 Auth Final)
# IMPORTANTE: Ya incluye la corrección del 'sys.path'
import sys
import os
import hashlib # Ahora para SHA-512
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from datetime import datetime
from typing import Dict, Any

# --- AJUSTE DE RUTA: NECESARIO PARA IMPORTAR PY-SENTINEL ---
# Esto permite que Python encuentre el módulo 'pysentinel' un nivel arriba
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# -----------------------------------------------------------

# La importación problemática AHORA FUNCIONA
from pysentinel.core.config import Config 

app = FastAPI(title="PySentinel C2", version="6.2 Auth Final")

# --- CONFIGURACIÓN ---
ADMIN_USER = "admin"
SECRET_KEY = "SUPER_SECRET_SESSION_KEY" 

# Base de Datos
DB: Dict[str, Any] = {
    "agents": {}, "logs": [], "reports": {}, "commands": {}
}

# --- CARGA UNIFICADA DE SEGURIDAD (SHA-512) ---
try:
    # 1. Calculamos la ruta correcta de config.yaml (un nivel arriba)
    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    CONFIG_FILE_PATH = os.path.join(PROJECT_ROOT, 'config.yaml')
    
    # 2. Cargamos el archivo con la ruta correcta
    CONFIG = Config(config_path=CONFIG_FILE_PATH)
    ADMIN_HASH = CONFIG.admin_hash
    
    if not ADMIN_HASH:
        print("[WARNING] 'admin_password_hash' está vacío en config.yaml. Usando hash de emergencia.")
        # Usar un hash de emergencia (SHA-512 de "admin123")
        ADMIN_HASH = hashlib.sha512("admin123".encode()).hexdigest()

except Exception as e:
    print(f"[ERROR] Fallo al cargar config.yaml: {e}. Usando hash de emergencia.")
    ADMIN_HASH = hashlib.sha512("admin123".encode()).hexdigest()
    
# --- RUTAS ---

@app.get("/login")
async def login_page():
    return FileResponse('static/login.html')

@app.post("/api/v1/auth/login")
async def login(request: Request):
    """Login unificado: Hashea input con SHA-512 y compara con config.yaml."""
    data = await request.json()
    
    if data.get("username") != ADMIN_USER:
        return JSONResponse(status_code=401, content={"status": "error", "message": "Credenciales inválidas"})

    # 1. HASHEAR con SHA-512
    input_password = data.get("password", "")
    input_hash = hashlib.sha512(input_password.encode()).hexdigest()
    
    # 2. Comparar con el hash leído de config.yaml
    if input_hash == ADMIN_HASH:
        request.session["user"] = ADMIN_USER 
        return {"status": "ok", "redirect": "/"}
    
    return JSONResponse(status_code=401, content={"status": "error", "message": "Credenciales inválidas"})

@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return {"status": "ok"}

# --- MIDDLEWARES ---

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

    user = request.session.get("user")
    
    if not user:
        if path == "/" or path == "/index.html":
            return RedirectResponse(url="/login")
        if path.startswith("/api/v1/admin"):
             return JSONResponse(status_code=403, content={"error": "Unauthorized"})

    response = await call_next(request)
    return response

# Se ejecutan ANTES que el auth_middleware
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --- RESTO DE LA APP ---

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def index(request: Request):
    return FileResponse('static/index.html')

@app.post("/api/v1/heartbeat")
async def heartbeat(data: dict):
    aid = data.get("agent_id")
    if aid:
        DB["agents"][aid] = {"hostname": data.get("hostname"), "last_seen": datetime.now().isoformat()}
    cmd = None
    if aid in DB["commands"] and DB["commands"][aid]:
        cmd = DB["commands"][aid].pop(0)
    return {"status": "ok", "command": cmd}

@app.post("/api/v1/alert")
async def receive_alert(data: dict):
    print(f"[ALERT] [{data.get('severity', 'INFO')}] {data.get('message')}")
    entry = data.copy()
    entry["received_at"] = datetime.now().isoformat()
    DB["logs"].append(entry)
    return {"status": "received"}

@app.get("/api/v1/dashboard")
def get_dashboard_data():
    return {"agents": DB["agents"], "recent_incidents": DB["logs"][-50:]}

@app.post("/api/v1/admin/command")
async def queue_command(data: dict):
    tgt = data.get("target_agent_id")
    if tgt:
        if tgt not in DB["commands"]: DB["commands"][tgt] = []
        DB["commands"][tgt].append(data.get("command"))
        return {"status": "queued"}
    return {"status": "error"}

@app.post("/api/v1/report/{dtype}")
async def save_report(dtype: str, req: Request):
    data = await req.json()
    aid = data.get("agent_id")
    if aid:
        if aid not in DB["reports"]: DB["reports"][aid] = {}
        DB["reports"][aid][dtype] = data.get("content")
    return {"status": "saved"}

@app.get("/api/v1/agent/{aid}/{dtype}")
def get_agent_report(aid: str, dtype: str):
    return DB.get("reports", {}).get(aid, {}).get(dtype, [])