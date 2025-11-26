# PySentinel_Server/server.py
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from datetime import datetime
from typing import Any, Dict, List, Optional
import os

app = FastAPI(title="PySentinel C2", version="6.3")

# CORS Configuration
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_methods=["*"], 
    allow_headers=["*"]
)

# In-Memory Storage (Note: Production should use persistent SQL storage)
DB: Dict[str, Any] = {
    "agents": {}, 
    "logs": [], 
    "reports": {}, 
    "commands": {}
}

# Static Files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def index():
    """Serves the main Dashboard interface."""
    return FileResponse('static/index.html')

@app.post("/api/v1/heartbeat")
async def heartbeat(data: dict):
    """
    Agent check-in endpoint. 
    Updates agent status and retrieves pending commands.
    """
    aid = data.get("agent_id")
    if aid:
        DB["agents"][aid] = {
            "hostname": data.get("hostname"), 
            "last_seen": datetime.now().isoformat()
        }
    
    # Retrieve pending command if exists
    cmd = None
    if aid in DB["commands"] and DB["commands"][aid]:
        cmd = DB["commands"][aid].pop(0)
    
    return {"status": "ok", "command": cmd}

@app.post("/api/v1/alert")
async def receive_alert(data: dict):
    """Receives security alerts from agents."""
    # In production, use a proper logger instead of print
    print(f"[ALERT] [{data.get('severity', 'INFO')}] {data.get('message')}")
    
    entry = data.copy()
    entry["received_at"] = datetime.now().isoformat()
    DB["logs"].append(entry)
    return {"status": "received"}

@app.get("/api/v1/dashboard")
def get_dashboard_data():
    """Provides aggregated data for the frontend dashboard."""
    return {
        "agents": DB["agents"], 
        "recent_incidents": DB["logs"][-50:]
    }

@app.post("/api/v1/admin/command")
async def queue_command(data: dict):
    """Queue a command for a specific agent."""
    tgt = data.get("target_agent_id")
    if tgt:
        if tgt not in DB["commands"]: 
            DB["commands"][tgt] = []
        DB["commands"][tgt].append(data.get("command"))
        return {"status": "queued"}
    return {"status": "error", "message": "Target ID missing"}

@app.post("/api/v1/report/{dtype}")
async def save_report(dtype: str, req: Request):
    """Stores detailed reports (processes, ports) sent by agents."""
    data = await req.json()
    aid = data.get("agent_id")
    if aid:
        if aid not in DB["reports"]: 
            DB["reports"][aid] = {}
        DB["reports"][aid][dtype] = data.get("content")
    return {"status": "saved"}

@app.get("/api/v1/agent/{aid}/{dtype}")
def get_agent_report(aid: str, dtype: str):
    """Retrieves a specific report for an agent."""
    return DB.get("reports", {}).get(aid, {}).get(dtype, [])