"""
Basilisk C2 Server v7.1.0
Enterprise Command & Control with session management, rate limiting, and RBAC.

SECURITY NOTES:
  - BASILISK_ADMIN_PASSWORD_HASH and BASILISK_SERVER_SECRET_KEY are REQUIRED.
    The server refuses to start if either is absent — no insecure fallbacks.
  - Agent endpoints (/heartbeat, /alert, /report) require a shared API token
    (BASILISK_AGENT_TOKEN) to prevent unauthenticated data injection.
"""
import sys
import os
import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, List, Dict, Optional
from collections import defaultdict

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SERVER_DIR, '..'))
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
STATIC_DIR = os.path.join(SERVER_DIR, "static")
TEMPLATES_DIR = os.path.join(SERVER_DIR, "templates")

import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException, Header
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
from basilisk.server.database import (
    init_db, get_db, Agent, IncidentLog, PendingCommand, AgentReport
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("BasiliskC2")

CONFIG = Config(config_path=os.path.join(PROJECT_ROOT, "config.yaml"))

# ── Required secrets — server will NOT start if any are missing ──────────────
ADMIN_USER = os.getenv("BASILISK_ADMIN_USER", "admin").strip()
SECRET_KEY = os.getenv("BASILISK_SERVER_SECRET_KEY", "").strip()
ADMIN_HASH = os.getenv("BASILISK_ADMIN_PASSWORD_HASH", "").strip()
# Shared token agents must send in the X-Agent-Token header.
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
AGENT_TOKEN = os.getenv("BASILISK_AGENT_TOKEN", "").strip()

_missing = [
    name for name, val in [
        ("BASILISK_SERVER_SECRET_KEY", SECRET_KEY),
        ("BASILISK_ADMIN_PASSWORD_HASH", ADMIN_HASH),
        ("BASILISK_AGENT_TOKEN", AGENT_TOKEN),
    ]
    if not val
]
if _missing:
    logger.critical(
        "❌ CRITICAL: Missing required environment variables: %s\n"
        "   Set them in your .env file or environment and restart.",
        ", ".join(_missing)
    )
    sys.exit(1)
# ─────────────────────────────────────────────────────────────────────────────

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300        # seconds
SESSION_LIFETIME = 8      # hours
login_attempts: Dict[str, List[datetime]] = defaultdict(list)
last_heartbeats: Dict[str, datetime] = defaultdict(lambda: datetime.min)


# ── Pydantic schemas ──────────────────────────────────────────────────────────

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


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Basilisk C2",
    version="7.1.0",
    description="Enterprise-grade Command & Control Server",
    docs_url=None,
    redoc_url=None,
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

origins = [
    "https://localhost:8443",
    "http://localhost:8443",
    "https://127.0.0.1:8443",
    "http://127.0.0.1:8443",
]
if hasattr(CONFIG, "c2_url") and CONFIG.c2_url:
    origins.append(CONFIG.c2_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=True,
    same_site="lax",
)


# ── Security middleware ───────────────────────────────────────────────────────

@app.middleware("http")
async def security_headers_and_session_guard(request: Request, call_next):
    """Enforce security headers and validate dashboard sessions."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    public_routes = ["/login", "/favicon.ico", "/api/v1/auth/login"]
    # Agent routes are authenticated via X-Agent-Token, not session cookies.
    agent_route_prefixes = ["/api/v1/heartbeat", "/api/v1/alert", "/api/v1/report"]

    if (
        request.url.path in public_routes
        or request.url.path.startswith("/static/")
        or any(request.url.path.startswith(p) for p in agent_route_prefixes)
    ):
        return response

    user = request.session.get("user")
    if not user:
        if request.url.path == "/" or request.url.path.endswith(".html"):
            return RedirectResponse("/login")
        return JSONResponse(status_code=403, content={"detail": "Unauthorized"})

    # Enforce session expiry
    expires_at = request.session.get("expires_at")
    if expires_at and datetime.now().timestamp() > expires_at:
        request.session.clear()
        return JSONResponse(status_code=403, content={"detail": "Session expired"})

    return response


# ── Agent token dependency ────────────────────────────────────────────────────

def verify_agent_token(x_agent_token: Optional[str] = Header(default=None)) -> None:
    """
    Validate agent requests using a shared secret token.
    Agents must send the token in the X-Agent-Token HTTP header.
    Raises HTTP 401 if missing or incorrect.
    """
    if not x_agent_token or not secrets.compare_digest(x_agent_token, AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid or missing agent token")


# ── Auth endpoints ────────────────────────────────────────────────────────────

@app.post("/api/v1/auth/login")
async def login(data: LoginSchema, request: Request):
    """Authenticate admin user with rate limiting and session creation."""
    client_ip = request.client.host if request.client else "unknown"
    now = datetime.now()

    attempts = [
        t for t in login_attempts[client_ip]
        if now - t < timedelta(seconds=LOCKOUT_TIME)
    ]
    login_attempts[client_ip] = attempts

    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        logger.warning("🔒 Lockout triggered for IP: %s", client_ip)
        raise HTTPException(status_code=429, detail="Too many attempts")

    if data.username == ADMIN_USER and verify_password(ADMIN_HASH, data.password):
        login_attempts.pop(client_ip, None)
        request.session["user"] = ADMIN_USER
        request.session["expires_at"] = (
            now + timedelta(hours=SESSION_LIFETIME)
        ).timestamp()
        logger.info("✅ Admin logged in from %s", client_ip)
        return {"status": "ok", "redirect": "/"}

    login_attempts[client_ip].append(now)
    logger.warning("❌ Failed login attempt from %s", client_ip)
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    """Clear session and terminate authentication."""
    request.session.clear()
    return {"status": "ok"}


# ── Agent endpoints (require X-Agent-Token) ───────────────────────────────────

@app.post("/api/v1/heartbeat")
async def heartbeat(
    data: HeartbeatSchema,
    db: Session = Depends(get_db),
    _: None = Depends(verify_agent_token),
):
    """Process agent health check and return pending commands."""
    aid = data.agent_id
    now = datetime.now()

    if (now - last_heartbeats[aid]).total_seconds() < 1.0:
        return {"status": "throttled"}
    last_heartbeats[aid] = now

    agent = db.query(Agent).filter(Agent.agent_id == aid).first()
    if not agent:
        agent = Agent(agent_id=aid)
        db.add(agent)

    agent.last_seen = now          # type: ignore[assignment]
    agent.hostname = data.hostname  # type: ignore[assignment]
    agent.os_info = data.os        # type: ignore[assignment]
    agent.cpu_percent = data.cpu_percent  # type: ignore[assignment]
    agent.ram_percent = data.ram_percent  # type: ignore[assignment]

    pending_commands = (
        db.query(PendingCommand)
        .filter(PendingCommand.agent_id == aid)
        .order_by(asc(PendingCommand.issued_at))
        .all()
    )

    commands_to_send = []
    if pending_commands:
        for cmd in pending_commands:
            commands_to_send.append(cmd.command)
            db.delete(cmd)
        logger.info("⚡ Sending %d commands to %s", len(commands_to_send), aid)

    db.commit()

    return {
        "status": "ok",
        "command": commands_to_send[0] if commands_to_send else None,
        "commands": commands_to_send,
    }


@app.post("/api/v1/alert")
async def receive_alert(
    data: AlertSchema,
    db: Session = Depends(get_db),
    _: None = Depends(verify_agent_token),
):
    """Store security alert from agent."""
    logger.warning("🔥 ALERT [%s] %s: %s", data.severity, data.agent_id, data.message)
    db.add(IncidentLog(
        agent_id=data.agent_id,
        received_at=datetime.now(),
        type=data.type,
        message=data.message,
        severity=data.severity,
    ))
    db.commit()
    return {"status": "received"}


@app.post("/api/v1/report/{report_type}")
async def receive_report(
    report_type: str,
    data: ReportSchema,
    db: Session = Depends(get_db),
    _: None = Depends(verify_agent_token),
):
    """Store structured telemetry report from agent."""
    logger.info("📊 [REPORT] Received: %s -> %s", data.agent_id, report_type)
    try:
        content_json = json.dumps(data.content)
    except (TypeError, ValueError) as e:
        logger.error("❌ [REPORT] JSON error: %s", e)
        raise HTTPException(status_code=400, detail="Invalid JSON content")

    report = (
        db.query(AgentReport)
        .filter(
            AgentReport.agent_id == data.agent_id,
            AgentReport.report_type == report_type,
        )
        .first()
    )

    if report:
        report.content = content_json          # type: ignore[assignment]
        report.generated_at = datetime.now()   # type: ignore[assignment]
    else:
        db.add(AgentReport(
            agent_id=data.agent_id,
            report_type=report_type,
            content=content_json,
        ))

    db.commit()
    return {"status": "stored"}


# ── Dashboard / admin endpoints (require session) ─────────────────────────────

@app.get("/api/v1/dashboard")
def dashboard_stats(db: Session = Depends(get_db)):
    """Retrieve aggregated dashboard metrics and recent incidents."""
    agents = db.query(Agent).all()
    incidents = (
        db.query(IncidentLog)
        .order_by(desc(IncidentLog.received_at))
        .limit(50)
        .all()
    )

    return {
        "agents": {
            a.agent_id: {
                "hostname": a.hostname,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                "status": (
                    "ONLINE"
                    if a.last_seen and (datetime.now() - a.last_seen).total_seconds() < 30
                    else "OFFLINE"
                ),
                "os": a.os_info,
                "cpu_percent": a.cpu_percent,
                "ram_percent": a.ram_percent,
            }
            for a in agents
        },
        "recent_incidents": [
            {
                "received_at": line.received_at.isoformat(),
                "agent_id": line.agent_id,
                "severity": line.severity,
                "message": line.message,
                "type": line.type,
            }
            for line in incidents
        ],
    }


@app.post("/api/v1/admin/command")
async def queue_command(data: CommandSchema, db: Session = Depends(get_db)):
    """Queue remote command for agent execution (requires admin session)."""
    cmd_str = (
        data.command if isinstance(data.command, str) else json.dumps(data.command)
    )

    if len(cmd_str) > 4096:
        raise HTTPException(status_code=413, detail="Command payload too large")

    pending = PendingCommand(agent_id=data.target_agent_id, command=cmd_str)
    db.add(pending)
    db.commit()
    logger.info("✅ [COMMAND] Queued for %s: %s", data.target_agent_id, cmd_str)
    return {"status": "queued", "command": cmd_str}


@app.get("/api/v1/agent/{agent_id}/{report_type}")
def get_agent_report(agent_id: str, report_type: str, db: Session = Depends(get_db)):
    """Retrieve specific report type for agent."""
    report = (
        db.query(AgentReport)
        .filter(
            AgentReport.agent_id == agent_id,
            AgentReport.report_type == report_type,
        )
        .first()
    )

    if report and report.content:
        return JSONResponse(content=json.loads(str(report.content)))
    return JSONResponse(content=[])


# ── Static page routes ────────────────────────────────────────────────────────

@app.get("/")
async def root():
    """Serve main dashboard interface."""
    index_path = os.path.join(TEMPLATES_DIR, "index.html")
    if not os.path.exists(index_path):
        return {"error": f"Dashboard not found at: {index_path}"}
    return FileResponse(index_path)


@app.get("/login")
async def login_page():
    """Serve login interface."""
    login_path = os.path.join(TEMPLATES_DIR, "login.html")
    if not os.path.exists(login_path):
        return {"error": "Login template not found"}
    return FileResponse(login_path)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🔒 Initializing Basilisk C2 Enterprise v7.1.0...")
    init_db()
    cert_mgr = CertManager(cert_dir="certs")
    cert, key = cert_mgr.ensure_certificates()
    uvicorn.run(
        app,
        host="0.0.0.0",  # nosec B104
        port=8443,
        ssl_keyfile=key,
        ssl_certfile=cert,
        log_level="info",
    )  # nosec
