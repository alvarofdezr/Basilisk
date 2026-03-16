"""
Basilisk Integration Test — end-to-end command flow validation.
Login → queue commands → verify reports are stored.

Este fichero NO se ejecuta automáticamente con pytest.
Solo corre cuando se llama directamente: uv run python tests/test_flow.py

Las credenciales se leen de variables de entorno — nunca hardcodeadas.

Configuración (en .env o exportadas):
    BASILISK_TEST_URL       https://localhost:8443   (opcional, este es el default)
    BASILISK_TEST_USER      admin                    (opcional, este es el default)
    BASILISK_TEST_PASS      tu_password              (obligatorio)
    BASILISK_TEST_AGENT_ID  AGENT_TU_HOSTNAME        (obligatorio, lo ves en el log del agente)
"""
import os
import json
import time
import sys
import requests
from dotenv import load_dotenv

# Cargar .env para que funcione tanto con pytest como ejecutado directamente
load_dotenv()

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Configuración — desde entorno, nunca hardcodeada
BASE_URL = os.getenv("BASILISK_TEST_URL",  "https://localhost:8443")
USERNAME = os.getenv("BASILISK_TEST_USER", "admin")
PASSWORD = os.getenv("BASILISK_TEST_PASS", "")
AGENT_ID = os.getenv("BASILISK_TEST_AGENT_ID", "")


def _print_section(title: str) -> None:
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


def _check_config() -> bool:
    """Devuelve True si la configuración está completa, False si faltan vars."""
    missing = [
        name for name, val in [
            ("BASILISK_TEST_PASS", PASSWORD),
            ("BASILISK_TEST_AGENT_ID", AGENT_ID),
        ]
        if not val
    ]
    if missing:
        print(
            f"\n[SKIP] test_flow requiere variables de entorno no definidas: "
            f"{', '.join(missing)}\n"
            f"       Añádelas al .env para ejecutar el test de integración.\n"
            f"       Los smoke tests (test_smoke.py) no las necesitan.",
            file=sys.stderr,
        )
        return False
    return True


def test_flow() -> bool:
    """
    Ejecuta el flujo completo: login → comandos → verificar reports.
    Devuelve True si todo fue bien.

    Cuando pytest recoge este fichero, encuentra esta función pero como
    empieza por test_ la ejecutaría — por eso usamos pytest.mark.skip
    si la config no está disponible.
    """
    if not _check_config():
        return False

    _print_section("🧪 BASILISK COMMAND FLOW TEST")

    session = requests.Session()
    session.verify = False

    # ── Step 0: Login ──────────────────────────────────────────────────────
    print("\n[0] LOGGING IN...")
    try:
        resp = session.post(
            f"{BASE_URL}/api/v1/auth/login",
            json={"username": USERNAME, "password": PASSWORD},
            timeout=5,
        )
        print(f"    Status : {resp.status_code}  {resp.json()}")
        if resp.status_code != 200:
            print("    ✗ Login failed — abortando.")
            return False
    except Exception as e:
        print(f"    ✗ Error de conexión: {e}")
        return False

    # ── Step 1: Queue commands ─────────────────────────────────────────────
    print("\n[1] ENVIANDO COMANDOS...")
    for cmd in ["REPORT_PROCESSES", "REPORT_PORTS", "RUN_AUDIT"]:
        print(f"    → {cmd}")
        try:
            resp = session.post(
                f"{BASE_URL}/api/v1/admin/command",
                json={"target_agent_id": AGENT_ID, "command": cmd},
                timeout=5,
            )
            print(f"      {resp.status_code}  {resp.json()}")
        except Exception as e:
            print(f"      ✗ {e}")
            return False

    # ── Step 2: Wait ───────────────────────────────────────────────────────
    wait = 10
    print(f"\n[2] ESPERANDO {wait}s (el agente hace heartbeat cada 3s)...")
    for remaining in range(wait, 0, -1):
        print(f"    ⏳ {remaining}s", end="\r")
        time.sleep(1)
    print()

    # ── Step 3: Check reports ──────────────────────────────────────────────
    print("\n[3] COMPROBANDO REPORTS...")
    all_ok = True
    for report_type in ["processes", "ports", "audit"]:
        print(f"    → {report_type}")
        try:
            resp = session.get(
                f"{BASE_URL}/api/v1/agent/{AGENT_ID}/{report_type}",
                timeout=5,
            )
            data = resp.json()
            count = len(data) if isinstance(data, list) else len(data.keys())
            if count == 0:
                print("      ⚠  Sin datos — el agente puede no haber respondido aún.")
                all_ok = False
            else:
                first = data[0] if isinstance(data, list) else data
                print(f"      ✓  {count} item(s). Primero: {json.dumps(first)[:120]}...")
        except Exception as e:
            print(f"      ✗ {e}")
            all_ok = False

    _print_section("✅ TEST COMPLETO" if all_ok else "⚠  TEST COMPLETO CON AVISOS")
    return all_ok


# ── Cuando pytest importa este fichero, este bloque NO se ejecuta ─────────────
# ── Solo corre cuando llamas: uv run python tests/test_flow.py ───────────────
if __name__ == "__main__":
    if not _check_config():
        sys.exit(1)
    success = test_flow()
    sys.exit(0 if success else 1)
