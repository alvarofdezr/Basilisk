"""
Basilisk Integration Test — end-to-end command flow validation.
Login → queue commands → verify reports are stored.

Skipped automatically by pytest when:
  - Required env vars are missing (BASILISK_TEST_PASS, BASILISK_TEST_AGENT_ID)
  - The server is not reachable at BASILISK_TEST_URL

Run directly when server + agent are both running:
    uv run python tests/test_flow.py

Required env vars (add to .env):
    BASILISK_TEST_PASS        your admin password
    BASILISK_TEST_AGENT_ID    AGENT_YOUR_HOSTNAME  (visible in agent log)

Optional:
    BASILISK_TEST_URL         https://localhost:8443  (default)
    BASILISK_TEST_USER        admin                   (default)
"""
import os
import json
import time
import sys

import pytest
import requests
from dotenv import load_dotenv

load_dotenv()

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

BASE_URL = os.getenv("BASILISK_TEST_URL",  "https://localhost:8443")
USERNAME = os.getenv("BASILISK_TEST_USER", "admin")
PASSWORD = os.getenv("BASILISK_TEST_PASS", "")
AGENT_ID = os.getenv("BASILISK_TEST_AGENT_ID", "")

# Skip the entire module if required env vars are missing
_MISSING = [
    name for name, val in [
        ("BASILISK_TEST_PASS", PASSWORD),
        ("BASILISK_TEST_AGENT_ID", AGENT_ID),
    ]
    if not val
]
if _MISSING:
    pytest.skip(
        f"Integration test requires env vars: {', '.join(_MISSING)}. "
        "Add them to .env to run this test.",
        allow_module_level=True,
    )


def _server_is_up() -> bool:
    """Return True if the C2 server is reachable."""
    try:
        requests.get(f"{BASE_URL}/login", verify=False, timeout=3)
        return True
    except requests.exceptions.ConnectionError:
        return False


# ── Test ──────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not _server_is_up(), reason="C2 server not running — start with: uv run python run_server.py")
def test_flow() -> None:
    """
    End-to-end flow: login → queue commands → verify agent reports.
    Requires both server and agent to be running.
    """
    _section("🧪 BASILISK COMMAND FLOW TEST")

    session = requests.Session()
    session.verify = False

    # Step 0: Login
    print("\n[0] LOGGING IN...")
    resp = session.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"username": USERNAME, "password": PASSWORD},
        timeout=5,
    )
    print(f"    Status: {resp.status_code}  {resp.json()}")
    assert resp.status_code == 200, f"Login failed: {resp.status_code} {resp.text}"

    # Step 1: Queue commands
    print("\n[1] QUEUING COMMANDS...")
    for cmd in ["REPORT_PROCESSES", "REPORT_PORTS", "RUN_AUDIT"]:
        print(f"    → {cmd}")
        r = session.post(
            f"{BASE_URL}/api/v1/admin/command",
            json={"target_agent_id": AGENT_ID, "command": cmd},
            timeout=5,
        )
        assert r.status_code == 200, f"Command queue failed for {cmd}: {r.status_code}"
        print(f"      {r.json()}")

    # Step 2: Wait for agent to process
    wait = 10
    print(f"\n[2] WAITING {wait}s (agent heartbeats every 3s)...")
    for remaining in range(wait, 0, -1):
        print(f"    ⏳ {remaining}s", end="\r")
        time.sleep(1)
    print()

    # Step 3: Verify reports exist and are non-empty
    print("\n[3] CHECKING REPORTS...")
    for report_type in ["processes", "ports", "audit"]:
        print(f"    → {report_type}")
        r = session.get(
            f"{BASE_URL}/api/v1/agent/{AGENT_ID}/{report_type}",
            timeout=5,
        )
        assert r.status_code == 200, f"Report fetch failed for {report_type}: {r.status_code}"
        data = r.json()
        count = len(data) if isinstance(data, list) else len(data.keys())
        assert count > 0, (
            f"Report '{report_type}' is empty. "
            "Agent may not have responded yet — try increasing the wait time."
        )
        first = data[0] if isinstance(data, list) else data
        print(f"      ✓ {count} item(s). First: {json.dumps(first)[:120]}...")

    _section("✅ ALL CHECKS PASSED")


def _section(title: str) -> None:
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


# ── Direct execution ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    missing = [
        name for name, val in [
            ("BASILISK_TEST_PASS", PASSWORD),
            ("BASILISK_TEST_AGENT_ID", AGENT_ID),
        ]
        if not val
    ]
    if missing:
        print(
            f"[ERROR] Missing env vars: {', '.join(missing)}\n"
            "        Add them to .env and retry.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not _server_is_up():
        print(
            f"[ERROR] Server not reachable at {BASE_URL}\n"
            "        Start it with: uv run python run_server.py",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        test_flow()
        sys.exit(0)
    except AssertionError as e:
        print(f"\n[FAIL] {e}", file=sys.stderr)
        sys.exit(1)
