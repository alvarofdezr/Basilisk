"""
Basilisk Integration Test
End-to-end command flow validation: login → queue commands → verify reports.
"""
import requests
import json
import time

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

BASE_URL = "https://localhost:8443"
AGENT_ID = "AGENT_PC-ALVARO"


def test_flow() -> None:
    """Execute complete command flow test."""
    print("\n" + "="*60)
    print("🧪 TESTING BASILISK COMMAND FLOW")
    print("="*60)
    
    session = requests.Session()
    session.verify = False
    
    print("\n[0] LOGGING IN...")
    try:
        resp = session.post(
            f"{BASE_URL}/api/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5
        )
        print(f"    ✓ Status: {resp.status_code}")
        print(f"    Response: {resp.json()}")
        if resp.status_code != 200:
            print("    ✗ Login failed!")
            return
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return
    
    print("\n[1] SENDING COMMANDS TO SERVER...")
    commands = ['REPORT_PROCESSES', 'REPORT_PORTS', 'RUN_AUDIT']
    
    for cmd in commands:
        print(f"    → Sending: {cmd}")
        try:
            resp = session.post(
                f"{BASE_URL}/api/v1/admin/command",
                json={"target_agent_id": AGENT_ID, "command": cmd},
                timeout=5
            )
            print(f"    ✓ Status: {resp.status_code}")
            print(f"    Response: {resp.json()}")
        except Exception as e:
            print(f"    ✗ Error: {e}")
            return
    
    print(f"\n[2] WAITING 8 SECONDS FOR AGENT TO PROCESS...")
    print("    (Agent heartbeats every 3s, should get commands in next heartbeat)")
    
    for i in range(8, 0, -1):
        print(f"    ⏳ {i}...")
        time.sleep(1)
    
    print(f"\n[3] CHECKING FOR REPORTS...")
    report_types = ['processes', 'ports', 'audit']
    
    for report_type in report_types:
        print(f"    → Fetching: {report_type}")
        try:
            resp = session.get(
                f"{BASE_URL}/api/v1/agent/{AGENT_ID}/{report_type}",
                timeout=5
            )
            print(f"    ✓ Status: {resp.status_code}")
            data = resp.json()
            
            if isinstance(data, list):
                print(f"    ✓ Data: {len(data)} items")
                if len(data) > 0:
                    print(f"    First item: {json.dumps(data[0], indent=6)[:200]}...")
            else:
                print(f"    ✓ Data: {type(data)} object")
                print(f"    {json.dumps(data, indent=6)[:200]}...")
        except Exception as e:
            print(f"    ✗ Error: {e}")
    
    print("\n" + "="*60)
    print("✅ TEST COMPLETE")
    print("="*60 + "\n")


if __name__ == "__main__":
    test_flow()