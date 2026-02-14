"""
Basilisk Agent Entry Point
Initializes and starts the endpoint agent with graceful shutdown.
"""
import sys
import os

sys.path.insert(0, os.getcwd())

from basilisk.agent.engine import BasiliskAgent

if __name__ == "__main__":
    try:
        agent = BasiliskAgent()
        agent.start()
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user.")