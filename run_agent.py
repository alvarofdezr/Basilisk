import sys
import os

# Asegura que Python encuentre el paquete 'basilisk'
sys.path.insert(0, os.getcwd())

from basilisk.agent.engine import BasiliskAgent

if __name__ == "__main__":
    try:
        agent = BasiliskAgent()
        agent.start()
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user.")
