"""
Basilisk Agent Entry Point
Delegates to basilisk.agent.engine.main() — single source of truth.
"""
import sys
import os

sys.path.insert(0, os.getcwd())

from basilisk.agent.engine import main

if __name__ == "__main__":
    main()
