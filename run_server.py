"""
Basilisk C2 Server Entry Point
Delegates to basilisk.server.server.main() — single source of truth.
"""
import sys
import os

sys.path.insert(0, os.getcwd())

from basilisk.server.server import main

if __name__ == "__main__":
    main()
