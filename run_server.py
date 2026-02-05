import os
import uvicorn
import sys

sys.path.insert(0, os.getcwd())

from basilisk.server.database import init_db
from basilisk.utils.cert_manager import CertManager

if __name__ == "__main__":
    print("🚀 Starting Basilisk C2 Server...")
    
    init_db()
    
    cert_mgr = CertManager(cert_dir="certs")
    cert, key = cert_mgr.ensure_certificates()

    uvicorn.run("basilisk.server.server:app", host="0.0.0.0", port=8443, ssl_keyfile=key, ssl_certfile=cert, reload=True)