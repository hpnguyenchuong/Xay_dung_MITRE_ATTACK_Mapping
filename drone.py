import threading
import os

from utils.constants import C_YELLOW, C_END
from core.db_manager import init_forensic_db, db_worker, load_re_findings_from_json
from simulator.c2_server import tcp_server, terminal_dashboard_thread, http_server

def main():
    init_forensic_db()
    load_re_findings_from_json()
    
    # Start background threads
    threading.Thread(target=db_worker, daemon=True).start()
    threading.Thread(target=tcp_server, daemon=True).start()
    threading.Thread(target=terminal_dashboard_thread, daemon=True).start()
    
    try:
        http_server()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] Shutting down C2...{C_END}")

if __name__ == "__main__":
    main()
