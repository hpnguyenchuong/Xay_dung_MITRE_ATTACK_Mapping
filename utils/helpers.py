import base64
import json

class TransportObfuscationLayer:
    """
    Toy obfuscation for simulation. 
    Uses XOR + Base64 to demonstrate defense evasion (T1027). 
    This is not real encryption.
    """
    @staticmethod
    def obfuscate(payload: str) -> bytes:
        xored = bytes([b ^ 0x42 for b in payload.encode('utf-8')])
        return base64.b64encode(xored)
    
    @staticmethod
    def deobfuscate(cipher_bytes: bytes) -> str:
        decoded = base64.b64decode(cipher_bytes)
        return bytes([b ^ 0x42 for b in decoded]).decode('utf-8')

def get_breakdown(row):
    if row and dict(row).get("breakdown"):
        try:
            return json.loads(row["breakdown"])
        except Exception:
            return {}
    return {}

def get_color(tactic):
    colors = {
        "TA0111": "#f97316", # Command and Control - Orange
        "TA0104": "#ef4444", # Execution - Red
        "TA0103": "#a855f7", # Persistence - Purple
        "TA0102": "#eab308", # Privilege Escalation - Yellow
        "TA0105": "#ec4899", # Discovery - Pink
        "TA0106": "#10b981", # Lateral Movement - Green
        "TA0107": "#3b82f6", # Collection - Blue
        "TA0108": "#14b8a6", # Exfiltration - Teal
        "TA0109": "#ef4444", # Impact - Red
        
        "TA0101": "#f43f5e", # Initial Access
        "TA0100": "#6366f1", # Execution (Enterprise)
        
        # ICS specific
        "TA0110": "#0ea5e9", # Inhibit Response Function
        "TA0106": "#f43f5e", # Impair Process Control
    }
    return colors.get(tactic, "#3b82f6")
