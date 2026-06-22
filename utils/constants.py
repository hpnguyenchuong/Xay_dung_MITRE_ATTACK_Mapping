import os

HOST = "0.0.0.0"
PORT = 5555
WEB_PORT = 9000

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
INDEX_HTML_PATH = os.path.join(TEMPLATE_DIR, "index.html")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
ATTACKS_DIR = os.path.join(REPORTS_DIR, "attacks")
NAVIGATOR_DIR = os.path.join(BASE_DIR, "navigator_exports")
DB_FILE_PATH = os.path.join(LOGS_DIR, "soc_artifacts.db")

for d in [LOGS_DIR, REPORTS_DIR, ATTACKS_DIR, NAVIGATOR_DIR]:
    os.makedirs(d, exist_ok=True)

C_GREEN, C_RED, C_YELLOW, C_BLUE, C_CYAN, C_BOLD, C_END = ("\033[92m", "\033[91m", "\033[93m", "\033[94m", "\033[96m", "\033[1m", "\033[0m")

ICS_MAPPING_RULES = {
    "DF_MUTEX_01": {
        "finding": "Mutex Artifact", "tactic": "TA0103", "tactic_name": "Persistence", 
        "enterprise_tech": "T1547.001", "ics_tech": None, "name": "Registry Run Keys / Startup Folder", "confidence": 95, "score": 15
    },
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run": {
        "finding": "Registry Run Key", "tactic": "TA0103", "tactic_name": "Persistence", 
        "enterprise_tech": "T1547.001", "ics_tech": None, "name": "Registry Run Keys / Startup Folder", "confidence": 95, "score": 20
    },
    "c2.dronefleet.net": {
        "finding": "C2 Domain", "tactic": "TA0111", "tactic_name": "Command and Control", 
        "enterprise_tech": "T1071", "ics_tech": "T0885", "name": "Application Layer Protocol -> Commonly Used Port", "confidence": 98, "score": 35
    },
    "XOR+Base64": {
        "finding": "Encoded Payload", "tactic": "TA0103", "tactic_name": "Evasion", 
        "enterprise_tech": "T1027", "ics_tech": None, "name": "Obfuscated Files or Information", "confidence": 90, "score": 20
    },
    "gps_spoof": {
        "finding": "GPS Spoofing", "tactic": "TA0106", "tactic_name": "Impair Process Control",
        "enterprise_tech": "T1005", "ics_tech": "T0831", "name": "Manipulation of Control", "confidence": 95, "score": 40
    },
    "battery_drain": {
        "finding": "Battery Drain Exploitation", "tactic": "TA0105", "tactic_name": "Impact",
        "enterprise_tech": "T1498", "ics_tech": "T0879", "name": "Damage to Property", "confidence": 90, "score": 40
    },
    "drone_agent": {
        "finding": "Service Creation", "tactic": "TA0103", "tactic_name": "Persistence", 
        "enterprise_tech": "T1547.001", "ics_tech": None, "name": "Service Creation Persistence", "confidence": 95, "score": 25
    },
    "FLEET_SYNC": {
        "finding": "Unauthorized State Synchronization", "tactic": "TA0106", "tactic_name": "Impair Process Control",
        "enterprise_tech": "T1489", "ics_tech": "T0869", "name": "Loss of State", "confidence": 90, "score": 30
    },
    "FLEET_COMMAND_PUSH": {
        "finding": "Rogue Command Injection", "tactic": "TA0104", "tactic_name": "Execution",
        "enterprise_tech": "T1059", "ics_tech": "T0885", "name": "Remote Control of Fleet", "confidence": 95, "score": 40
    },
    "custom_protocol_v1": {
        "finding": "Non-Standard Port Usage", "tactic": "TA0111", "tactic_name": "Command and Control",
        "enterprise_tech": "T1571", "ics_tech": "T0885", "name": "Command Relay", "confidence": 85, "score": 25
    }
}

ICS_IMPACT_MAPPING = {
    "T0806": ["Execution Environment Constraint"],
    "T0886": ["Autostart Survival Operations"],
    "T0866": ["Exploitation of Remote Services"],
    "T0885": ["Remote Control of Fleet", "Command Relay"],
    "T0831": ["Manipulation of Control"],
    "T0832": ["Manipulation of View", "Telemetry Falsification"]
}

ICS_TRANSLATION_RULES = {
    "T1071": {"ics": "T0869", "effect": "Loss of Telemetry"},
    "T1547.001": {"ics": "T0866", "effect": "Unauthorized Startup"},
    "T1027": {"ics": "T0832", "effect": "Manipulation of Control"},
    "T1005": {"ics": "T0832", "effect": "Manipulation of Control"},
    "T1498": {"ics": "T0879", "effect": "Damage to Property"}
}

ATTACK_TO_ENTERPRISE = {
    "gps_spoof": "T1565.001",
    "imu_drift": "T1565",
    "lidar_jamming": "T1498",
    "battery_drain": "T1496",
    "beacon": "T1071.001",
    "network_scan": "T1046",
    "payload_transfer": "T1105"
}

ENTERPRISE_TO_ICS = {
    "T1071.001": "T0855",
    "T1046": "T0846",
    "T1105": "T0867",
    "T1496": "T0814",
    "T1565.001": "T0832",
    "T1565": "T0831",
    "T1498": "T0828"
}

TRANSLATION_REASON = {
    "T1071.001": "HTTP beaconing observed in Enterprise layer indicates remote command delivery capability, therefore mapped to ICS T0855 Command Message.",
    "T1046": "Network scanning activity indicates reconnaissance against drone telemetry endpoints.",
    "T1105": "Ingress tool transfer is utilized to deliver malicious payloads to the ICS asset, mapping to ICS T0867.",
    "T1496": "Battery drain attacks map to Resource Exhaustion in ICS.",
    "T1565.001": "GPS spoofing directly manipulates navigation control, mapping to Manipulation of View/Control.",
    "T1565": "IMU drift injection manipulates data affecting control systems.",
    "T1498": "Lidar jamming maps to ICS sensor disruption."
}
