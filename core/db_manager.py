import os, json, time, sqlite3, threading, base64, socket, hashlib, math, re, queue
from datetime import datetime
from typing import Dict
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from utils.constants import *
from utils.helpers import *
from core.state import *
from core.mapping_engine import mitre_engine

def init_forensic_db():
    with db_write_lock:
        try:
            cursor = db_conn.cursor()
            
            # Tables are no longer dropped to preserve data
            
            # Module 1: Malware Profile Database
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS malware_profiles (
                    drone_id TEXT PRIMARY KEY, family TEXT, version TEXT, campaign TEXT,
                    c2_protocol TEXT, obfuscation TEXT, capabilities TEXT, first_seen TEXT, last_seen TEXT
                )
            """)
            
            # Telemetry Table (Modified)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, drone_id TEXT, ip TEXT, battery INTEGER,
                    altitude INTEGER, speed INTEGER, gps TEXT, artifact_hash TEXT, timestamp TEXT,
                    network_speed INTEGER, signal_strength INTEGER, max_altitude INTEGER, codename TEXT, temp INTEGER, satellites INTEGER, beacon_interval REAL
                )
            """)
            
            # Module 3: IOC Database
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, drone_id TEXT, type TEXT, value TEXT, source TEXT, timestamp TEXT
                )
            """)
            
            # Module 4: MITRE Mapping Engine
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_mapping (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, drone_id TEXT, tactic TEXT, tactic_name TEXT, technique_id TEXT, enterprise_tech_id TEXT, ics_tech_id TEXT, name TEXT, confidence INTEGER, reason TEXT, evidence TEXT, timestamp TEXT
                )
            """)
            cursor.execute("PRAGMA table_info(attack_mapping)")
            attack_cols = [info[1] for info in cursor.fetchall()]
            for col, col_type in [("tactic", "TEXT"), ("tactic_name", "TEXT"), ("enterprise_tech_id", "TEXT"), ("ics_tech_id", "TEXT"), ("confidence", "INTEGER"), ("reason", "TEXT"), ("evidence", "TEXT")]:
                if col not in attack_cols:
                    cursor.execute(f"ALTER TABLE attack_mapping ADD COLUMN {col} {col_type}")
            
            # Module 10: Timeline
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, drone_id TEXT, event_type TEXT, message TEXT, timestamp TEXT
                )
            """)
            
            # Module 11: Threat Score & Risk
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS drone_risk (
                    drone_id TEXT PRIMARY KEY, score INTEGER, breakdown TEXT, last_updated TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS active_attacks (
                    attack_id TEXT PRIMARY KEY,
                    drone_id TEXT,
                    attack_type TEXT,
                    status TEXT,
                    started_at TEXT,
                    params TEXT
                )
            """)
            
            # Module 12: IOC Correlation
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ioc_attack_mapping (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, drone_id TEXT, ioc_value TEXT, technique_id TEXT, description TEXT, timestamp TEXT
                )
            """)
            cursor.execute("PRAGMA table_info(ioc_attack_mapping)")
            columns = [info[1] for info in cursor.fetchall()]
            if "confidence" not in columns:
                cursor.execute("ALTER TABLE ioc_attack_mapping ADD COLUMN confidence INTEGER DEFAULT 95")
            if "campaign" not in columns:
                cursor.execute("ALTER TABLE ioc_attack_mapping ADD COLUMN campaign TEXT")
            
            # Module 13: RE Findings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS re_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, drone_id TEXT, artifact_address TEXT, artifact_type TEXT, finding TEXT, technique_id TEXT, enterprise_tech_id TEXT, ics_tech_id TEXT, behavior TEXT, evidence TEXT, mapping_reason TEXT, confidence INTEGER, timestamp TEXT, source TEXT
                )
            """)
            cursor.execute("PRAGMA table_info(re_findings)")
            re_cols = [info[1] for info in cursor.fetchall()]
            for col, col_type in [("artifact_address", "TEXT"), ("artifact_type", "TEXT"), ("enterprise_tech_id", "TEXT"), ("ics_tech_id", "TEXT"), ("mapping_reason", "TEXT"), ("confidence", "INTEGER"), ("source", "TEXT"), ("validation_level", "TEXT"), ("rejected_candidates", "TEXT"), ("confidence_breakdown", "TEXT"), ("campaign_stage", "TEXT")]:
                if col not in re_cols:
                    cursor.execute(f"ALTER TABLE re_findings ADD COLUMN {col} {col_type}")
                    
            # Evidence Chain
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence_chain (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, drone_id TEXT, artifact TEXT, behavior TEXT, enterprise_technique TEXT, ics_technique TEXT, operational_effect TEXT, timestamp TEXT
                )
            """)
            
            # Campaign Timeline
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS campaign_timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, drone_id TEXT, time TEXT, stage TEXT, artifact TEXT, technique TEXT
                )
            """)
            
            # Mapping History
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mapping_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, artifact TEXT, technique TEXT
                )
            """)
            
            # Pre-populate campaign timeline for the academic presentation
            cursor.execute("SELECT COUNT(*) as count FROM campaign_timeline")
            if cursor.fetchone()["count"] == 0:
                timeline_data = [
                    ("00:00:00", "DRONE-ALL", "Initial Access", "c2_connect.exe", "T1071 (Application Layer Protocol)"),
                    ("00:15:30", "DRONE-01", "Persistence", "run_key_add", "T1547.001 (Registry Run Keys)"),
                    ("00:30:15", "DRONE-07", "Collection", "telemetry_dump", "T1005 (Data from Local System)"),
                    ("00:45:00", "DRONE-ALL", "Impact", "gps_spoof", "T0831 (Manipulation of Control)"),
                    ("00:55:20", "DRONE-03", "Exfiltration", "TCP Flood", "T1041 (Exfiltration Over C2 Channel)")
                ]
                cursor.executemany("INSERT INTO campaign_timeline (drone_id, time, stage, artifact, technique) VALUES (?, ?, ?, ?, ?)", [(d, t, s, a, tech) for t, d, s, a, tech in timeline_data])
                
            # Alerts Engine & Cases
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, drone_id TEXT, severity TEXT, title TEXT, description TEXT, timestamp TEXT, status TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id INTEGER PRIMARY KEY AUTOINCREMENT, drone_id TEXT, alert_id INTEGER, priority TEXT, assigned_to TEXT, resolution_notes TEXT, status TEXT, created_time TEXT
                )
            """)
            
            # Phase 5: Ultimate Research Framework Tables
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS behavior_rules (
                    artifact TEXT PRIMARY KEY,
                    behavior TEXT
                )
            """)

            cursor.execute("SELECT COUNT(*) as count FROM behavior_rules")
            if cursor.fetchone()["count"] == 0:
                behaviors = [
                    ("DF_MUTEX_01", "Persistence"),
                    ("c2.dronefleet.net", "Command and Control"),
                    ("XOR+Base64", "Evasion"),
                    ("gps_spoof", "Navigation Manipulation"),
                    ("battery_drain", "Battery Drain Exploitation"),
                    ("FLEET_SYNC", "Fleet Synchronization"),
                    ("FLEET_COMMAND_PUSH", "Lateral Movement"),
                    ("custom_protocol_v1", "Custom Protocol Usage"),
                    ("DF_REG_RUN", "Persistence"),
                    ("DF_STARTUP_CFG", "Persistence")
                ]
                cursor.executemany("INSERT INTO behavior_rules VALUES (?, ?)", behaviors)

            # Mapping Rule Repository
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mapping_rules (
                    rule_id TEXT PRIMARY KEY, artifact_regex TEXT, artifact_type TEXT, behavior TEXT, enterprise_technique TEXT, ics_technique TEXT, confidence_weight INTEGER, rule_priority INTEGER, reference TEXT
                )
            """)
            
            # Ground Truth Dataset
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ground_truth_mapping (
                    artifact_pattern TEXT PRIMARY KEY, expected_enterprise TEXT, expected_ics TEXT, analyst_note TEXT, source_reference TEXT, validation_level TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dataset_provenance (
                    case_id TEXT PRIMARY KEY,
                    case_name TEXT,
                    origin TEXT,
                    description TEXT,
                    validation_level TEXT
                )
            """)

            cursor.execute("SELECT COUNT(*) as count FROM dataset_provenance")
            if cursor.fetchone()["count"] == 0:
                provenance = [
                    ("clean_case", "Clean Case", "Baseline Drone", "Normal drone telemetry without malicious artifacts", "L3"),
                    ("persistence_case", "Persistence Case", "Simulated RE Findings", "Persistence artifacts such as mutex and startup entries", "L3"),
                    ("gps_drift_case", "GPS Drift Case", "Simulated Cyber-Physical Scenario", "Navigation manipulation and GPS spoofing scenario", "L2"),
                    ("droneflood_case", "DroneFlood Campaign", "Custom C2 Simulation", "Full campaign with C2, fleet control, and mission impact", "L3")
                ]
                cursor.executemany("INSERT INTO dataset_provenance VALUES (?, ?, ?, ?, ?)", provenance)
            
            # Populate Default Rules
            cursor.execute("SELECT COUNT(*) as count FROM mapping_rules")
            if cursor.fetchone()["count"] == 0:
                rules = [
                    ("RULE_001", r"DF_MUTEX_.*", "Memory Dump", "Persistence", "T1547.001", None, 95, 100, "MITRE ATT&CK Enterprise"),
                    ("RULE_002", r".*\.dronefleet\.net", ".rdata", "Application Layer C2", "T1071", "T0885", 90, 90, "MITRE ATT&CK Enterprise/ICS"),
                    ("RULE_003", r"telemetry_exfil", "Network Flow", "Exfiltration", "T1041", "T0811", 85, 80, "MITRE ATT&CK Enterprise/ICS"),
                    ("RULE_004", r"XOR\+Base64|XOR_KEY_.*|encoded_payload", "Config Block", "Evasion", "T1027", None, 95, 95, "MITRE ATT&CK Enterprise"),
                    ("RULE_005", r"drone_agent", "Process List", "Service Execution", "T1569.002", None, 80, 50, "MITRE ATT&CK Enterprise"),
                    ("RULE_006", r"gps_spoof", "Memory Artifact", "Navigation Manipulation", "T1565.001", "T0832", 90, 85, "MITRE ATT&CK ICS"),
                    ("RULE_007", r"imu_drift", "Memory Artifact", "IMU Manipulation", "T1565", "T0831", 85, 80, "MITRE ATT&CK ICS"),
                    ("RULE_008", r"battery_drain", "Memory Artifact", "Battery Drain", "T1496", "T0814", 95, 90, "MITRE ATT&CK Enterprise/ICS"),
                    ("RULE_009", r"lidar_jamming", "Memory Artifact", "Sensor Jamming", "T1498", "T0828", 90, 85, "MITRE ATT&CK ICS"),
                    ("RULE_010", r"collision", "Memory Artifact", "Kinetic Impact", "T0831", "T0831", 100, 95, "MITRE ATT&CK ICS"),
                    ("RULE_011", r"emergency_land", "Memory Artifact", "Kinetic Impact", "T0831", "T0831", 100, 95, "MITRE ATT&CK ICS")
                ]
                cursor.executemany("INSERT INTO mapping_rules VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rules)

            cursor.execute(r"""
                UPDATE mapping_rules
                SET artifact_regex='XOR\+Base64|XOR_KEY_.*|encoded_payload'
                WHERE rule_id='RULE_004'
            """)

            cursor.execute("""
                UPDATE mapping_rules
                SET behavior='Service Execution',
                    enterprise_technique='T1569.002',
                    ics_technique=NULL,
                    reference='MITRE ATT&CK Enterprise'
                WHERE rule_id='RULE_005'
            """)

            # Populate Ground Truth
            cursor.execute("SELECT COUNT(*) as count FROM ground_truth_mapping")
            if cursor.fetchone()["count"] == 0:
                gt = [
                    ("DF_MUTEX_01", "T1547.001", "T0866", "Mutex created to ensure persistence across reboots", "Memory Analysis", "High"),
                    ("c2.dronefleet.net", "T1071", "T0885", "Hardcoded C2 domain found in binary", "Static Analysis", "High"),
                    ("XOR+Base64", "T1027", "T0832", "XOR+Base64 encoded config block", "Static Analysis", "High"),
                    ("telemetry_dump", "T1041", "T0811", "Bulk telemetry sent over C2", "Dynamic Analysis", "Medium"),
                    ("drone_agent", "T1055", "T0866", "Malicious process spawned", "Dynamic Analysis", "Medium")
                ]
                cursor.executemany("INSERT INTO ground_truth_mapping VALUES (?, ?, ?, ?, ?, ?)", gt)

            cursor.execute("""
                UPDATE ground_truth_mapping
                SET artifact_pattern='XOR+Base64', expected_ics='T0832', analyst_note='XOR+Base64 encoded config block'
                WHERE artifact_pattern='XOR_KEY_B64'
            """)

            
            db_conn.commit()
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"DB Init Error: {e}")

def db_worker():
    global server_processed_packets
    while True:
        try:
            item = db_queue.get()
            if item is None: break
            drone_id, client_ip, p_hash, packet, packet_type, t_now = item
            
            if packet_type == "telemetry":
                with db_write_lock:
                    mitre_engine.analyze_packet(drone_id, client_ip, p_hash, packet)
                    try:
                        cursor = db_conn.cursor()
                        cursor.execute("""
                            INSERT INTO telemetry (
                                drone_id, ip, battery, altitude, speed, gps, artifact_hash, timestamp,
                                network_speed, signal_strength, max_altitude, codename, temp, satellites, beacon_interval
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            drone_id, client_ip, packet.get("battery", 0), packet.get("altitude", 0),
                            packet.get("speed", 0), packet.get("gps", "0,0"), p_hash, t_now,
                            packet.get("network_speed", 100), packet.get("signal_strength", -50),
                            packet.get("max_altitude", 300), packet.get("codename", "Unknown"),
                            packet.get("temp", 40), packet.get("satellites", 10), packet.get("beacon_interval", packet.get("status", {}).get("beacon_interval", 5.0))
                        ))
                        db_conn.commit()
                    except Exception as e:
                        print(f"Telemetry DB Error: {e}")
            else:
                with db_write_lock:
                    mitre_engine.analyze_packet(drone_id, client_ip, p_hash, packet)
                    db_conn.commit()
            
            with server_stats_lock:
                server_processed_packets += 1
                
            db_queue.task_done()
        except Exception as e:
            print(f"Worker Error: {e}")

def load_re_findings_from_json():
    """Load RE findings từ file JSON vào database theo cấu trúc phân loại attack_type"""
    try:
        file_path = os.path.join(BASE_DIR, "datasets", "re_findings.json")
        if not os.path.exists(file_path):
            file_path = "datasets/re_findings.json"
            
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        cursor = db_conn.cursor()
        
        # Prevent duplication
        cursor.execute("SELECT COUNT(*) as count FROM re_findings WHERE mapping_reason LIKE 'RE Finding:%'")
        if cursor.fetchone()["count"] > 0:
            return True
            
        total_loaded = 0
        for attack_type, artifact_list in data.get("artifacts_by_attack_type", {}).items():
            for artifact in artifact_list:
                cursor.execute("""
                    INSERT INTO re_findings 
                    (finding, artifact_type, evidence, source, validation_level, 
                     confidence, enterprise_tech_id, ics_tech_id, behavior, 
                     mapping_reason, timestamp, drone_id, artifact_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    artifact.get("name"),
                    artifact.get("type"),
                    artifact.get("evidence"),
                    artifact.get("source", "Telemetry/RE Analysis"),
                    artifact.get("validation_level", "L3"),
                    artifact.get("confidence", 95),
                    artifact.get("enterprise") or artifact.get("enterprise_tech"),
                    artifact.get("ics") or artifact.get("ics_tech"),
                    attack_type.replace("_", " ").title(),
                    f"RE Finding: {attack_type} attack vector",
                    datetime.now().isoformat(),
                    "DRONE-ALL",
                    artifact.get("address", "Unknown")
                ))
                total_loaded += 1
                
        db_conn.commit()
        print(f"[+] Loaded {total_loaded} RE findings categorized by attack types")
        return True
    except Exception as e:
        print(f"[!] Failed to load RE findings: {e}")
        return False