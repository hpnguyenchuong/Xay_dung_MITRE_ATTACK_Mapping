import os
import json
import sqlite3
from datetime import datetime

from utils.constants import *
from utils.helpers import *
from core.state import *


def build_navigator_layer(name, findings, attack_type="Unknown", domain="enterprise-attack"):
    tech_map = {}
    for f in findings:
        # Determine technique ID based on domain
        if domain == "ics-attack":
            t_id = f.get("ics_tech_id")
        else:
            t_id = f.get("technique_id") or f.get("enterprise_tech_id")
            
        if not t_id: continue
        
        score = f.get("confidence") or 50
        occ = f.get("occ", 1)
        tech_name = f.get("technique_name", "Unknown")
        tactic_name = f.get("tactic_name", "Unknown")
        atk_type = f.get("attack_type", attack_type)
        
        if t_id not in tech_map:
            tech_map[t_id] = {
                "scores": [score] * occ,
                "occ": occ,
                "attack_types": {atk_type},
                "tech_name": tech_name,
                "tactic_name": tactic_name,
                "drone_ids": {f.get("drone_id")} if f.get("drone_id") else set(),
                "evidence": {f.get("evidence")} if f.get("evidence") else set(),
                "reason": {f.get("reason")} if f.get("reason") else set(),
                "ent_id": f.get("technique_id") or f.get("enterprise_tech_id"),
                "ics_id": f.get("ics_tech_id"),
                "timestamp": f.get("timestamp")
            }
        else:
            tech_map[t_id]["scores"].extend([score] * occ)
            tech_map[t_id]["occ"] += occ
            tech_map[t_id]["attack_types"].add(atk_type)
            if f.get("drone_id"): tech_map[t_id]["drone_ids"].add(f.get("drone_id"))
            if f.get("evidence"): tech_map[t_id]["evidence"].add(f.get("evidence"))
            if f.get("reason"): tech_map[t_id]["reason"].add(f.get("reason"))

    techniques = []
    for t_id, data in tech_map.items():
        avg_score = sum(data["scores"]) / len(data["scores"]) if data["scores"] else 0
        
        # Explainability fields
        comment = ""
        drone_str = ", ".join(d for d in data['drone_ids'] if d)
        if drone_str:
            comment += f"Drone ID: {drone_str}\n\n"
            
        atk_types_str = ", ".join(a for a in data['attack_types'] if a)
        if atk_types_str and atk_types_str != "Unknown":
            comment += f"Attack Type: {atk_types_str}\n\n"
            
        ent_str = data['ent_id'] if data['ent_id'] else "N/A"
        ics_str = data['ics_id'] if data['ics_id'] else "N/A"
        comment += f"Enterprise Technique: {ent_str}\n\n"
        comment += f"ICS Technique: {ics_str}\n\n"
        comment += f"Technique Name:\n{data['tech_name']}\n\n"
        
        # Translation Reason Engine
        trans_reason = TRANSLATION_REASON.get(ent_str)
        if not trans_reason and data['ics_id'] and data['ent_id']:
            trans_reason = f"Enterprise behavior {ent_str} mapped to ICS {ics_str} due to semantic overlap."
            
        if trans_reason:
            comment += f"Translation Reason:\n{trans_reason}\n\n"
            
        evs = [e for e in data["evidence"] if e and e != "N/A"]
        if evs:
            comment += f"Evidence:\n{chr(10).join(evs)[:150]}\n\n"
            
        comment += f"Confidence:\n{int(avg_score)}%\n\n"
        comment += f"Occurrences:\n{data['occ']}"
        
        techniques.append({
            "techniqueID": t_id,
            "score": int(avg_score),
            "enabled": True,
            "showSubtechniques": True,
            "comment": comment.strip(),
            "color": get_color(data["tactic_name"])
        })
        
    return {
        "name": name,
        "version": "4.5",
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5"
        },
        "domain": domain,
        "description": f"MITRE ATT&CK Mapping for {name}",
        "sorting": 0,
        "layout": {
            "layout": "side"
        },
        "hideDisabled": False,
        "techniques": techniques
    }

def export_drone_layer(drone_id):
    conn = sqlite3.connect(DB_FILE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    findings = conn.execute("SELECT technique_id, enterprise_tech_id, ics_tech_id, MAX(confidence) as confidence, MAX(evidence) as evidence, tactic_name, MAX(name) as technique_name, COUNT(*) as occ, MAX(timestamp) as timestamp, MAX(reason) as reason, drone_id FROM attack_mapping WHERE drone_id=? GROUP BY technique_id", (drone_id,)).fetchall()
    
    atk_row = conn.execute("SELECT attack_type FROM active_attacks WHERE drone_id=? ORDER BY started_at DESC LIMIT 1", (drone_id,)).fetchone()
    attack_type = atk_row["attack_type"] if atk_row else "Unknown"
    
    if findings:
        # Enterprise Layer
        layer_ent = build_navigator_layer(f"Drone {drone_id} Enterprise", [dict(f) for f in findings], attack_type, domain="enterprise-attack")
        filepath_ent = os.path.join(BASE_DIR, "exports", "drones", f"{drone_id}_enterprise.json")
        with open(filepath_ent, "w", encoding="utf-8") as f:
            json.dump(layer_ent, f, indent=2, ensure_ascii=False)
            
        # ICS Layer
        layer_ics = build_navigator_layer(f"Drone {drone_id} ICS", [dict(f) for f in findings], attack_type, domain="ics-attack")
        filepath_ics = os.path.join(BASE_DIR, "exports", "drones", f"{drone_id}_ics.json")
        with open(filepath_ics, "w", encoding="utf-8") as f:
            json.dump(layer_ics, f, indent=2, ensure_ascii=False)
    conn.close()

def export_campaign_layers():
    conn = sqlite3.connect(DB_FILE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    tactics = conn.execute("SELECT DISTINCT tactic_name FROM attack_mapping WHERE tactic_name IS NOT NULL").fetchall()
    
    all_campaign_findings = []
    
    for row in tactics:
        tactic = row["tactic_name"]
        findings = conn.execute("SELECT technique_id, enterprise_tech_id, ics_tech_id, MAX(confidence) as confidence, MAX(evidence) as evidence, tactic_name, MAX(name) as technique_name, COUNT(*) as occ, MAX(timestamp) as timestamp, MAX(reason) as reason FROM attack_mapping WHERE tactic_name=? GROUP BY technique_id", (tactic,)).fetchall()
        
        all_campaign_findings.extend(findings)
        
        campaign_name = tactic.lower().replace(" ", "_")
        layer = build_navigator_layer(f"{tactic} Campaign", [dict(f) for f in findings], f"Campaign Aggregation")
        filepath = os.path.join(BASE_DIR, "exports", "campaigns", f"{campaign_name}_campaign.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(layer, f, indent=2, ensure_ascii=False)
            
    if all_campaign_findings:
        layer_full = build_navigator_layer("Full Campaign", [dict(f) for f in all_campaign_findings], "Campaign Aggregation")
        filepath_full = os.path.join(BASE_DIR, "exports", "campaigns", "full_campaign.json")
        with open(filepath_full, "w", encoding="utf-8") as f:
            json.dump(layer_full, f, indent=2, ensure_ascii=False)
            
    conn.close()

def export_fleet_layer():
    conn = sqlite3.connect(DB_FILE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    findings = conn.execute("SELECT technique_id, enterprise_tech_id, ics_tech_id, MAX(confidence) as confidence, MAX(evidence) as evidence, tactic_name, MAX(name) as technique_name, COUNT(*) as occ, MAX(timestamp) as timestamp, MAX(reason) as reason FROM attack_mapping GROUP BY technique_id").fetchall()
    if findings:
        layer_ent = build_navigator_layer("Fleet Enterprise", [dict(f) for f in findings], "Fleet Aggregation", domain="enterprise-attack")
        filepath_ent = os.path.join(BASE_DIR, "exports", "fleet", "fleet_enterprise.json")
        with open(filepath_ent, "w", encoding="utf-8") as f:
            json.dump(layer_ent, f, indent=2, ensure_ascii=False)
            
        layer_ics = build_navigator_layer("Fleet ICS", [dict(f) for f in findings], "Fleet Aggregation", domain="ics-attack")
        filepath_ics = os.path.join(BASE_DIR, "exports", "fleet", "fleet_ics.json")
        with open(filepath_ics, "w", encoding="utf-8") as f:
            json.dump(layer_ics, f, indent=2, ensure_ascii=False)
    conn.close()

def export_incident_layer(attack_id):
    if not attack_id: return
    conn = sqlite3.connect(DB_FILE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    
    atk_row = conn.execute("SELECT attack_type FROM active_attacks WHERE attack_id=? LIMIT 1", (attack_id,)).fetchone()
    attack_type = atk_row["attack_type"] if atk_row else "Unknown"
    
    # Lấy event gần nhất
    findings_raw = conn.execute("SELECT id, technique_id, enterprise_tech_id, ics_tech_id, confidence, evidence, tactic_name, name as technique_name, drone_id, timestamp, reason FROM attack_mapping ORDER BY id DESC LIMIT 1").fetchall()
    
    def get_translation_reason(ent, ics):
        if not ent or not ics: return None
        if "T1071" in ent and "T0855" in ics:
            return "HTTP beaconing observed in Enterprise layer indicates remote command delivery capability, therefore mapped to ICS T0855 Command Message."
        if "T1046" in ent:
            return f"Network service scanning ({ent}) directly translates to ICS Network Sniffing ({ics}) to identify drone telemetry endpoints."
        if "T1105" in ent:
            return f"Ingress tool transfer ({ent}) is utilized to deliver malicious payloads to the ICS asset, mapping to ICS {ics}."
        if "T1027" in ent:
            return f"Obfuscated files or information ({ent}) maps to evasion techniques impacting the ICS environment ({ics})."
        return f"Enterprise behavior {ent} maps to ICS {ics} due to semantic overlap in cyber-physical impact."
    
    for f in findings_raw:
        # Xuất RAW file (chuẩn nghiên cứu)
        raw_filepath = os.path.join(BASE_DIR, "exports", "raw", f"{attack_id}_raw.json")
        
        evidence_list = f["evidence"].split("\n") if f["evidence"] else []
        trans_reason = get_translation_reason(f["technique_id"], f["ics_tech_id"])
        
        # Build Semantic Path
        semantic_path = []
        if f["technique_id"]:
            semantic_path.append({
                "layer": "IT",
                "technique": f["technique_id"],
                "description": f["technique_name"]
            })
            
        semantic_path.append({
            "layer": "Communication",
            "description": "Remote Command Delivery" if "T1071" in (f["technique_id"] or "") else "Semantic Overlap Channel"
        })
        
        if f["ics_tech_id"]:
            semantic_path.append({
                "layer": "Physical",
                "technique": f["ics_tech_id"],
                "description": "ICS Control Message" if f["ics_tech_id"] == "T0855" else "Physical Effect"
            })
            
        # extract matched rule
        matched_rule = "UNKNOWN"
        if f["reason"] and "Matched Rule " in f["reason"]:
            matched_rule = f["reason"].split("Matched Rule ")[1].split(":")[0]
            
        raw_data = {
            "attack_id": attack_id,
            "drone_id": f["drone_id"],
            "sample": "Q2_DroneFlood",
            "attack_type": attack_type,
            "enterprise_technique": {
                "id": f["technique_id"],
                "name": f["technique_name"]
            },
            "ics_technique": {
                "id": f["ics_tech_id"],
                "name": "Command Message" if f["ics_tech_id"] == "T0855" else "ICS Control"
            }
        }
        
        if trans_reason:
            raw_data["translation_reason"] = trans_reason
            
        raw_data.update({
            "confidence": f["confidence"],
            "evidence": evidence_list,
            "matched_rule": matched_rule,
            "timestamp": f["timestamp"],
            "semantic_path": semantic_path
        })
        
        with open(raw_filepath, "w", encoding="utf-8") as r:
            json.dump(raw_data, r, indent=2, ensure_ascii=False)
            
        # NÂNG CẤP: Sinh file JSON MITRE Navigator layer cho cuộc tấn công (Incident)
        # và lưu vào reports/attacks để Forensic Report UI có thể hiển thị
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        drone_id = f["drone_id"]
        
        # Build Navigator layer cho incident
        incident_layer = build_navigator_layer(
            f"Incident {attack_id}", 
            [dict(f)], 
            attack_type, 
            domain="enterprise-attack"
        )
        
        # Lưu vào exports/incidents
        inc_filepath = os.path.join(BASE_DIR, "exports", "incidents", f"DRONE-{drone_id}_ATTACK-{attack_id}_{ts}.json")
        with open(inc_filepath, "w", encoding="utf-8") as r:
            json.dump(incident_layer, r, indent=2, ensure_ascii=False)
            
        # Copy sang reports/attacks để Frontend Dashboard có thể list file
        reports_attacks_dir = os.path.join(BASE_DIR, "reports", "attacks")
        os.makedirs(reports_attacks_dir, exist_ok=True)
        report_filepath = os.path.join(reports_attacks_dir, f"DRONE-{drone_id}_ATTACK-{attack_id}_{ts}.json")
        with open(report_filepath, "w", encoding="utf-8") as r:
            json.dump(incident_layer, r, indent=2, ensure_ascii=False)
            
    conn.close()

def generate_navigator_exports(drone_id=None, attack_id=None):
    try:
        os.makedirs(os.path.join(BASE_DIR, "exports", "drones"), exist_ok=True)
        os.makedirs(os.path.join(BASE_DIR, "exports", "campaigns"), exist_ok=True)
        os.makedirs(os.path.join(BASE_DIR, "exports", "incidents"), exist_ok=True)
        os.makedirs(os.path.join(BASE_DIR, "exports", "raw"), exist_ok=True)
        os.makedirs(os.path.join(BASE_DIR, "exports", "fleet"), exist_ok=True)
        
        if drone_id:
            export_drone_layer(drone_id)
            
        if attack_id:
            export_incident_layer(attack_id)
            
        export_campaign_layers()
        export_fleet_layer()
    except Exception as e:
        print(f"Error generating navigator exports: {e}")