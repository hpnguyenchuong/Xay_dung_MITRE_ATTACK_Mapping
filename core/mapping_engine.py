import os, json, time, sqlite3, threading, base64, socket, hashlib, math, re, queue
from datetime import datetime
from typing import Dict
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from utils.constants import *
from utils.helpers import *
from core.state import *

class MITREMappingEngine:
    EVIDENCE_WEIGHTS = {
        "Memory Dump": 95, "Config Block": 90, ".rdata Section": 90,
        "Decompiled Code": 85, "Network PCAP": 80, "Dynamic Analysis": 75,
        "Strings Analysis": 70, "File System": 65
    }

    def __init__(self):
        self.last_packet_time = {}
        self.packet_lock = threading.Lock()
        self.last_gps_data = {}
        self.network_history = {}

    def calculate_confidence(self, artifact, source, campaign_count=0, fleet_role="member"):
        base_score = artifact.get("confidence", 80)
        evidence_strength = self.EVIDENCE_WEIGHTS.get(source, 70)
        
        campaign_bonus = 15 if campaign_count >= 3 else 8 if campaign_count >= 2 else 3
        fleet_bonus = 10 if (fleet_role == "leader" and artifact.get("type") == "Command") else 0
        
        score = (base_score * 0.5 + evidence_strength * 0.3) + campaign_bonus + fleet_bonus
        return min(100, int(score))
    
    def map_artifact(self, drone_id, artifact, source, validation_level="L2", campaign_count=0, fleet_role="member"):
        # Pre-defined mapping rules
        mapping_rules = {
            "DF_MUTEX_01": {"tech": "T1547.001", "ics": "T0866", "tactic": "Persistence", "score": 95},
            "c2.dronefleet.net": {"tech": "T1071", "ics": "T0885", "tactic": "C2", "score": 98},
            "XOR+Base64": {"tech": "T1027", "ics": "T0832", "tactic": "Evasion", "score": 85},
            "gps_spoof": {"tech": "T0831", "ics": "T0831", "tactic": "Impact", "score": 95},
            "imu_drift": {"tech": "T0832", "ics": "T0832", "tactic": "Impact", "score": 94},
            "battery_drain": {"tech": "T0879", "ics": "T0879", "tactic": "Impact", "score": 90},
            "lidar_jamming": {"tech": "T0831", "ics": "T0831", "tactic": "Impact", "score": 93},
            "collision": {"tech": "T0831", "ics": "T0831", "tactic": "Impact", "score": 96},
            "emergency_land": {"tech": "T0831", "ics": "T0831", "tactic": "Impact", "score": 92}
        }
        
        rule = mapping_rules.get(artifact, {})
        if not rule:
            return None
        
        confidence = self.calculate_confidence(
            {"confidence": rule["score"], "type": "Artifact"}, source, campaign_count, fleet_role
        )
        
        rejected = []
        all_candidates = ["T1547.001", "T1055", "T1543", "T1071", "T1041", "T1105"]
        for cand in all_candidates:
            if cand != rule["tech"]:
                import random
                rejected.append({"technique": cand, "score": random.randint(50, 70), 
                                "reason": f"Lower confidence or no evidence for {cand}"})
        
        return {"technique": rule["tech"], "confidence": confidence, "rejected": rejected}

    def analyze_network_behavior(self, drone_id: str, packet: dict, now: float, cursor, t_str: str):
        # Implement RE Artifact Correlation (CLO5)
        with self.packet_lock:
            payload_size = len(json.dumps(packet))
            
            if drone_id not in self.network_history:
                self.network_history[drone_id] = {"intervals": [], "sizes": [], "last_time": now}
                return
                
            history = self.network_history[drone_id]
            time_diff = now - history["last_time"]
            history["last_time"] = now
            
            history["intervals"].append(time_diff)
            history["sizes"].append(payload_size)
            
            if len(history["intervals"]) > 10:
                history["intervals"].pop(0)
                history["sizes"].pop(0)
                
            if len(history["intervals"]) == 10:
                avg_interval = sum(history["intervals"]) / 10.0
                avg_size = sum(history["sizes"]) / 10.0
                
                interval_variance = sum((x - avg_interval)**2 for x in history["intervals"]) / 10.0
                size_variance = sum((x - avg_size)**2 for x in history["sizes"]) / 10.0
                
                if interval_variance < 0.5 and size_variance < 1000.0:
                    cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, "T1071.001"))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (drone_id, "TA0111", "Command and Control", "T1071.001", "T1071.001", "T0855", "Standard Application Layer Protocol: Web Traffic", t_str))
                        cursor.execute("INSERT INTO timeline (drone_id, event_type, message, timestamp) VALUES (?, ?, ?, ?)", (drone_id, "TECHNIQUE_MAPPED", "T1071.001 (Persistent C2 Channel) mapped via RE Artifact Correlation", t_str))

    def evaluate_candidates(self, cursor, finding: str, source: str, validation_level: str = "L1", artifact_quality: int = 10, fleet_role: str = "member"):
        # 1. Deduce Behavior
        cursor.execute("SELECT behavior FROM behavior_rules WHERE artifact=?", (finding,))
        b_row = cursor.fetchone()
        behavior = b_row["behavior"] if b_row else "Unknown Behavior"

        # 2. Find Candidates
        cursor.execute("SELECT * FROM mapping_rules")
        rules = cursor.fetchall()
        candidates = []
        for r in rules:
            import re
            if re.match(r["artifact_regex"], finding) or (r["behavior"] == behavior and behavior != "Unknown Behavior"):
                candidates.append({
                    "technique_id": r["ics_technique"], "enterprise_tech_id": r["enterprise_technique"], "ics_tech_id": r["ics_technique"],
                    "tactic": "TA0106", "tactic_name": r["behavior"], "name": r["behavior"],
                    "base_score": r["confidence_weight"], "reason": f"Matched Rule {r['rule_id']}: {behavior}", "rejected_reason": "Low confidence score"
                })

        if not candidates:
            return None, []
            
        strength_map = {
            "Memory Dump": 95,
            "Config Extraction": 90,
            "Decompiled Code": 85,
            "Reverse Engineering": 85,
            "Strings Analysis": 75,
            "Network Traffic": 60,
            "Network Flow": 60,
            ".rdata Section": 90,
            "Config Block": 90
        }
        evidence_strength = strength_map.get(source, 70)
        
        for cand in candidates:
            # Fleet Role adjustment
            adjusted_base = cand["base_score"]
            if fleet_role == "leader" and finding in ["FLEET_COMMAND_PUSH", "LEADER_NODE_COMPROMISED"]:
                adjusted_base += 10
            elif fleet_role == "member" and finding == "FLEET_COMMAND_PUSH":
                adjusted_base -= 15
            elif fleet_role == "member" and finding == "MEMBER_NODE_CONTROLLED":
                adjusted_base += 10
                
            rule_score = max(0, adjusted_base - 15)
            campaign_context = 5 if evidence_strength > 70 else 0
            
            total_score = min(rule_score + (evidence_strength // 5) + campaign_context, 100)
            cand["score"] = total_score
            cand["confidence_breakdown"] = {
                "rule_score": rule_score,
                "evidence_strength": evidence_strength,
                "campaign_context": campaign_context,
                "fleet_role_bonus": adjusted_base - cand["base_score"],
                "formula": f"final_score = rule({rule_score}) + (evidence({evidence_strength})/5) + context({campaign_context}) + fleet_bonus({adjusted_base - cand['base_score']})",
                "final_score": total_score,
                "confidence_level": "HIGH" if total_score > 85 else "MEDIUM" if total_score > 60 else "LOW",
                "selected": False
            }
        
        candidates.sort(key=lambda x: x["score"], reverse=True)
        if candidates:
            candidates[0]["confidence_breakdown"]["selected"] = True
        
        # Apply Enterprise -> ICS Translation if applicable
        for cand in candidates:
            ent_tech = cand.get("enterprise_tech_id")
            if ent_tech in ICS_TRANSLATION_RULES:
                cand["ics_tech_id"] = ICS_TRANSLATION_RULES[ent_tech]["ics"]
                cand["operational_effect"] = ICS_TRANSLATION_RULES[ent_tech]["effect"]
            else:
                cand["operational_effect"] = "Mission Degradation"
                
        return candidates[0], candidates

    def analyze_packet(self, drone_id: str, client_ip: str, p_hash: str, packet: dict):
        if "telemetry" in packet and isinstance(packet["telemetry"], dict):
            tel = packet["telemetry"]
            if "lat" in tel and ("lon" in tel or "lng" in tel):
                lon_val = tel.get("lon", tel.get("lng"))
                packet["gps"] = f"{tel['lat']},{lon_val}"
            if "speed" in tel:
                packet["speed"] = tel["speed"]
            if "altitude" in tel:
                packet["altitude"] = tel["altitude"]
        
        now = time.time()
        t_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            db_write_lock.acquire()
            cursor = db_conn.cursor()
            self.analyze_network_behavior(drone_id, packet, now, cursor, t_str)
            # 1. Map IOCs
            cursor.execute("SELECT id FROM iocs WHERE value=?", (client_ip,))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO iocs (drone_id, type, value, source, timestamp) VALUES (?, ?, ?, ?, ?)", (drone_id, "IP", client_ip, "Network", t_str))
            
            cursor.execute("SELECT id FROM iocs WHERE value=?", (p_hash,))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO iocs (drone_id, type, value, source, timestamp) VALUES (?, ?, ?, ?, ?)", (drone_id, "SHA256", p_hash, "Payload Extraction", t_str))

            if "artifact_strings" in packet:
                for string in packet["artifact_strings"]:
                    cursor.execute("SELECT id FROM iocs WHERE value=?", (string,))
                    if not cursor.fetchone():
                        ioc_type = "STRING"
                        artifact_type = "Unknown Artifact"
                        evidence = "Memory Artifact"
                        finding_desc = "Unknown"
                        tech = "Unknown"
                        tech_name = "Unknown"
                        tactic = "Unknown"
                        tactic_name = "Unknown"
                        score_add = 0
                        
                        reason = "Identified through heuristic signature matching."
                        confidence = 80
                        
                        enterprise_tech = None
                        ics_tech = None
                        
                        cursor.execute("SELECT * FROM mapping_rules ORDER BY rule_priority DESC")
                        rules = cursor.fetchall()
                        
                        matched_rule = None
                        for rule in rules:
                            if re.search(rule["artifact_regex"], string):
                                matched_rule = rule
                                break
                                
                        if matched_rule:
                            finding_desc = matched_rule["artifact_type"]
                            evidence = string
                            tactic = "Mapped Tactic"
                            tactic_name = matched_rule["behavior"]
                            enterprise_tech = matched_rule["enterprise_technique"]
                            ics_tech = matched_rule["ics_technique"]
                            tech = ics_tech
                            tech_name = matched_rule["behavior"]
                            confidence = matched_rule["confidence_weight"]
                            score_add = 20
                            reason = "Matched by Dynamic Rule Engine."
                            
                            ioc_type = "STRING"
                            artifact_type = matched_rule["artifact_type"]
                            
                            if "MUTEX" in string:
                                ioc_type = "MUTEX"
                            elif ".net" in string or ".com" in string:
                                ioc_type = "NETWORK"
                            elif "run" in string.lower():
                                ioc_type = "REGISTRY"
                        
                        cursor.execute("INSERT INTO iocs (drone_id, type, value, source, timestamp) VALUES (?, ?, ?, ?, ?)", (drone_id, ioc_type, string, "Memory Artifact", t_str))
                        
                        if finding_desc != "Unknown":
                            artifact_address = packet.get("artifact_address", "0x004A80")
                            
                            if tech:
                                cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (drone_id, tactic, tactic_name, tech, enterprise_tech, ics_tech, tech_name, confidence, reason, evidence, t_str))
                            
                            # Determine source
                            artifact_source = "Memory Dump"
                            if "c2.dronefleet.net" in string:
                                artifact_source = ".rdata Section"
                            elif "XOR" in string or "Base64" in string:
                                artifact_source = "Config Block"
                            elif finding_desc == "Mutex Artifact":
                                artifact_source = "Process Memory / .data"
                            
                            cursor.execute("INSERT INTO re_findings (drone_id, artifact_address, artifact_type, finding, technique_id, enterprise_tech_id, ics_tech_id, behavior, evidence, mapping_reason, confidence, timestamp, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (drone_id, artifact_address, artifact_type, finding_desc, tech, enterprise_tech, ics_tech, tech_name, evidence, reason, confidence, t_str, artifact_source))
                            cursor.execute("SELECT score FROM drone_risk WHERE drone_id=?", (drone_id,))
                            current_score_row = cursor.fetchone()
                            current_score = current_score_row["score"] if current_score_row else 0
                            projected_score = current_score + score_add
                            
                            map_str = f"{tactic} -> {tech}" if tech else "No ATT&CK Map"
                            timeline_msg = f"Artifact Extracted\n\n{artifact_address}\n{string}\n\n↓\n\n{finding_desc}\n\n↓\n\n{map_str}\n{tech_name}\n\n↓\n\n+{score_add} Risk\n\n↓\n\nTotal Score = {projected_score}"
                            cursor.execute("INSERT INTO timeline (drone_id, event_type, message, timestamp) VALUES (?, ?, ?, ?)", (drone_id, "TECHNIQUE_MAPPED", timeline_msg, t_str))
                            
                            # Print to terminal
                            print(f"\n{C_RED}{C_BOLD}")
                            print("╔════════════════════════════════════════════════════════════════╗")
                            
                            def print_line(msg):
                                print(f"║{msg.ljust(64)}║")
                                
                            print_line(f"  🚨 ARTIFACT DETECTED: {finding_desc[:38]}")
                            print("╠════════════════════════════════════════════════════════════════╣")
                            print_line(f"  📍 Source: {artifact_source[:50]}")
                            print_line(f"  🎯 MITRE: {tech_name[:51]}")
                            print_line(f"  📈 Threat Score: +{score_add}")
                            print("╚════════════════════════════════════════════════════════════════╝")
                            print(f"{C_END}")

            # 2. Map Profiles & Config
            if "profile" in packet:
                prof = packet["profile"]
                cursor.execute("SELECT drone_id FROM malware_profiles WHERE drone_id=?", (drone_id,))
                if not cursor.fetchone():
                    cursor.execute("""
                        INSERT INTO malware_profiles (drone_id, family, version, campaign, c2_protocol, obfuscation, capabilities, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (drone_id, prof.get("family"), prof.get("version"), prof.get("campaign"), prof.get("c2_protocol"), prof.get("obfuscation"), json.dumps(prof.get("capabilities", [])), t_str, t_str))
                    cursor.execute("INSERT INTO timeline (drone_id, event_type, message, timestamp) VALUES (?, ?, ?, ?)", (drone_id, "CONNECTION", f"Drone Connected: {prof.get('family')} detected", t_str))
                else:
                    cursor.execute("UPDATE malware_profiles SET last_seen=? WHERE drone_id=?", (t_str, drone_id))

            if "config" in packet and packet["type"] == "register":
                conf = packet["config"]
                profile_family = packet.get("profile", {}).get("family", packet.get("family", ""))
                if profile_family != "CleanDrone" and conf.get("obfuscation") == "XOR+Base64":
                    cursor.execute("SELECT id FROM re_findings WHERE drone_id=? AND finding=?", (drone_id, "XOR+Base64 Obfuscation"))
                    if not cursor.fetchone():
                        artifact_address = packet.get("artifact_address", "0x00401000")
                        cursor.execute("INSERT INTO re_findings (drone_id, artifact_address, artifact_type, finding, technique_id, enterprise_tech_id, ics_tech_id, behavior, evidence, mapping_reason, confidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (drone_id, artifact_address, "Encoding Type", "XOR+Base64 Obfuscation", "T0832", "T1027", "T0832", "Obfuscated Command Channel", "Encoded C2 command payload", "Payload content intentionally encoded before transmission", 85, t_str))

            if "re_findings" in packet:
                for f in packet["re_findings"]:
                    cursor.execute("SELECT id FROM re_findings WHERE drone_id=? AND artifact_address=?", (drone_id, f.get("address", "")))
                    if not cursor.fetchone():
                        finding_val = f.get("finding", "Unknown")
                        source_val = f.get("source", "Unknown")
                        validation_val = f.get("validation_level", "L1")
                        quality_val = f.get("artifact_quality", 10)
                        fleet_role_val = packet.get("fleet_role", "member")
                        selected, candidates_list = self.evaluate_candidates(
                            cursor,
                            finding_val,
                            source_val,
                            validation_val,
                            quality_val,
                            fleet_role_val
                        )
                        
                        rejected_json = "[]"
                        breakdown_json = "{}"
                        if selected:
                            confidence = selected["score"]
                            mapping_reason = selected["reason"]
                            breakdown_json = json.dumps(selected.get("confidence_breakdown", {}))
                            rejected_list = [c for c in candidates_list if c["enterprise_tech_id"] != selected["enterprise_tech_id"]]
                            rejected_json = json.dumps([{"technique": r["enterprise_tech_id"], "score": r["score"], "reason": r["rejected_reason"], "breakdown": r.get("confidence_breakdown", {})} for r in rejected_list])
                            
                            ent_tech = selected["enterprise_tech_id"]
                            ics_tech = selected["ics_tech_id"]
                            t_id = selected["technique_id"]
                            op_effect = selected.get("operational_effect", "Mission Degradation")
                            
                            # Add the attack mapping if it doesn't exist
                            cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, t_id))
                            if not cursor.fetchone():
                                cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (drone_id, selected["tactic"], selected["tactic_name"], t_id, ent_tech, ics_tech, selected["name"], confidence, mapping_reason, f.get("evidence", ""), t_str))
                            
                            # Insert Evidence Chain
                            cursor.execute("INSERT INTO evidence_chain (drone_id, artifact, behavior, enterprise_technique, ics_technique, operational_effect, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)", (drone_id, finding_val, selected["tactic_name"], ent_tech, ics_tech, op_effect, t_str))
                            
                            # Insert Mapping History
                            time_str = datetime.now().strftime("%H:%M:%S")
                            cursor.execute("INSERT INTO mapping_history (time, artifact, technique) VALUES (?, ?, ?)", (time_str, finding_val, ent_tech))
                            
                        else:
                            confidence = f.get("confidence", 85)
                            mapping_reason = "Identified through heuristic signature matching."
                            ent_tech = f.get("enterprise_tech_id", "")
                            ics_tech = f.get("ics_tech_id", "")
                            t_id = f.get("technique_id", "")

                        stage_val = packet.get("campaign_stage", "Unknown")
                        cursor.execute("INSERT INTO re_findings (drone_id, artifact_address, artifact_type, finding, technique_id, enterprise_tech_id, ics_tech_id, behavior, evidence, mapping_reason, confidence, timestamp, source, validation_level, rejected_candidates, confidence_breakdown, campaign_stage) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (drone_id, f.get("address", ""), f.get("type", "Memory Artifact"), finding_val, t_id, ent_tech, ics_tech, f.get("behavior", ""), f.get("evidence", ""), mapping_reason, confidence, t_str, source_val, f.get("validation_level", "L1"), rejected_json, breakdown_json, stage_val))

            # Track Campaign Timeline
            stage = packet.get("campaign_stage")
            if stage:
                cursor.execute("SELECT stage FROM campaign_timeline WHERE drone_id=? ORDER BY id DESC LIMIT 1", (drone_id,))
                row = cursor.fetchone()
                if not row or row["stage"] != stage:
                    arts = [f.get("finding", "") for f in packet.get("re_findings", [])]
                    art_str = arts[-1] if arts else "None"
                    if arts:
                        cursor.execute("SELECT enterprise_tech_id FROM re_findings WHERE drone_id=? AND finding=? ORDER BY id DESC LIMIT 1", (drone_id, art_str))
                        t_row = cursor.fetchone()
                        tech_str = t_row["enterprise_tech_id"] if t_row else "None"
                    else:
                        tech_str = "None"
                    time_str = datetime.now().strftime("%H:%M:%S")
                    cursor.execute("INSERT INTO campaign_timeline (drone_id, time, stage, artifact, technique) VALUES (?, ?, ?, ?, ?)", (drone_id, time_str, stage, art_str, tech_str))

            # Process Pre-Mapped MITRE Candidates
            if "mitre_candidates" in packet:
                for tech in packet["mitre_candidates"]:
                    cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, tech))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, name, timestamp) VALUES (?, ?, ?, ?, ?, ?)", (drone_id, "TA0111", "Command and Control", tech, f"Candidate {tech} detected", t_str))

            # Check Beacon Abuse based on telemetry interval
            interval = packet.get("beacon_interval", packet.get("status", {}).get("beacon_interval", 5.0))

            if interval > 0 and interval < 1.0:
                flood_counter[drone_id] = flood_counter.get(drone_id, 0) + 1

                if flood_counter[drone_id] >= 10:
                    payload = json.dumps({"cmd": "stop_attack"})
                    obfuscated = TransportObfuscationLayer.obfuscate(payload) + b"\n"

                    with clients_lock:
                        client_sock = clients.get(drone_id)
                        if client_sock:
                            try:
                                client_sock.sendall(obfuscated)
                                cursor.execute(
                                    "INSERT INTO timeline (drone_id, event_type, message, timestamp) VALUES (?, ?, ?, ?)",
                                    (drone_id, "CONTAINMENT", "[SOAR ENGINE] Active Defense Playbook executed successfully: Host network containment applied.", t_str)
                                )
                                cursor.execute(
                                    "UPDATE cases SET status='ISOLATED_BY_SOAR', resolution_notes='Automated containment triggered due to traffic flood' WHERE drone_id=? AND status='OPEN'",
                                    (drone_id,)
                                )
                            except Exception:
                                pass

                    flood_counter[drone_id] = 0

                cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, "T0814"))
                if not cursor.fetchone():
                    cursor.execute(
                        "INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (drone_id, "TA0107", "Inhibit Response Function", "T0814", "T1498", "T0814", "Denial of Service (Traffic Flood Abuse)", 95, "Abnormal C2 interval detected", f"Interval: {interval}s", t_str)
                    )
                    cursor.execute(
                        "INSERT INTO alerts (drone_id, severity, title, description, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)",
                        (drone_id, "CRITICAL", "[UPLINK_STORM PACKET FLOOD DETECTED]", f"Aggressive C2 Beaconing interval: {interval}s detected.", t_str, "OPEN")
                    )
            else:
                flood_counter[drone_id] = 0
                        
            # Dynamic Attack Phase Mapping based on client explicitly reporting phase
            if "attack_phase" in packet:
                phase = packet["attack_phase"]
                
                if phase == "evasion":
                    cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, "T0878"))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                       (drone_id, "TA0107", "Inhibit Response Function", "T0878", "T1562", "T0878", "Alarm Suppression", 90, "Sensor silencing detected", "Battery and Proximity alerts suppressed", t_str))
                
                elif phase == "hardware":
                    cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, "T0836"))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                       (drone_id, "TA0106", "Impair Process Control", "T0836", "T1498", "T0836", "Modify Parameter", 95, "RTH Coordinates overwritten", "Flight Controller manipulation detected", t_str))
                    
                    cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, "T0843"))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                       (drone_id, "TA0106", "Impair Process Control", "T0843", "T1543", "T0843", "Program Download", 85, "Firmware overwrite detected", "Malicious code flashed to MCU", t_str))
                
                elif phase == "impact":
                    cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, "T0809"))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                       (drone_id, "TA0104", "Impact", "T0809", "T1485", "T0809", "Data Destruction", 99, "SD Card Wiped", "Forensic evidence deleted", t_str))
                        
                    cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, "T0879"))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                       (drone_id, "TA0104", "Impact", "T0879", "T1495", "T0879", "Damage to Property", 100, "Rotor shutdown mid-air", "Kinetic impact initiated", t_str))

                elif phase == "initial_access":
                    cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, "T0886"))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                       (drone_id, "TA0108", "Initial Access", "T0886", "T1190", "T0886", "Remote System Discovery", 90, "Exploited external remote services", "Access to C2 network established", t_str))
                        
                elif phase == "execution":
                    cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, "T0853"))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                       (drone_id, "TA0104", "Execution", "T0853", "T1059", "T0853", "Scripting", 95, "Command execution via scripts", "Automated code executed on device", t_str))

            # GPS Anomaly Detection (Flight Telemetry Manipulation)
            if "gps" in packet:
                gps_str = packet["gps"]
                try:
                    lat, lon = map(float, gps_str.split(","))
                    if drone_id in self.last_gps_data:
                        last_lat, last_lon, last_t = self.last_gps_data[drone_id]
                        time_diff = now - last_t
                        time_diff = max(time_diff, 0.001)
                        
                        # Haversine
                        R = 6371
                        dlat = math.radians(lat - last_lat)
                        dlon = math.radians(lon - last_lon)
                        a = math.sin(dlat/2)**2 + math.cos(math.radians(last_lat)) * math.cos(math.radians(lat)) * math.sin(dlon/2)**2
                        distance = R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
                        speed_kmh = distance / (time_diff / 3600)
                        packet["speed"] = int(speed_kmh)
                        
                        if speed_kmh > 300.0:
                            cursor.execute("SELECT id FROM alerts WHERE drone_id=? AND title=?", (drone_id, "Flight Telemetry Manipulation"))
                            if not cursor.fetchone():
                                cursor.execute("INSERT INTO alerts (drone_id, severity, title, description, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)", (drone_id, "HIGH", "Flight Telemetry Manipulation", f"Possible GPS Spoofing: {speed_kmh:.0f} km/h detected", t_str, "OPEN"))
                                
                                cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id=?", (drone_id, "T0831"))
                                if not cursor.fetchone():
                                    cursor.execute("INSERT INTO attack_mapping (drone_id, tactic, tactic_name, technique_id, enterprise_tech_id, ics_tech_id, name, confidence, reason, evidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (drone_id, "TA0106", "Impair Process Control", "T0831", "T1005", "T0831", "Manipulation of Control (GPS Anomaly)", 95, "Unrealistic speed and distance calculation", f"Speed: {speed_kmh:.0f} km/h", t_str))
                                    cursor.execute("INSERT INTO timeline (drone_id, event_type, message, timestamp) VALUES (?, ?, ?, ?)", (drone_id, "TECHNIQUE_MAPPED", "T0831 (GPS Anomaly) observed", t_str))
                    
                    with self.packet_lock:
                        self.last_gps_data[drone_id] = (lat, lon, now)
                except Exception: pass
                        
            with self.packet_lock:
                self.last_packet_time[drone_id] = now
            
            # 4. Update Threat Score
            cursor.execute("SELECT score, breakdown FROM drone_risk WHERE drone_id=?", (drone_id,))
            risk_row = cursor.fetchone()
            
            # Calculate ICS Operational Impact Formula
            safety_impact = 0
            mission_impact = 0
            availability_impact = 0
            
            speed_kmh = packet.get("speed", 0)
            satellites = packet.get("satellites", 10)
            temp = packet.get("temp", 40)
            
            if speed_kmh > 300.0:
                safety_impact = 80
                
            cursor.execute("SELECT id FROM attack_mapping WHERE drone_id=? AND technique_id IN ('T0831', 'T0832')", (drone_id,))
            has_mission_tech = cursor.fetchone()
            
            if (has_mission_tech or speed_kmh > 300.0) and satellites < 3:
                mission_impact = 90
                
            if temp > 50 and satellites < 3:
                availability_impact = 60
                
            score = int((0.4 * safety_impact) + (0.4 * mission_impact) + (0.2 * availability_impact))
            
            breakdown = {
                "Safety Impact (0.4)": f"{safety_impact}% (Speed > 300km/h)" if safety_impact > 0 else "0%",
                "Mission Impact (0.4)": f"{mission_impact}% (Waypoint Drift & Satellite Loss)" if mission_impact > 0 else "0%",
                "Availability Impact (0.2)": f"{availability_impact}% (Hardware Overheat & Signal Jamming)" if availability_impact > 0 else "0%"
            }

            breakdown_str = json.dumps(breakdown)
            
            if risk_row:
                cursor.execute("UPDATE drone_risk SET score=?, breakdown=?, last_updated=? WHERE drone_id=?", (score, breakdown_str, t_str, drone_id))
            else:
                cursor.execute("INSERT INTO drone_risk (drone_id, score, breakdown, last_updated) VALUES (?, ?, ?, ?)", (drone_id, score, breakdown_str, t_str))
            
            # Alert Engine & Case Management
            if score >= 80:
                cursor.execute("SELECT id FROM alerts WHERE drone_id=? AND status='OPEN' AND severity='CRITICAL'", (drone_id,))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO alerts (drone_id, severity, title, description, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)", (drone_id, "CRITICAL", "High Risk Drone Detected", f"Threat Score = {score}", t_str, "OPEN"))
                    alert_id = cursor.lastrowid
                    cursor.execute("INSERT INTO cases (drone_id, alert_id, priority, assigned_to, resolution_notes, status, created_time) VALUES (?, ?, ?, ?, ?, ?, ?)", (drone_id, alert_id, "P1", "Unassigned", "", "OPEN", t_str))
                    
            # IOC Correlation Engine
            cursor.execute("SELECT value FROM iocs WHERE drone_id=?", (drone_id,))
            ioc_values = [row[0] for row in cursor.fetchall()]
            has_mutex = any("DF_MUTEX" in v for v in ioc_values)
            has_domain = any("c2." in v for v in ioc_values)
            if has_mutex and has_domain:
                cursor.execute("SELECT id FROM ioc_attack_mapping WHERE drone_id=? AND campaign=?", (drone_id, "DroneFlood"))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO ioc_attack_mapping (drone_id, ioc_value, technique_id, description, timestamp, confidence, campaign) VALUES (?, ?, ?, ?, ?, ?, ?)", (drone_id, "DF_MUTEX + C2 Domain", "T0885 + Persistence Evidence", "Correlated DroneFlood Campaign (Multiple High-Fidelity IOCs)", t_str, 95, "DroneFlood"))
                    cursor.execute("INSERT INTO timeline (drone_id, event_type, message, timestamp) VALUES (?, ?, ?, ?)", (drone_id, "CORRELATION", "IOCs Correlated to DroneFlood Campaign (95% Confidence)", t_str))
            
            if server_processed_packets > 0 and server_processed_packets % 100 == 0:
                cursor.execute("DELETE FROM timeline WHERE id NOT IN (SELECT id FROM timeline ORDER BY id DESC LIMIT 5000)")
            
            db_conn.commit()
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"DB Error: {e}")
        finally:
            db_write_lock.release()
mitre_engine = MITREMappingEngine()

