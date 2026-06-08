import socket
import sys
import time
import json
import base64
import random
import threading
import uuid
import urllib.request
import argparse

C_GREEN, C_RED, C_YELLOW, C_BLUE, C_CYAN, C_BOLD, C_END = ("\033[92m", "\033[91m", "\033[93m", "\033[94m", "\033[96m", "\033[1m", "\033[0m")

class TransportObfuscationLayer:
    @staticmethod
    def obfuscate(data_str: str) -> bytes:
        xored = bytes([b ^ 0x42 for b in data_str.encode('utf-8')])
        return base64.b64encode(xored)
    @staticmethod
    def deobfuscate(cipher_bytes: bytes) -> str:
        decoded = base64.b64decode(cipher_bytes)
        return bytes([b ^ 0x42 for b in decoded]).decode('utf-8')

MALWARE_PROFILE = {
    "family": "DroneFlood",
    "version": "1.0",
    "campaign": "DF-2026",
    "author": "Unknown",
    "c2_protocol": "TCP",
    "obfuscation": "XOR+Base64",
    "capabilities": ["telemetry_exfiltration", "c2_beacon", "remote_command"]
}

RE_FINDINGS = [
    {
        "address": "0x004A80",
        "type": "Mutex",
        "finding": "DF_MUTEX_01",
        "behavior": "Persistence Simulation",
        "technique_id": "T0866",
        "enterprise_tech_id": "T1547.001",
        "ics_tech_id": "T0866",
        "evidence": "Mutex exists in RAM",
        "confidence": 95,
        "source": "Memory Dump",
        "validation_level": "L3"
    },
    {
        "address": "0x004B12",
        "type": "Domain",
        "finding": "c2.dronefleet.net",
        "behavior": "Command and Control",
        "technique_id": "T0885",
        "enterprise_tech_id": "T1071",
        "ics_tech_id": "T0885",
        "evidence": "Hardcoded C2 domain",
        "confidence": 98,
        "source": ".rdata Section",
        "validation_level": "L3"
    },
    {
        "address": "0x004F31",
        "type": "Encoding",
        "finding": "XOR+Base64",
        "behavior": "Obfuscated Command Channel",
        "technique_id": "T0832",
        "enterprise_tech_id": "T1027",
        "ics_tech_id": "T0832",
        "evidence": "Payload content intentionally encoded",
        "confidence": 85,
        "source": "Config Block",
        "validation_level": "L2"
    },
    {
        "address": "0x005C10",
        "type": "Function",
        "finding": "gps_spoof",
        "behavior": "GPS Manipulation",
        "technique_id": "T0832",
        "enterprise_tech_id": "T1005",
        "ics_tech_id": "T0832",
        "evidence": "Code block injecting random coordinates",
        "confidence": 95,
        "source": "Reverse Engineering",
        "validation_level": "L3"
    },
    {
        "address": "0x005D44",
        "type": "Function",
        "finding": "battery_drain",
        "behavior": "Battery Drain Exploitation",
        "technique_id": "T0879",
        "enterprise_tech_id": "T1498",
        "ics_tech_id": "T0879",
        "evidence": "Code block altering battery sensor data",
        "confidence": 90,
        "source": "Reverse Engineering",
        "validation_level": "L3"
    },
    {
        "address": "0x005A99",
        "type": "Network Flow",
        "finding": "FLEET_SYNC",
        "behavior": "Peer-to-Peer Command",
        "technique_id": "T0866",
        "enterprise_tech_id": "T1563",
        "ics_tech_id": "T0866",
        "evidence": "Drone-to-drone sync traffic",
        "confidence": 88,
        "source": "Network Flow",
        "validation_level": "L2"
    },
    {
        "address": "0x001A20", "type": "Registry Key", "finding": "DF_REG_RUN", "behavior": "Persistence", "technique_id": "T0866", "enterprise_tech_id": "T1547.001", "ics_tech_id": "T0866", "evidence": "Registry Run key modification", "confidence": 95, "source": "Config Extraction", "validation_level": "L3"
    },
    {
        "address": "0x001A25", "type": "File", "finding": "DF_STARTUP_CFG", "behavior": "Persistence", "technique_id": "T0866", "enterprise_tech_id": "T1547.001", "ics_tech_id": "T0866", "evidence": "Startup folder script dropped", "confidence": 90, "source": "Reverse Engineering", "validation_level": "L3"
    },
    {
        "address": "0x002B40", "type": "Network Pattern", "finding": "beacon_30s", "behavior": "Command and Control", "technique_id": "T0885", "enterprise_tech_id": "T1071", "ics_tech_id": "T0885", "evidence": "C2 beacon every 30 seconds", "confidence": 85, "source": "Network Traffic", "validation_level": "L2"
    },
    {
        "address": "0x002B45", "type": "Payload", "finding": "encoded_payload", "behavior": "Evasion", "technique_id": "T0832", "enterprise_tech_id": "T1027", "ics_tech_id": "T0832", "evidence": "Custom encoded payload over HTTP", "confidence": 90, "source": "Reverse Engineering", "validation_level": "L3"
    },
    {
        "address": "0x002B50", "type": "Protocol", "finding": "custom_protocol_v1", "behavior": "Command and Control", "technique_id": "T0884", "enterprise_tech_id": "T1090", "ics_tech_id": "T0884", "evidence": "Non-standard protocol headers detected", "confidence": 95, "source": "Network Traffic", "validation_level": "L3"
    },
    {
        "address": "0x003C10", "type": "Command", "finding": "FLEET_COMMAND_PUSH", "behavior": "Lateral Movement", "technique_id": "T0866", "enterprise_tech_id": "T1563", "ics_tech_id": "T0866", "evidence": "P2P command pushing to fleet members", "confidence": 90, "source": "Network Flow", "validation_level": "L3"
    },
    {
        "address": "0x003C15", "type": "Process", "finding": "LEADER_NODE_COMPROMISED", "behavior": "Lateral Movement", "technique_id": "T0866", "enterprise_tech_id": "T1563", "ics_tech_id": "T0866", "evidence": "Leader node broadcasting override commands", "confidence": 95, "source": "Memory Dump", "validation_level": "L3"
    },
    {
        "address": "0x003C20", "type": "Process", "finding": "MEMBER_NODE_CONTROLLED", "behavior": "Lateral Movement", "technique_id": "T0866", "enterprise_tech_id": "T1563", "ics_tech_id": "T0866", "evidence": "Member node accepting unauthorized sync", "confidence": 90, "source": "Memory Dump", "validation_level": "L3"
    },
    {
        "address": "0x004D10", "type": "Memory Variable", "finding": "waypoint_override", "behavior": "Manipulation of Control", "technique_id": "T0832", "enterprise_tech_id": "T1005", "ics_tech_id": "T0832", "evidence": "Active waypoint coordinates overwritten in RAM", "confidence": 95, "source": "Memory Dump", "validation_level": "L3"
    },
    {
        "address": "0x004D15", "type": "Logic", "finding": "gps_offset_120m", "behavior": "Manipulation of Control", "technique_id": "T0832", "enterprise_tech_id": "T1005", "ics_tech_id": "T0832", "evidence": "Hardcoded offset of 120m injected into navigation", "confidence": 95, "source": "Decompiled Code", "validation_level": "L3"
    },
    {
        "address": "0x004D20", "type": "Logic", "finding": "navigation_drift", "behavior": "Manipulation of Control", "technique_id": "T0832", "enterprise_tech_id": "T1005", "ics_tech_id": "T0832", "evidence": "PID controller loop manipulated to cause drift", "confidence": 90, "source": "Reverse Engineering", "validation_level": "L3"
    }
]

MALWARE_CONFIG = {
    "config_version": "1.0",
    "c2_port": 5555,
    "obfuscation": "XOR+Base64"
}

codename = ""
max_altitude = 300
beacon_mode = "NORMAL"
engine_kill = False
gps_spoof_active = False
physical_damage_active = False

def tcp_flood_task(c2_ip):
    while beacon_mode == "ABUSE":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((c2_ip, MALWARE_CONFIG["c2_port"]))
            s.close()
            time.sleep(0.01)
        except:
            pass

def udp_flood_task(c2_ip):
    while beacon_mode == "ABUSE":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"X" * 1024, (c2_ip, MALWARE_CONFIG["c2_port"]))
            time.sleep(0.01)
        except:
            pass

def listen_for_c2_commands(sock, drone_id):
    global codename, max_altitude, beacon_mode, engine_kill, gps_spoof_active, physical_damage_active
    cmd_buffer = ""
    while True:
        try:
            cmd_data = sock.recv(4096)
            if not cmd_data: break
            cmd_buffer += cmd_data.decode('utf-8')
            while "\n" in cmd_buffer:
                line, cmd_buffer = cmd_buffer.split("\n", 1)
                if not line.strip(): continue
                
                raw_payload = TransportObfuscationLayer.deobfuscate(line.strip().encode('utf-8'))
                instruction = json.loads(raw_payload)
                command = instruction.get("cmd")
                
                if command == "ping":
                    print(f"\n{C_CYAN}[+] Received Command: PING{C_END}")
                    print(f" {C_GREEN}[i]{C_END} C2 Verification ping received.")
                elif command == "get_status":
                    print(f"\n{C_CYAN}[+] Received Command: GET_STATUS{C_END}")
                elif command == "get_config":
                    print(f"\n{C_CYAN}[+] Received Command: GET_CONFIG{C_END}")
                elif command == "get_ioc":
                    print(f"\n{C_CYAN}[+] Received Command: GET_IOC{C_END}")
                elif command == "get_profile":
                    print(f"\n{C_CYAN}[+] Received Command: GET_PROFILE{C_END}")
                elif command == "tcp_flood":
                    print(f"\n{C_RED}[!] EMERGENCY DIRECTIVE: SIMULATE TCP TRAFFIC FLOOD!{C_END}")
                    beacon_mode = "ABUSE"
                    threading.Thread(target=tcp_flood_task, args=(MALWARE_CONFIG.get("c2", "127.0.0.1"),), daemon=True).start()
                elif command == "udp_flood":
                    print(f"\n{C_RED}[!] EMERGENCY DIRECTIVE: SIMULATE UDP TRAFFIC FLOOD!{C_END}")
                    beacon_mode = "ABUSE"
                    threading.Thread(target=udp_flood_task, args=(MALWARE_CONFIG.get("c2", "127.0.0.1"),), daemon=True).start()
                elif command == "stop_attack":
                    print(f"\n{C_GREEN}[+] EMERGENCY SUCCESS: THE TRANSMISSION CHANNEL RESTORED TO NOMINAL SPEC.{C_END}")
                    beacon_mode = "NORMAL"
                elif command == "manipulate_control":
                    print(f"\n{C_RED}[!] EMERGENCY DIRECTIVE: MANIPULATION OF CONTROL (T0831) ACTIVATED!{C_END}")
                    engine_kill = True
                elif command == "restore_control":
                    print(f"\n{C_GREEN}[+] EMERGENCY SUCCESS: HARDWARE CONTROL RESTORED.{C_END}")
                    engine_kill = False
                elif command == "gps_spoof":
                    print(f"\n{C_RED}[!] CRITICAL: GPS SPOOFING ATTACK INITIATED!{C_END}")
                    gps_spoof_active = True
                elif command == "stop_gps_spoof":
                    print(f"\n{C_GREEN}[+] SUCCESS: GPS SPOOFING ABORTED.{C_END}")
                    gps_spoof_active = False
                elif command == "physical_damage":
                    print(f"\n{C_RED}[!] CRITICAL: PHYSICAL DAMAGE (BATTERY DRAIN) ATTACK INITIATED!{C_END}")
                    physical_damage_active = True
        except: break

def run_drone_agent(c2_ip, port, drone_id, scenario):
    global max_altitude, beacon_mode, engine_kill, gps_spoof_active, physical_damage_active
    
    codename_list = ["Specter-Alpha", "Valkyrie-X1", "ShadowHawk-V", "Predator-C2", "Horizon-Zero", "SkyRanger-M9"]
    codename = codename_list[hash(drone_id) % len(codename_list)]
    max_alt = random.choice([300, 350, 400, 450, 500])
    
    session_id = uuid.uuid4().hex[:8].upper()
    print(f" {C_GREEN}[+]{C_END} Hooking communication stream pipeline for: {C_BOLD}{drone_id}{C_END} (Codename: {codename}) | Scenario: {scenario}")
    
    start_time = time.time()
    battery = 100
    last_battery_drop = start_time
    last_warning_time = 0
    
    stages = ["Clean", "Persistence", "Custom C2", "Fleet Takeover", "GPS Drift", "Mission Failure"]
    current_stage_idx = 0
    
    if scenario == "Clean Drone": current_stage_idx = 0
    elif scenario == "Persistence Only": current_stage_idx = 1
    elif scenario == "Custom C2": current_stage_idx = 2
    elif scenario == "Fleet Takeover": current_stage_idx = 3
    elif scenario == "GPS Drift": current_stage_idx = 4
    elif scenario == "Mission Failure": current_stage_idx = 5
    
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((c2_ip, port))
            
            MALWARE_CONFIG["c2"] = c2_ip
            
            reg_packet = {
                "type": "register", 
                "drone_id": drone_id,
                "session_id": session_id,
                "profile": MALWARE_PROFILE,
                "config": MALWARE_CONFIG,
                "re_findings": RE_FINDINGS
            }
            sock.sendall(TransportObfuscationLayer.obfuscate(json.dumps(reg_packet)) + b"\n")
            
            threading.Thread(target=listen_for_c2_commands, args=(sock, drone_id), daemon=True).start()
            
            seq = 0
            lat_base = 10.841 + random.uniform(-0.005, 0.005)
            lng_base = 106.654 + random.uniform(-0.005, 0.005)
            
            while True:
                seq += 1
                current_time = time.time()
                uptime = int(current_time - start_time)
                
                # Advance stage for Full Campaign
                if scenario == "Full Campaign":
                    current_stage_idx = min(5, uptime // 15) # Advance stage every 15s
                
                campaign_stage = stages[current_stage_idx]
                
                # Filter Findings based on Stage
                active_findings = []
                for f in RE_FINDINGS:
                    if campaign_stage == "Clean":
                        pass
                    elif campaign_stage == "Persistence" and f["finding"] in ["DF_MUTEX_01", "DF_REG_RUN", "DF_STARTUP_CFG"]:
                        active_findings.append(f)
                    elif campaign_stage == "Custom C2" and f["finding"] in ["DF_MUTEX_01", "DF_REG_RUN", "DF_STARTUP_CFG", "c2.dronefleet.net", "XOR+Base64", "beacon_30s", "encoded_payload", "custom_protocol_v1"]:
                        active_findings.append(f)
                    elif campaign_stage == "Fleet Takeover" and f["finding"] in ["DF_MUTEX_01", "c2.dronefleet.net", "FLEET_SYNC", "FLEET_COMMAND_PUSH", "LEADER_NODE_COMPROMISED", "MEMBER_NODE_CONTROLLED"]:
                        active_findings.append(f)
                    elif campaign_stage == "GPS Drift" and f["finding"] in ["gps_spoof", "waypoint_override", "gps_offset_120m", "navigation_drift", "c2.dronefleet.net", "DF_MUTEX_01"]:
                        active_findings.append(f)
                        gps_spoof_active = True
                    elif campaign_stage == "Mission Failure":
                        active_findings.append(f)
                        physical_damage_active = True
                
                print(f"{C_YELLOW}[*] Campaign Stage: {C_BOLD}{campaign_stage}{C_END} | Active Artifacts: {len(active_findings)}")
                
                if gps_spoof_active:
                    lat_base += 1.5
                    lng_base -= 2.0
                else:
                    lat_base += random.uniform(-0.00012, 0.00012)
                    lng_base += random.uniform(-0.00012, 0.00012)
                
                current_time = time.time()
                
                drain_interval = 10.0
                if physical_damage_active:
                    battery = max(0, battery - 5)
                elif current_time - last_battery_drop >= drain_interval:
                    drops = int((current_time - last_battery_drop) / drain_interval)
                    battery = max(0, battery - drops)
                    last_battery_drop += drops * drain_interval
                    
                if battery <= 0:
                    uptime = int(current_time - start_time)
                    print(f"\n{C_RED}{C_BOLD}[!] BATTERY DEPLETED. DRONE OFFLINE: {drone_id}{C_END}")
                    
                    telemetry_packet = {
                        "type": "telemetry", 
                        "drone_id": drone_id, 
                        "session_id": session_id,
                        "sequence": seq,
                        "beacon_interval": 0,
                        "gps": f"{lat_base:.6f},{lng_base:.6f}", 
                        "battery": 0, 
                        "altitude": 0, 
                        "speed": 0,
                        "codename": codename, 
                        "max_altitude": max_alt,
                        "network_speed": 0, 
                        "signal_strength": -99,
                        "temp": 40, 
                        "satellites": 0,
                        "family": MALWARE_PROFILE["family"],
                        "version": MALWARE_PROFILE["version"],
                        "campaign": MALWARE_PROFILE["campaign"],
                        "campaign_stage": campaign_stage,
                        "custom_c2_indicators": {"beacon_interval": 30, "encoded_payload": True, "fleet_command": True} if current_stage_idx >= 1 else {},
                        "re_findings": active_findings
                    }
                    try:
                        sock.sendall(TransportObfuscationLayer.obfuscate(json.dumps(telemetry_packet)) + b"\n")
                        sock.close()
                    except: pass
                    sys.exit(0)
                    
                if battery < 10:
                    pass
                alt = random.randint(120, max_alt - 20)
                net_speed = random.randint(150, 280)
                sig_strength = random.randint(-62, -48)
                temp = random.randint(38, 48)
                satellites = random.randint(12, 18)
                
                sleep_time = 0.5 if beacon_mode == "ABUSE" else delay_seconds
                if engine_kill:
                    speed_val = 0
                    alt = 300
                else:
                    speed_val = random.randint(35, 65)

                if physical_damage_active:
                    temp = random.randint(55, 80)
                    satellites = random.randint(0, 2)

                telemetry_packet = {
                    "type": "telemetry", 
                    "drone_id": drone_id, 
                    "session_id": session_id,
                    "sequence": seq,
                    "beacon_interval": sleep_time,
                    "gps": f"{lat_base:.6f},{lng_base:.6f}", 
                    "battery": battery, 
                    "altitude": alt, 
                    "speed": speed_val,
                    "codename": codename, 
                    "max_altitude": max_alt,
                    "network_speed": net_speed, 
                    "signal_strength": sig_strength,
                    "temp": temp, 
                    "satellites": satellites,
                    "family": MALWARE_PROFILE["family"],
                    "version": MALWARE_PROFILE["version"],
                    "campaign": MALWARE_PROFILE["campaign"],
                    "campaign_stage": campaign_stage,
                    "custom_c2_indicators": {"beacon_interval": 30, "encoded_payload": True, "fleet_command": True} if current_stage_idx >= 1 else {},
                    "re_findings": active_findings
                }
                sock.sendall(TransportObfuscationLayer.obfuscate(json.dumps(telemetry_packet)) + b"\n")
                
                uptime = int(current_time - start_time)
                print(f"\n ╭──[ {C_CYAN}BOT: {drone_id}{C_END} ]──────[ {C_YELLOW}UPTIME: {uptime}s{C_END} ]──────[ {C_GREEN}SEQ: {seq}{C_END} ]")
                print(f" │ ↳ Batt: {battery}% | Alt: {alt}m | Net: {net_speed}Mbps | GPS: {lat_base:.4f},{lng_base:.4f}")
                print(f" ╰{'─'*65}")
                
                if args.pause_after.lower() == campaign_stage.lower():
                    print(f"\n{C_RED}[!] PAUSED AFTER {campaign_stage.upper()}. Press [ENTER] to continue...{C_END}")
                    input()
                    
                time.sleep(sleep_time)
        except Exception as e:
            current_time = time.time()
            uptime = int(current_time - start_time)
            
            drain_interval = 10.0
            if physical_damage_active:
                battery = max(0, battery - 5)
            elif current_time - last_battery_drop >= drain_interval:
                drops = int((current_time - last_battery_drop) / drain_interval)
                battery = max(0, battery - drops)
                last_battery_drop += drops * drain_interval
                
            if battery <= 0:
                print(f"\n{C_RED}{C_BOLD}[!] BATTERY DEPLETED. DRONE OFFLINE: {drone_id}{C_END}")
                sys.exit(0)
            time.sleep(3)

def main():
    global beacon_mode
    
    parser = argparse.ArgumentParser(description="DroneFlood Campaign Simulator")
    parser.add_argument("--scenario", type=str, choices=["clean", "persistence", "custom_c2", "fleet_takeover", "gps_drift", "mission_failure", "full_campaign"], default="full_campaign", help="Scenario to execute")
    parser.add_argument("--speed", type=str, choices=["fast", "demo", "slow"], default="demo", help="Speed of the campaign simulation")
    parser.add_argument("--pause-after", type=str, default="", help="Pause the simulation after a specific stage (e.g., 'Persistence')")
    parser.add_argument("--repeat", type=int, default=1, help="Number of times to repeat the scenario")
    args = parser.parse_args()
    
    speed_map = {"fast": 1, "demo": 5, "slow": 10}
    delay_seconds = speed_map.get(args.speed, 5)
    
    scenario_map = {
        "clean": "Clean Drone",
        "persistence": "Persistence Only",
        "custom_c2": "Custom C2",
        "fleet_takeover": "Fleet Takeover",
        "gps_drift": "GPS Drift",
        "mission_failure": "Mission Failure",
        "full_campaign": "Full Campaign"
    }
    selected_scenario = scenario_map[args.scenario]
    
    print(r"""
   __  __ _  _ _    _ __  __ ___ ___ ___  ___  
  | |  | | \| | |  | |  |  |  |  |__ |  \ |__  
  |_|  |_| |  |_|_ |_|  |_|  |  |___ |_ / |___ (_) [ BOTNET INFILTRATION TERMINAL ]
    """)
    
    print(f"{C_YELLOW}[*] Executing OS Fingerprint & Telemetry Spy modules...{C_END}")
    time.sleep(1)
    print(f"{C_RED}[!] Exploiting Zero-Day Vulnerability in Drone Fleet Management System...{C_END}")
    time.sleep(1.5)
    print(f"{C_GREEN}[+] Access Granted. Privilege Escalation Successful.{C_END}")
    time.sleep(1)
    print(f"{C_CYAN}[+] Injecting DroneFlood Botnet Payload into System Memory (Scenario: {selected_scenario})...{C_END}\n")
    time.sleep(1)
    
    c2_ip = "127.0.0.1"
    num_drones = 3
        
    port = MALWARE_CONFIG["c2_port"]
    beacon_mode = random.choice(["NORMAL", "ABUSE"])
    print(f"\n {C_BLUE}[i]{C_END} Swarm profile calibrated to beacon mode: {C_BOLD}{beacon_mode}{C_END}")
    
    # FETCH ACTIVE CLEAN DRONES TO INFECT
    active_drones = []
    try:
        req = urllib.request.Request(f"http://{c2_ip}:9000/api/drones")
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            fleet = data.get("fleet", {})
            active_drones = [d for d, info in fleet.items() if info.get("status") == "ACTIVE"]
    except Exception as e:
        print(f" {C_YELLOW}[!] Could not fetch active drones from C2 REST API. Fallback to random IDs.{C_END}")
        
    for repeat_idx in range(args.repeat):
        if args.repeat > 1:
            print(f"\n{C_YELLOW}{C_BOLD}=== CAMPAIGN ITERATION {repeat_idx + 1} / {args.repeat} ==={C_END}")
            
        print(f" {C_RED}[!] LAUNCHING MULTIPLE BOTNET AGENTS (Count: {num_drones})...{C_END}\n")
        
        threads = []
        for i in range(num_drones):
            # Pick a random drone_id
            drone_id = f"DRONE-{random.randint(100,999)}"
                
            t = threading.Thread(target=run_drone_agent, args=(c2_ip, port, drone_id, selected_scenario), daemon=True)
            t.start()
            threads.append(t)
            time.sleep(0.5)
            
        # Wait for all threads in this iteration to finish
        for t in threads:
            t.join()
            
        if repeat_idx < args.repeat - 1:
            print(f" {C_CYAN}[i] Waiting 5 seconds before next iteration...{C_END}")
            time.sleep(5)
            
    print(f"\n{C_GREEN}{C_BOLD}[+] All iterations completed successfully.{C_END}")

if __name__ == "__main__": main()
