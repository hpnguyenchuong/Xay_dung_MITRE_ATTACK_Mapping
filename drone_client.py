import socket
import sys
import time
import json
import base64
import random
import threading
import uuid
import math
import argparse

C_GREEN, C_RED, C_CYAN, C_YELLOW, C_BOLD, C_END = ("\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[1m", "\033[0m")

class TransportObfuscationLayer:
    @staticmethod
    def obfuscate(data_str: str) -> bytes:
        xored = bytes([b ^ 0x42 for b in data_str.encode('utf-8')])
        return base64.b64encode(xored)
    @staticmethod
    def deobfuscate(cipher_bytes: bytes) -> str:
        decoded = base64.b64decode(cipher_bytes)
        return bytes([b ^ 0x42 for b in decoded]).decode('utf-8')

codename = "CLEAN-DRONE"
max_altitude = 120

def send_payload(sock, payload_dict):
    try:
        data_str = json.dumps(payload_dict)
        cipher_bytes = TransportObfuscationLayer.obfuscate(data_str)
        sock.sendall(cipher_bytes + b"\n")
        return True
    except Exception as e:
        return False

def main():
    parser = argparse.ArgumentParser(description="Drone Client Simulator")
    parser.add_argument("c2_ip", help="C2 Server IP")
    parser.add_argument("--playback", type=str, default="datasets/clean_case.json", help="Path to playback JSON file")
    args = parser.parse_args()
        
    c2_ip = args.c2_ip
    drone_id = f"DRONE-{random.randint(100, 999)}"
    
    print(f"{C_CYAN}[i]{C_END} Starting Clean Drone Simulator: {C_BOLD}{drone_id}{C_END}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((c2_ip, 5555))
        print(f"{C_GREEN}[+]{C_END} Connected to Drone Malware Analysis Server at {c2_ip}:5555")
    except Exception as e:
        print(f"Failed to connect: {e}")
        sys.exit(1)
        
    fleet_role = "leader" if random.random() > 0.7 else "member"
    
    # Registration Request
    reg_payload = {
        "type": "register",
        "drone_id": drone_id,
        "fleet_id": "fleet_alpha",
        "fleet_role": fleet_role,
        "ip": "10.0.0." + str(random.randint(10, 250)),
        "timestamp": time.time(),
        "model": "PX4",
        "mission": "Powerline Inspection",
        "gps_status": "OK",
        "profile": {
            "family": "CleanDrone",
            "version": "baseline-1.0",
            "campaign": "Baseline",
            "c2_protocol": "Telemetry-TCP",
            "obfuscation": "None",
            "capabilities": ["clean_telemetry", "mission_reporting"]
        },
        "mitre_candidates": [],
        "config": {
            "obfuscation": "None",
            "artifact_address": "0x00401000"
        }
    }
    send_payload(sock, reg_payload)

    global dynamic_phase
    dynamic_phase = None

    def listen_for_commands():
        global dynamic_phase
        cmd_buffer = ""
        while True:
            try:
                data = sock.recv(4096)
                if not data: break
                cmd_buffer += data.decode('utf-8')
                while "\n" in cmd_buffer:
                    line, cmd_buffer = cmd_buffer.split("\n", 1)
                    if not line.strip(): continue
                    raw_payload = TransportObfuscationLayer.deobfuscate(line.strip().encode('utf-8'))
                    instruction = json.loads(raw_payload)
                    cmd = instruction.get("cmd")
                    print(f"\n{C_GREEN}[+] C2 COMMAND RECEIVED: {C_BOLD}{cmd.upper()}{C_END}")
                    
                    if cmd in ["spoof", "gps_spoof", "flood", "evasion", "hardware", "impact", "physical_damage", "normal", "initial_access", "execution"]:
                        if cmd == "physical_damage":
                            dynamic_phase = "impact"
                            print(f"{C_RED}[!] CRITICAL: PHYSICAL DAMAGE (BATTERY DRAIN) ATTACK INITIATED!{C_END}")
                        elif cmd == "gps_spoof":
                            dynamic_phase = "spoof"
                            print(f"{C_YELLOW}[!] Switched Attack Phase to: SPOOF{C_END}")
                        else:
                            dynamic_phase = cmd
                            print(f"{C_YELLOW}[!] Switched Attack Phase to: {cmd.upper()}{C_END}")
            except Exception as e:
                break
                
    threading.Thread(target=listen_for_commands, daemon=True).start()
    
    lat = 21.0285
    lon = 105.8542
    battery = 100
    altitude = random.randint(50, 400)
    max_altitude = random.randint(150, 400)
    waypoints = random.randint(5, 15)
    current_wp = 1
    
    playback_data = []
    try:
        with open(args.playback, "r") as f:
            playback_data = json.load(f)
    except Exception as e:
        print(f"{C_RED}Failed to load playback file: {args.playback}{C_END}")
        sys.exit(1)
        
    start_time = time.time()
    
    try:
        while True:
            elapsed = time.time() - start_time
            
            # Find current playback state
            current_state = playback_data[0]
            for state in playback_data:
                if elapsed >= state.get("time_offset", 0):
                    current_state = state
                    
            mode = "AUTO"
            artifacts = current_state.get("artifacts", [])
            
            # Drain battery normally
            battery -= 0.1
            if random.random() > 0.8 and current_wp < waypoints:
                current_wp += 1
                
            drone_state = "NORMAL"
            gps_status = "NORMAL"
            signal_strength = random.randint(85, 95)
            deviation_m = random.randint(0, 5)
            if "DF_MUTEX_01" in artifacts:
                drone_state = "PERSISTENCE_DETECTED"
            if "c2.dronefleet.net" in artifacts:
                drone_state = "C2_CONNECTED"
            
            altitude = max(0, altitude + current_state.get("alt_change", 0))
            speed = current_state.get("speed", 40)
            
            if dynamic_phase in ["gps_drift", "spoof"]:
                drone_state = "GPS_DRIFT"
                gps_status = "SPOOFED"
                deviation_m = random.randint(110, 130)
            elif dynamic_phase in ["mission_failure", "impact"]:
                drone_state = "MISSION_FAILURE"
                gps_status = "LOST"
                deviation_m = random.randint(300, 500)
                battery -= 5.0
            
            payload = {
                "type": "telemetry",
                "drone_id": drone_id,
                "timestamp": time.time(),
                "battery": max(0, round(battery, 1)),
                "gps_status": gps_status,
                "signal_strength": signal_strength,
                "telemetry_status": "ONLINE" if battery > 0 else "OFFLINE",
                "telemetry": {
                    "lat": 37.7749 + (random.random() * 0.01),
                    "lng": -122.4194 + (random.random() * 0.01),
                    "alt": 100.5 + (random.random() * 5.0),
                    "speed": 15.2,
                    "heading": 90.0
                },
                "status": {
                    "mode": mode,
                    "armed": True,
                    "beacon_interval": 5.0,
                    "telemetry_mode": mode,
                    "drone_state": drone_state,
                    "flight_mode": "DEGRADED" if gps_status == "SPOOFED" else "AUTO",
                    "fleet_role": fleet_role,
                    "mission_context": {
                        "mission": "Powerline Inspection",
                        "mission_phase": "OFF_ROUTE" if gps_status in ["SPOOFED", "LOST"] else f"WAYPOINT_{current_wp}",
                        "waypoints": waypoints,
                        "current_waypoint": current_wp,
                        "deviation_m": deviation_m
                    },
                },
                "artifact_strings": artifacts
            }
            
            print(f"[{time.strftime('%H:%M:%S')}] State: {drone_state} | Mode: {mode} | Batt: {battery}% | Speed: {speed} | Artifacts: {artifacts}")
            
            if not send_payload(sock, payload):
                print(f"\n{C_RED}[!] CONNECTION LOST.{C_END}")
                break
            
            if battery <= 0:
                print(f"\n{C_RED}[!] CRITICAL: BATTERY 0%. CONNECTION LOST.{C_END}")
                print(f"{C_RED}[!] WARNING: {drone_id} IS IN FREE FALL AND CURRENTLY OFFLINE!{C_END}\n")
                break
                
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\nSimulator stopped.")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
