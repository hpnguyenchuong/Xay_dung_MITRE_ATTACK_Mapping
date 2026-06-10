#!/usr/bin/env python3
"""
DRONE CLIENT - Victim Drone Simulator (Ubuntu)
Chạy bình thường, có backdoor để bị chiếm quyền
"""

import socket
import sys
import time
import json
import base64
import random
import threading
import argparse
import math
from datetime import datetime

C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_BOLD = "\033[1m"
C_END = "\033[0m"

class TransportObfuscationLayer:
    @staticmethod
    def obfuscate(data_str: str) -> bytes:
        xored = bytes([b ^ 0x42 for b in data_str.encode('utf-8')])
        return base64.b64encode(xored)
    
    @staticmethod
    def deobfuscate(cipher_bytes: bytes) -> str:
        decoded = base64.b64decode(cipher_bytes)
        return bytes([b ^ 0x42 for b in decoded]).decode('utf-8')


class DroneVictim:
    """Drone client có thể bị chiếm quyền và tấn công"""
    
    def __init__(self, c2_ip, c2_port, drone_id=None):
        self.c2_ip = c2_ip
        self.c2_port = c2_port
        self.drone_id = drone_id or f"DRONE-{random.randint(100, 999)}"
        
        # Trạng thái hoạt động
        self.state = "NORMAL"  # NORMAL, COMPROMISED, UNDER_ATTACK, CRITICAL, OFFLINE
        self.compromised_at = None
        self.attacker_sock = None
        
        # Dữ liệu telemetry bình thường
        self.battery = 100
        self.gps = {"lat": 10.841, "lng": 106.654}
        self.altitude = 120
        self.speed = 40
        self.temperature = 35
        self.satellites = 12
        
        # Artifact tracking
        self.active_artifacts = []
        self.campaign_stage = "NORMAL"
        self.threat_score = 0
        
        # Attack flags
        self.gps_spoof_active = False
        self.battery_drain_active = False
        self.imu_drift_active = False
        self.target_gps = None
        self.battery_drain_rate = 0.1  # Bình thường giảm 0.1%/giây
        
        # Flight data
        self.heading = 90
        self.roll = 0
        self.pitch = 0
        
        # Socket
        self.sock = None
        self.running = True
        
    def connect(self):
        """Kết nối đến C2 server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5.0)
        self.sock.connect((self.c2_ip, self.c2_port))
        self.sock.settimeout(None)
        print(f"{C_GREEN}[+] Connected to C2 at {self.c2_ip}:{self.c2_port}{C_END}")
        return True
    
    def register(self):
        """Đăng ký với C2 server (telemetry sạch)"""
        reg_packet = {
            "type": "register",
            "profile_type": "CLIENT",
            "drone_id": self.drone_id,
            "fleet_id": "fleet_alpha",
            "ip": "10.0.0." + str(random.randint(10, 250)),
            "timestamp": time.time(),
            "profile": {
                "family": "CleanDrone",
                "version": "baseline-1.0",
                "campaign": "Baseline",
                "c2_protocol": "Telemetry-TCP",
                "obfuscation": "None",
                "capabilities": ["clean_telemetry", "mission_reporting"]
            },
            "config": {"obfuscation": "None"}
        }
        self.send_packet(reg_packet)
        print(f"{C_GREEN}[+] Registered as CLEAN drone: {self.drone_id}{C_END}")
    
    def send_packet(self, packet):
        """Gửi packet (có obfuscation)"""
        try:
            data_str = json.dumps(packet)
            cipher_bytes = TransportObfuscationLayer.obfuscate(data_str)
            self.sock.sendall(cipher_bytes + b"\n")
            return True
        except Exception as e:
            print(f"{C_RED}[!] Failed to send: {e}{C_END}")
            return False
    
    def compromise(self):
        """Bị chiếm quyền - chuyển sang trạng thái COMPROMISED"""
        if self.state == "NORMAL":
            self.state = "COMPROMISED"
            self.compromised_at = time.time()
            self.active_artifacts = ["DF_MUTEX_01", "c2.dronefleet.net"]
            self.campaign_stage = "PERSISTENCE"
            self.threat_score = 35
            print(f"\n{C_RED}{C_BOLD}")
            print("╔════════════════════════════════════════════════════════════════╗")
            print(f"║  🔴 DRONE {self.drone_id} HAS BEEN COMPROMISED!                 ║")
            print("║  📡 Backdoor channel established                                ║")
            print("║  🎯 Awaiting attack commands...                                 ║")
            print("╚════════════════════════════════════════════════════════════════╝")
            print(f"{C_END}")
            return True
        return False
    
    def execute_command(self, command):
        """Thực thi lệnh từ attacker"""
        cmd_type = command.get("cmd")
        params = command.get("params", {})
        
        # Tính chiều dài của lệnh để đóng khung vừa khít
        cmd_display = cmd_type.upper().replace("_", " ")
        border_len = len(cmd_display) + 20
        if border_len < 60:
            border_len = 60
        
        print(f"\n{C_RED}{C_BOLD}")
        print("┌" + "─" * border_len + "┐")
        
        def print_line(msg):
            print(f"│{msg.ljust(border_len)}│")
            
        print_line(f"  ATTACK COMMAND: {cmd_display}")
        print("├" + "─" * border_len + "┤")
        
        # Lệnh chiếm quyền
        if cmd_type == "compromise":
            print_line("  Status: Drone is being compromised")
            print_line("  Effect: Backdoor channel established")
            self.compromise()
            
        # Lệnh GPS Spoof
        elif cmd_type == "gps_spoof":
            self.gps_spoof_active = True
            self.target_gps = params
            self.state = "UNDER_ATTACK"
            if "gps_spoof" not in self.active_artifacts:
                self.active_artifacts.append("gps_spoof")
            self.campaign_stage = "GPS_SPOOF"
            self.threat_score = 65
            target_str = f"lat={self.target_gps.get('lat')}, lng={self.target_gps.get('lng')}"
            print_line("  Status: GPS spoofing activated")
            print_line(f"  Target: {target_str}")
            print_line("  Effect: Drone will fly to fake coordinates")
            
        # Lệnh IMU Drift
        elif cmd_type == "imu_drift":
            self.imu_drift_active = True
            self.state = "UNDER_ATTACK"
            if "imu_drift_injection" not in self.active_artifacts:
                self.active_artifacts.append("imu_drift_injection")
            self.threat_score = 80
            rate = params.get("drift_rate", 15)
            print_line("  Status: IMU drift activated")
            print_line(f"  Rate: {rate} degrees/second")
            print_line("  Effect: Attitude angles will be corrupted")
            
        # Lệnh Battery Drain
        elif cmd_type == "battery_drain":
            self.battery_drain_active = True
            self.battery_drain_rate = params.get("rate", 5.0)
            self.state = "UNDER_ATTACK"
            if "battery_drain" not in self.active_artifacts:
                self.active_artifacts.append("battery_drain")
            self.threat_score = 85
            print_line("  Status: Battery drain activated")
            print_line(f"  Rate: {self.battery_drain_rate}%/second")
            seconds = int(100 / self.battery_drain_rate) if self.battery_drain_rate > 0 else 0
            print_line(f"  Effect: Battery will deplete in ~{seconds} seconds")
            
        # Lệnh LiDAR Jamming
        elif cmd_type == "lidar_jamming":
            self.state = "UNDER_ATTACK"
            if "lidar_jamming" not in self.active_artifacts:
                self.active_artifacts.append("lidar_jamming")
            print_line("  Status: LiDAR jamming activated")
            print_line("  Effect: Obstacle detection disabled")
            
        # Lệnh Collision
        elif cmd_type == "collision":
            self.state = "UNDER_ATTACK"
            if "collision_vector" not in self.active_artifacts:
                self.active_artifacts.append("collision_vector")
            self.threat_score = 100
            target = params.get("target", "Unknown")
            print_line("  Status: COLLISION COMMAND ACTIVATED")
            print_line(f"  Target: {target}")
            print_line("  Effect: Waypoint override - collision imminent")
            
        # Lệnh Emergency Landing
        elif cmd_type == "emergency_land":
            self.state = "CRITICAL"
            if "forced_landing" not in self.active_artifacts:
                self.active_artifacts.append("forced_landing")
            print_line("  Status: EMERGENCY LANDING ACTIVATED")
            print_line("  Effect: Drone will attempt forced landing")
            
        # Lệnh Stop Attack
        elif cmd_type == "stop_attack":
            self.gps_spoof_active = False
            self.imu_drift_active = False
            self.battery_drain_active = False
            self.battery_drain_rate = 0.1
            print_line("  Status: All attacks stopped")
            print_line("  Effect: Returning to normal operation")
        
        print("└" + "─" * border_len + "┘")
        print(f"{C_END}")
        
        return True
    
    def listen_for_commands(self):
        """Lắng nghe lệnh từ C2/Attacker"""
        buffer = ""
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                buffer += data.decode('utf-8')
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if not line.strip():
                        continue
                    try:
                        raw = TransportObfuscationLayer.deobfuscate(line.strip().encode('utf-8'))
                        command = json.loads(raw)
                        self.execute_command(command)
                    except Exception as e:
                        print(f"{C_RED}[!] Command parse error: {e}{C_END}")
            except Exception as e:
                if self.running:
                    print(f"{C_RED}[!] Listener error: {e}{C_END}")
                break
    
    def update_telemetry(self):
        """Cập nhật dữ liệu telemetry dựa trên trạng thái"""
        
        # GPS Spoof effect
        if self.gps_spoof_active and self.target_gps:
            self.gps = self.target_gps
        else:
            # Normal movement
            self.gps["lat"] += random.uniform(-0.00012, 0.00012)
            self.gps["lng"] += random.uniform(-0.00012, 0.00012)
        
        # Battery drain effect
        if self.battery_drain_active:
            self.battery -= self.battery_drain_rate * 5  # Mỗi 5 giây
        else:
            self.battery -= 0.1  # Normal drain
        
        # IMU Drift effect
        if self.imu_drift_active:
            self.roll += random.uniform(-10, 10)
            self.pitch += random.uniform(-10, 10)
            self.heading += random.uniform(-20, 20)
        
        # Altitude changes
        self.altitude += random.uniform(-2, 2)
        self.altitude = max(0, min(500, self.altitude))
        
        # Temperature
        if self.battery_drain_active:
            self.temperature += random.uniform(1, 3)
        else:
            self.temperature += random.uniform(-0.5, 0.5)
        self.temperature = max(25, min(80, self.temperature))
        
        # Satellites (GPS spoof affects satellite count)
        if self.gps_spoof_active:
            self.satellites = random.randint(0, 5)
        else:
            self.satellites = random.randint(8, 18)
        
        # Speed
        if self.imu_drift_active:
            self.speed = random.randint(20, 80)
        else:
            self.speed = random.randint(35, 65)
        
        # Check for critical state
        if self.battery <= 15:
            self.state = "CRITICAL"
            if "critical_battery" not in self.active_artifacts:
                self.active_artifacts.append("critical_battery")
        
        if self.battery <= 0:
            self.state = "OFFLINE"
    
    def get_telemetry(self):
        """Lấy packet telemetry hiện tại"""
        self.update_telemetry()
        
        telemetry = {
            "type": "telemetry",
            "drone_id": self.drone_id,
            "timestamp": time.time(),
            "battery": round(max(0, self.battery), 1),
            "gps": f"{self.gps['lat']:.6f},{self.gps['lng']:.6f}",
            "altitude": round(self.altitude, 1),
            "speed": round(self.speed, 1),
            "temperature": round(self.temperature, 1),
            "satellites": self.satellites,
            "heading": round(self.heading, 1),
            "roll": round(self.roll, 1),
            "pitch": round(self.pitch, 1),
            "state": self.state,
            "campaign_stage": self.campaign_stage,
            "artifact_strings": self.active_artifacts.copy(),
            "threat_score": self.threat_score
        }
        return telemetry
    
    def run(self):
        """Vòng lặp chính"""
        # Connect and register
        if not self.connect():
            return
        
        self.register()
        
        # Start command listener thread
        listener_thread = threading.Thread(target=self.listen_for_commands, daemon=True)
        listener_thread.start()
        
        print(f"{C_CYAN}[i] Drone {self.drone_id} is running...{C_END}")
        print(f"{C_CYAN}[i] State: {self.state} | Threat Score: {self.threat_score}{C_END}\n")
        
        # Main telemetry loop
        last_print = time.time()
        while self.running and self.state != "OFFLINE":
            telemetry = self.get_telemetry()
            self.send_packet(telemetry)
            
            # Print status every 5 seconds
            if time.time() - last_print >= 5:
                status_color = C_GREEN
                if self.state == "COMPROMISED":
                    status_color = C_YELLOW
                elif self.state == "UNDER_ATTACK":
                    status_color = C_RED
                elif self.state == "CRITICAL":
                    status_color = C_RED + C_BOLD
                
                print(f"{status_color}[{datetime.now().strftime('%H:%M:%S')}] {self.drone_id} | "
                      f"State: {self.state} | Batt: {telemetry['battery']}% | "
                      f"GPS: {telemetry['gps']} | Artifacts: {len(self.active_artifacts)}{C_END}")
                last_print = time.time()
            
            time.sleep(5)
        
        if self.state == "OFFLINE":
            print(f"\n{C_RED}{C_BOLD}[!] DRONE {self.drone_id} IS OFFLINE!{C_END}")
        
        self.sock.close()


def main():
    parser = argparse.ArgumentParser(description="Drone Client with Backdoor")
    parser.add_argument("c2_ip", help="C2 Server IP")
    parser.add_argument("c2_port", type=int, nargs='?', default=5555, help="C2 Server Port")
    parser.add_argument("--drone-id", type=str, default=None, help="Custom drone ID")
    args = parser.parse_args()
    
    print(f"{C_CYAN}")
    print("   ____                      __ _      __")
    print("  / __ \\____ _   __ ___  ___/ /(_)____/ /")
    print(" / / / / __ \\ | / // _ \\/ _  // // __  / ")
    print("/ /_/ / /_/ / |/ //  __/ /_/ // // /_/ /  ")
    print("\\____/ .___/|___/ \\___/\\__,_//_/ \\__,_/   ")
    print("    /_/                                  ")
    print(f"{C_END}")
    
    drone = DroneVictim(args.c2_ip, args.c2_port, args.drone_id)
    
    try:
        drone.run()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] Drone {drone.drone_id} shutting down...{C_END}")
        drone.running = False


if __name__ == "__main__":
    main()
