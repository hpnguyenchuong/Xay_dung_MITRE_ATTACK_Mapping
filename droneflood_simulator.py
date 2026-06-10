#!/usr/bin/env python3
"""
DRONEFLOOD SIMULATOR - Attack Tool (Kali)
Nhận lệnh từ C2, thực thi tấn công, báo trạng thái
"""

import socket
import sys
import time
import json
import base64
import random
import threading
import uuid
import urllib.request
import urllib.error
import argparse
import os
from datetime import datetime

C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
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


class DroneFloodSimulator:
    """Attack Simulator - có thể nhận lệnh từ C2 và thực thi tấn công"""
    
    def __init__(self, c2_ip, c2_port, web_port=9000):
        self.c2_ip = c2_ip
        self.c2_port = c2_port
        self.web_port = web_port
        self.attacker_id = f"ATTACKER-{random.randint(100, 999)}"
        self.running = True
        
        # Danh sách drone đã chiếm được (lưu drone_id)
        self.compromised_drones = []
        
        # HTTP server để nhận lệnh từ C2
        self.http_port = 5557
        self.http_server = None
        
    def fetch_drones(self):
        """Lấy danh sách drone từ C2 API"""
        try:
            url = f"http://{self.c2_ip}:{self.web_port}/api/drones"
            with urllib.request.urlopen(url, timeout=3) as res:
                data = json.loads(res.read().decode())
                fleet = data.get("fleet", {})
                
                # Chuyển đổi dict thành list với drone_id được giữ lại
                drone_list = []
                for drone_id, drone_info in fleet.items():
                    drone_list.append({
                        "id": drone_id,
                        "status": drone_info.get("status", "UNKNOWN"),
                        "threat_score": drone_info.get("threat_score", 0),
                        "battery": drone_info.get("battery", 0),
                        "campaign_stage": drone_info.get("campaign_stage", "NORMAL")
                    })
                return drone_list
        except Exception as e:
            print(f"{C_YELLOW}[!] Cannot fetch drones: {e}{C_END}")
            return []
    
    def send_command_to_drone(self, drone_id, command, params=None):
        """Gửi lệnh tấn công đến drone thông qua C2"""
        try:
            url = f"http://{self.c2_ip}:{self.web_port}/api/attack"
            data = json.dumps({
                "drone_id": drone_id,
                "command": command,
                "params": params or {}
            }).encode()
            
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            
            with urllib.request.urlopen(req, timeout=5) as res:
                result = json.loads(res.read().decode())
                return result
        except Exception as e:
            print(f"{C_RED}[!] Failed to send command: {e}{C_END}")
            return {"success": False}
    
    def compromise_drone(self, drone_id):
        """Chiếm quyền một drone"""
        if drone_id in self.compromised_drones:
            print(f"{C_YELLOW}[!] Drone {drone_id} already compromised!{C_END}")
            return False
            
        print(f"\n{C_RED}{C_BOLD}")
        print("╔════════════════════════════════════════════════════════════════╗")
        print(f"║  🔴 COMPROMISING DRONE: {drone_id}                              ║")
        print("╠════════════════════════════════════════════════════════════════╣")
        print("║  📡 Sending compromise payload...                              ║")
        print("║  🔑 Establishing backdoor channel...                           ║")
        print("╚════════════════════════════════════════════════════════════════╝")
        print(f"{C_END}")
        
        result = self.send_command_to_drone(drone_id, "compromise")
        
        if result.get("success"):
            self.compromised_drones.append(drone_id)
            print(f"{C_GREEN}✅ Drone {drone_id} has been compromised!{C_END}")
            return True
        else:
            print(f"{C_RED}❌ Failed to compromise {drone_id}{C_END}")
            return False
    
    def launch_attack(self, drone_id, attack_type, params=None):
        """Phát động tấn công lên drone"""
        
        attack_names = {
            "gps_spoof": "GPS SPOOFING",
            "battery_drain": "BATTERY DRAIN",
            "imu_drift": "IMU DRIFT",
            "lidar_jamming": "LIDAR JAMMING",
            "collision": "COLLISION",
            "emergency_land": "EMERGENCY LANDING"
        }
        
        mitre_ids = {
            "gps_spoof": "T0831",
            "battery_drain": "T0879",
            "imu_drift": "T0832",
            "lidar_jamming": "T0831",
            "collision": "T0831",
            "emergency_land": "T0831"
        }
        
        name = attack_names.get(attack_type, attack_type.upper())
        mitre_id = mitre_ids.get(attack_type, "Unknown")
        
        # Tính chiều dài khung
        title = f"LAUNCHING {name} ({mitre_id})"
        border_len = len(title) + 12
        if border_len < 60:
            border_len = 60
        
        print(f"\n{C_RED}{C_BOLD}")
        print("┌" + "─" * border_len + "┐")
        
        def print_line(msg):
            print(f"│{msg.ljust(border_len)}│")
            
        print_line(f"  {title}")
        print("├" + "─" * border_len + "┤")
        print_line(f"  Target: {drone_id}")
        
        # Thông tin thêm theo loại tấn công
        if attack_type == "gps_spoof":
            lat = params.get("lat", "10.900") if params else "10.900"
            lng = params.get("lng", "106.700") if params else "106.700"
            print_line(f"  Parameter: lat={lat}, lng={lng}")
        elif attack_type == "battery_drain":
            rate = params.get("rate", 5.0) if params else 5.0
            print_line(f"  Parameter: rate={rate}%/second")
        elif attack_type == "imu_drift":
            rate = params.get("drift_rate", 15) if params else 15
            print_line(f"  Parameter: drift_rate={rate} deg/s")
        elif attack_type == "collision":
            target = params.get("target", "DRONE-999") if params else "DRONE-999"
            print_line(f"  Parameter: target={target}")
        
        print("├" + "─" * border_len + "┤")
        
        # Gửi lệnh
        result = self.send_command_to_drone(drone_id, attack_type, params)
        
        if result.get("success"):
            print_line("  Result: SUCCESS")
            print_line(f"  Command sent to {drone_id}")
        else:
            print_line("  Result: FAILED")
            error = result.get("error", "Unknown error")[:40]
            print_line(f"  Error: {error}")
        
        print("└" + "─" * border_len + "┘")
        print(f"{C_END}")
        
        time.sleep(2)
        return result.get("success", False)
    
    def show_menu(self, drones):
        """Hiển thị menu tương tác"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        print(f"{C_CYAN}{C_BOLD}")
        print("╔════════════════════════════════════════════════════════════════════════════════════╗")
        print("║                         🔥 DRONEFLOOD ATTACK CONTROLLER 🔥                          ║")
        print("╠════════════════════════════════════════════════════════════════════════════════════╣")
        print(f"║  📡 C2 Target: {self.c2_ip}:{self.c2_port}                                           ║")
        print(f"║  🆔 Attacker ID: {self.attacker_id}                                                 ║")
        print(f"║  🤖 Compromised drones: {len(self.compromised_drones)}                              ║")
        print("╚════════════════════════════════════════════════════════════════════════════════════╝")
        print(f"{C_END}")
        
        # Hiển thị danh sách drone
        print(f"\n{C_CYAN}📡 AVAILABLE DRONES:{C_END}")
        print("┌────┬──────────────────┬──────────────┬──────────────────┬──────────┐")
        print("│ #  │ Drone ID         │ Status       │ Threat Score     │ Select   │")
        print("├────┼──────────────────┼──────────────┼──────────────────┼──────────┤")
        
        for i, drone in enumerate(drones[:15]):
            drone_id = drone.get("id", "Unknown")
            if drone_id in self.compromised_drones:
                status = f"{C_RED}COMPROMISED{C_END}"
                status_text = "🔴 COMPROMISED"
                selected = "✓"
            else:
                status = f"{C_GREEN}CLEAN{C_END}"
                status_text = "🟢 CLEAN"
                selected = " "
            threat = drone.get("threat_score", 0)
            print(f"│ {i+1:2} │ {drone_id:16} │ {status_text:12} │ {threat:16} │ [{selected}] │")
        
        print("└────┴──────────────────┴──────────────┴──────────────────┴──────────┘")
        
        # Hiển thị menu tấn công
        print(f"\n{C_YELLOW}⚔️ ATTACK OPTIONS:{C_END}")
        print("  1. GPS Spoof (T0831)     - Làm sai lệch tọa độ GPS")
        print("  2. Battery Drain (T0879) - Rút cạn pin nhanh chóng")
        print("  3. IMU Drift (T0832)     - Làm nhiễu cảm biến góc")
        print("  4. LiDAR Jamming (T0831) - Vô hiệu hóa tránh vật cản")
        print("  5. Collision (T0831)     - Gây va chạm với drone khác")
        print("  6. Emergency Land        - Hạ cánh khẩn cấp")
        print("  7. Compromise New        - Chiếm quyền drone mới")
        print("  0. Exit")
        
        print(f"\n{C_CYAN}[i] Compromised drones: {len(self.compromised_drones)}{C_END}")
        if self.compromised_drones:
            print(f"{C_CYAN}[i] Compromised list: {', '.join(self.compromised_drones)}{C_END}")
    
    def run_interactive(self):
        """Chạy chế độ tương tác"""
        print(f"{C_GREEN}[+] DroneFlood Simulator started{C_END}")
        print(f"{C_CYAN}[i] Listening for commands from C2 on port {self.http_port}{C_END}")
        
        # Start HTTP server để nhận lệnh
        threading.Thread(target=self.run_http_server, daemon=True).start()
        
        while self.running:
            # Fetch drone list
            drones = self.fetch_drones()
            
            if not drones:
                print(f"{C_YELLOW}[!] No drones found. Make sure drone_client is running!{C_END}")
                time.sleep(5)
                continue
            
            # Hiển thị menu
            self.show_menu(drones)
            
            # Nhận lựa chọn
            choice = input(f"\n{C_BOLD}>>> Select action: {C_END}").strip()
            
            if choice == "0":
                print(f"{C_YELLOW}[!] Shutting down...{C_END}")
                self.running = False
                break
            
            elif choice == "7":
                # Compromise new drone(s) - HỖ TRỢ NHIỀU DRONE CÙNG LÚC
                print("\n" + "=" * 60)
                print("📡 SELECT DRONE(S) TO COMPROMISE")
                print("=" * 60)
                print("  Format: 1,2,3  hoac 1 2 3  hoac 1-3  hoac all")
                print("-" * 60)
                
                for i, drone in enumerate(drones):
                    drone_id = drone.get("id", "Unknown")
                    if drone_id not in self.compromised_drones:
                        status_text = "CLEAN"
                        print(f"  {i+1}. {drone_id} [{status_text}]")
                    else:
                        status_text = "COMPROMISED"
                        print(f"  {i+1}. {drone_id} [{status_text}] - ALREADY DONE")
                
                print("-" * 60)
                drone_choice = input(">>> Enter numbers (ex: 1,2,3 or 1-3 or all): ").strip()
                
                if drone_choice.lower() == "all":
                    # Chọn tất cả drone chưa bị compromise
                    indices_to_compromise = [i for i, d in enumerate(drones) 
                                              if d.get("id", "Unknown") not in self.compromised_drones]
                else:
                    # Xử lý các định dạng: "1,2,3" hoặc "1 2 3" hoặc "1-3"
                    indices_to_compromise = []
                    
                    # Thay thế dấu phẩy và khoảng trắng
                    cleaned = drone_choice.replace(",", " ").replace("  ", " ")
                    
                    for part in cleaned.split():
                        if "-" in part:
                            # Xử lý range: 1-3
                            start, end = map(int, part.split("-"))
                            indices_to_compromise.extend(range(start - 1, end))
                        else:
                            # Xử lý số đơn lẻ
                            try:
                                idx = int(part) - 1
                                if 0 <= idx < len(drones):
                                    indices_to_compromise.append(idx)
                            except ValueError:
                                pass
                    
                    # Loại bỏ trùng lặp và sắp xếp
                    indices_to_compromise = sorted(set(indices_to_compromise))
                
                # Lọc chỉ lấy drone chưa bị compromise
                valid_indices = []
                for idx in indices_to_compromise:
                    if 0 <= idx < len(drones):
                        target = drones[idx].get("id", "Unknown")
                        if target not in self.compromised_drones:
                            valid_indices.append(idx)
                        else:
                            print(f"{C_YELLOW}[!] Drone {target} already compromised, skipped{C_END}")
                
                if not valid_indices:
                    print(f"{C_RED}[!] No valid drones selected!{C_END}")
                    time.sleep(2)
                    continue
                
                # Tiến hành compromise từng drone
                print(f"\n{C_CYAN}[i] Starting compromise on {len(valid_indices)} drone(s)...{C_END}\n")
                
                success_count = 0
                for idx in valid_indices:
                    target = drones[idx].get("id", "Unknown")
                    if self.compromise_drone(target):
                        success_count += 1
                    time.sleep(0.5)  # Delay nhẹ giữa các lần compromise
                
                print(f"\n{C_GREEN}[+] Compromise completed! Success: {success_count}/{len(valid_indices)}{C_END}")
                time.sleep(2)
            
            elif choice in ["1", "2", "3", "4", "5", "6"]:
                # Attack
                if not self.compromised_drones:
                    print(f"{C_RED}[!] No compromised drones! Compromise one first (option 7).{C_END}")
                    time.sleep(2)
                    continue
                
                print("\n🎯 Select target drone (compromised only):")
                for i, drone_id in enumerate(self.compromised_drones):
                    print(f"  {i+1}. {drone_id}")
                
                drone_choice = input(">>> Enter number (or 0 to cancel): ").strip()
                if drone_choice == "0":
                    continue
                    
                try:
                    idx = int(drone_choice) - 1
                    if 0 <= idx < len(self.compromised_drones):
                        target = self.compromised_drones[idx]
                        
                        attack_map = {
                            "1": ("gps_spoof", {"lat": 10.900, "lng": 106.700}),
                            "2": ("battery_drain", {"rate": 5.0}),
                            "3": ("imu_drift", {"drift_rate": 15}),
                            "4": ("lidar_jamming", {}),
                            "5": ("collision", {"target": "DRONE-999"}),
                            "6": ("emergency_land", {})
                        }
                        
                        attack_type, params = attack_map.get(choice, (None, None))
                        if attack_type:
                            self.launch_attack(target, attack_type, params)
                    else:
                        print(f"{C_RED}[!] Invalid choice{C_END}")
                except ValueError:
                    print(f"{C_RED}[!] Invalid input{C_END}")
                
                time.sleep(2)
            
            else:
                print(f"{C_YELLOW}[!] Invalid option. Choose 0-7.{C_END}")
                time.sleep(1)
    
    def run_http_server(self):
        """HTTP server để nhận lệnh từ C2"""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        class CommandHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.end_headers()
            
            def do_POST(self):
                if self.path == "/execute":
                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length)
                    
                    try:
                        cmd = json.loads(post_data.decode())
                        drone_id = cmd.get("drone_id")
                        attack_type = cmd.get("attack_type")
                        params = cmd.get("params", {})
                        
                        # Execute attack
                        success = self.server.simulator.launch_attack(drone_id, attack_type, params)
                        
                        self.send_response(200)
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"success": success}).encode())
                    except Exception as e:
                        self.send_response(500)
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                else:
                    self.send_response(404)
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
            
            def do_GET(self):
                if self.path == "/status":
                    self.send_response(200)
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    status = {
                        "compromised_drones": self.server.simulator.compromised_drones,
                        "attacker_id": self.server.simulator.attacker_id
                    }
                    self.wfile.write(json.dumps(status).encode())
                else:
                    self.send_response(404)
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
        
        server = HTTPServer(("0.0.0.0", self.http_port), CommandHandler)
        server.simulator = self
        print(f"{C_GREEN}[+] Attack HTTP server running on port {self.http_port}{C_END}")
        server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="DroneFlood Attack Simulator")
    parser.add_argument("c2_ip", help="C2 Server IP")
    parser.add_argument("c2_port", type=int, nargs='?', default=5555, help="C2 Server Port")
    parser.add_argument("--web-port", type=int, default=9000, help="Web UI Port")
    args = parser.parse_args()
    
    print(f"{C_RED}{C_BOLD}")
    print("   _____                      _ _____           _ ")
    print("  |  __ \\                    | |  ___|         | |")
    print("  | |  \\/ _ __  _ __ ___   __| | |__  _ __   __| |")
    print("  | | __ | '_ \\| '_ ` _ \\ / _` |  __|| '_ \\ / _` |")
    print("  | |_\\ \\| | | | | | | | | (_| | |___| | | | (_| |")
    print("   \\____/|_| |_|_| |_| |_|\\__,_\\____/|_| |_|\\__,_|")
    print("                                                 ")
    print(f"{C_END}")
    
    simulator = DroneFloodSimulator(args.c2_ip, args.c2_port, args.web_port)
    
    try:
        simulator.run_interactive()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}[!] Shutting down...{C_END}")


if __name__ == "__main__":
    main()
