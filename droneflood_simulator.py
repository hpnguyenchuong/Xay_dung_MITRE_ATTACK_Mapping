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
                fleet = data.get("drones", [])
                
                # Chuyển đổi list thành list với drone_id được giữ lại
                drone_list = []
                for drone_info in fleet:
                    drone_id = drone_info.get("drone_id", "Unknown")
                    battery = drone_info.get("battery", 0)
                    
                    # ⚡ CHỈ LẤY DRONE CÒN PIN VÀ ĐANG ONLINE
                    if battery <= 0 or drone_info.get("status") == "OFFLINE":
                        continue
                    
                    drone_list.append({
                        "id": drone_id,
                        "status": drone_info.get("status", "UNKNOWN"),
                        "threat_score": drone_info.get("threat_score", 0),
                        "battery": battery,
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
        print("+" + "="*64 + "+")
        print(f"|  [X] COMPROMISING DRONE: {drone_id}                              |")
        print("+" + "-"*64 + "+")
        print("|  [~] Sending compromise payload...                              |")
        print("|  [~] Establishing backdoor channel...                           |")
        print("+" + "="*64 + "+")
        print(f"{C_END}")
        
        result = self.send_command_to_drone(drone_id, "compromise")
        
        if result.get("success"):
            self.compromised_drones.append(drone_id)
            print(f"{C_GREEN}[OK] Drone {drone_id} has been compromised!{C_END}")
            return True
        else:
            print(f"{C_RED}[FAIL] Failed to compromise {drone_id}{C_END}")
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
        """Hiển thị menu tương tác (gọn hơn)"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        print(f"{C_CYAN}{C_BOLD}")
        print("+" + "="*84 + "+")
        print(f"|{'DRONEFLOOD ATTACK CONTROLLER'.center(84)}|")
        print("+" + "="*84 + "+")
        line1 = f"  [C2] Target: {self.c2_ip}:{self.c2_port}"
        line2 = f"  [ID] Attacker ID: {self.attacker_id}"
        line3 = f"  [OK] Compromised: {len(self.compromised_drones)} | Auto-refresh: 5s"
        print(f"|{line1.ljust(84)}|")
        print(f"|{line2.ljust(84)}|")
        print(f"|{line3.ljust(84)}|")
        print("+" + "="*84 + "+")
        print(f"{C_END}")
        
        # Hiển thị danh sách drone với cột Battery
        print(f"\n{C_CYAN}[+] AVAILABLE DRONES:{C_END}")
        print("+" + "-"*4 + "+" + "-"*18 + "+" + "-"*17 + "+" + "-"*10 + "+" + "-"*18 + "+" + "-"*10 + "+")
        print("| #  | Drone ID         | Status          | Battery  | Threat Score     | Select   |")
        print("+" + "-"*4 + "+" + "-"*18 + "+" + "-"*17 + "+" + "-"*10 + "+" + "-"*18 + "+" + "-"*10 + "+")
        
        for i, drone in enumerate(drones[:15]):
            drone_id = drone.get("id", "Unknown")[:16]
            try:
                battery = float(drone.get("battery", 0))
            except (ValueError, TypeError):
                battery = 0.0
            batt_str = f"{battery:.1f}%"
            
            # Màu battery
            if battery <= 15:
                batt_color = C_RED
            elif battery <= 40:
                batt_color = C_YELLOW
            else:
                batt_color = C_GREEN
            
            if drone_id in self.compromised_drones:
                status_text = "[X] COMPROMISED"
                selected = "X"
            else:
                status_text = "[ ] CLEAN"
                selected = " "
            
            threat = str(drone.get("threat_score", 0))
            
            col_id = f"{i+1:2}"
            col_drone = drone_id.ljust(16)
            col_status = status_text.ljust(15)
            col_batt = batt_str.ljust(8)
            col_threat = threat.rjust(16)
            col_sel = f"[{selected}]".center(8)
            
            print(f"| {col_id} | {col_drone} | {col_status} | {batt_color}{col_batt}{C_END} | {col_threat} | {col_sel} |")
        
        print("+" + "-"*4 + "+" + "-"*18 + "+" + "-"*17 + "+" + "-"*10 + "+" + "-"*18 + "+" + "-"*10 + "+")
        
        # Hiển thị menu tấn công
        print(f"\n{C_YELLOW}[!] ATTACK OPTIONS:{C_END}")
        print("  1. GPS Spoof (T0831)     - Lam sai lech toa do GPS")
        print("  2. Battery Drain (T0879) - Rut can pin nhanh chong")
        print("  3. IMU Drift (T0832)     - Lam nhieu cam bien goc")
        print("  4. LiDAR Jamming (T0831) - Vo hieu hoa tranh vat can")
        print("  5. Collision (T0831)     - Gay va cham voi drone khac")
        print("  6. Emergency Land        - Ha canh khan cap")
        print("  7. Compromise New        - Chiem quyen drone moi")
        print("  0. Exit")
        
        print(f"\n{C_CYAN}[i] Compromised drones: {len(self.compromised_drones)}{C_END}")
        if self.compromised_drones:
            print(f"{C_CYAN}[i] Compromised list: {', '.join(self.compromised_drones[:5])}{'...' if len(self.compromised_drones) > 5 else ''}{C_END}")

    def handle_compromise(self, drones):
        """Xử lý chức năng compromise (tách ra để code gọn)"""
        print("\n" + "=" * 60)
        print("[+] SELECT DRONE(S) TO COMPROMISE")
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
                    try:
                        start, end = map(int, part.split("-"))
                        indices_to_compromise.extend(range(start - 1, end))
                    except ValueError:
                        pass
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
            return
        
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

    def handle_attack(self, choice):
        """Xử lý chọn attack"""
        if not self.compromised_drones:
            print(f"{C_RED}[!] No compromised drones! Compromise one first (option 7).{C_END}")
            time.sleep(2)
            return
        
        print("\n🎯 Select target drone (compromised only):")
        for i, drone_id in enumerate(self.compromised_drones):
            print(f"  {i+1}. {drone_id}")
        
        drone_choice = input(">>> Enter number (or 0 to cancel): ").strip()
        if drone_choice == "0":
            return
            
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

    def run_interactive(self):
        """Chạy chế độ tương tác với auto-refresh mỗi 5 giây"""
        print(f"{C_GREEN}[+] DroneFlood Simulator started{C_END}")
        print(f"{C_CYAN}[i] Auto-refresh every 5 seconds | Press ENTER to interact{C_END}\n")
        
        # Start HTTP server để nhận lệnh
        threading.Thread(target=self.run_http_server, daemon=True).start()
        
        # Biến để theo dõi input không block
        import select
        import sys
        
        last_refresh = 0
        drones = []  # Lưu danh sách drone hiện tại
        
        while self.running:
            current_time = time.time()
            
            # Refresh danh sách drone mỗi 5 giây
            if current_time - last_refresh >= 5:
                # Fetch danh sách drone mới (đã lọc hết pin)
                new_drones = self.fetch_drones()
                
                # Lấy danh sách drone_id còn sống
                active_ids = {d.get("id") for d in new_drones}
                
                # ⚡ XÓA DRONE HẾT pin KHỎI COMPROMISED LIST
                self.compromised_drones = [
                    d_id for d_id in self.compromised_drones 
                    if d_id in active_ids
                ]
                
                if new_drones:
                    # Cập nhật danh sách drone (giữ nguyên compromised)
                    old_compromised = self.compromised_drones.copy()
                    drones = new_drones
                    # Khôi phục compromised status cho drone đã biết
                    for drone in drones:
                        drone_id = drone.get("id", "Unknown")
                        if drone_id in old_compromised and drone_id not in self.compromised_drones:
                            self.compromised_drones.append(drone_id)
                else:
                    print(f"{C_YELLOW}[!] No active drones found (all may be offline/dead).{C_END}")
                
                # Hiển thị menu mới
                if drones:
                    self.show_menu(drones)
                    print(f"\n{C_BOLD}>>> Select action (0-7): {C_END}", end="", flush=True)
                
                last_refresh = current_time
            
            # Kiểm tra input từ người dùng (không block), dùng timeout ngắn
            if sys.platform == 'win32':
                import msvcrt
                if msvcrt.kbhit():
                    choice = sys.stdin.readline().strip()
                    
                    if choice == "0":
                        print(f"{C_YELLOW}[!] Shutting down...{C_END}")
                        self.running = False
                        break
                    
                    elif choice == "7":
                        # Compromise new drone(s)
                        self.handle_compromise(drones)
                        last_refresh = 0 # force refresh
                    
                    elif choice in ["1", "2", "3", "4", "5", "6"]:
                        self.handle_attack(choice)
                        last_refresh = 0 # force refresh
                    
                    else:
                        print(f"{C_YELLOW}[!] Invalid option. Choose 0-7.{C_END}")
                        time.sleep(1)
            else:
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    choice = sys.stdin.readline().strip()
                    
                    if choice == "0":
                        print(f"{C_YELLOW}[!] Shutting down...{C_END}")
                        self.running = False
                        break
                    
                    elif choice == "7":
                        # Compromise new drone(s)
                        self.handle_compromise(drones)
                        last_refresh = 0 # force refresh
                    
                    elif choice in ["1", "2", "3", "4", "5", "6"]:
                        self.handle_attack(choice)
                        last_refresh = 0 # force refresh
                    
                    else:
                        print(f"{C_YELLOW}[!] Invalid option. Choose 0-7.{C_END}")
                        time.sleep(1)
            
            # Không sleep quá lâu để vẫn nhận input
            time.sleep(0.1)
    
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
        
        class ThreadingReusableServer(HTTPServer):
            allow_reuse_address = True
            
        server = ThreadingReusableServer(("0.0.0.0", self.http_port), CommandHandler)
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
