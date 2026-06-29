import subprocess
import time

print("[*] Starting Wireshark capture...")
pcap_proc = subprocess.Popen(["tshark", "-i", "1", "-w", "network_capture.pcap", "-f", "tcp port 5555"])

print("[*] Launching malware sample...")
malware_proc = subprocess.Popen(["drone_client.exe"])

time.sleep(10) # Let it run for 10 seconds

print("[*] Stopping analysis...")
malware_proc.terminate()
pcap_proc.terminate()
print("[+] PCAP saved to network_capture.pcap")
