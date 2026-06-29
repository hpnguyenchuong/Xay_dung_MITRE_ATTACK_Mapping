from scapy.all import rdpcap, TCP, IP
import csv
from pathlib import Path

PCAP_PATH = Path("../network_capture.pcap")
OUT_PATH = Path("../network_iocs.csv")

def main():
    rows = []

    packets = rdpcap(str(PCAP_PATH))

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            payload = bytes(pkt[TCP].payload)
            text = payload.decode(errors="ignore")

            if payload:
                rows.append({
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "src_port": pkt[TCP].sport,
                    "dst_port": pkt[TCP].dport,
                    "payload_preview": text[:120],
                    "contains_fleet_sync": "FLEET_SYNC" in text,
                    "contains_command_push": "FLEET_COMMAND_PUSH" in text,
                    "contains_c2": "c2.dronefleet.net" in text
                })

    with OUT_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "src_ip", "dst_ip", "src_port", "dst_port",
            "payload_preview",
            "contains_fleet_sync",
            "contains_command_push",
            "contains_c2"
        ])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Exported {len(rows)} network IOC rows to {OUT_PATH}")

if __name__ == "__main__":
    main()
