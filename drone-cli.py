#!/usr/bin/env python3
import requests
import json
import sys
import argparse

C2_URL = "http://localhost:9000/api/cli"

def send_command(cmd, drone_id=None):
    data = {"command": cmd}
    if drone_id:
        data["drone_id"] = drone_id
    try:
        resp = requests.post(C2_URL, json=data)
        result = resp.json()
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Drone CLI Tool")
    parser.add_argument("command", help="Command to execute")
    parser.add_argument("--drone", help="Drone ID")
    parser.add_argument("--c2", default="localhost:9000", help="C2 Server")
    args = parser.parse_args()
    
    C2_URL = f"http://{args.c2}/api/cli"
    send_command(args.command, args.drone)
