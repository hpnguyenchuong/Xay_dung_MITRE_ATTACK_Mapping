<div align="center">
  
# 🚁 Drone Fleet Malware Mapping Engine
### Transparent & Explainable MITRE ATT&CK Mapping based on RE Findings

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/frontend-React%2018-61dafb.svg)](https://reactjs.org/)
[![Tailwind CSS](https://img.shields.io/badge/styling-TailwindCSS-38bdf8.svg)](https://tailwindcss.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-ff6666.svg)](https://attack.mitre.org/)

A specialized research framework designed to analyze **Reverse Engineering (RE)** artifacts from drone malware and automatically translate them into structured **Enterprise & ICS MITRE ATT&CK** matrices with high explainability.

---
</div>

## 📌 Project Overview
This project serves as a proof-of-concept for an **Explainable Mapping Engine** that bridges the gap between low-level forensic evidence (e.g., memory offsets, mutices, hardcoded IPs) and high-level operational impacts on autonomous drone fleets. 

Unlike black-box AI classifiers, this engine utilizes a **Candidate Competition Rule Engine** that explicitly scores and justifies every MITRE ATT&CK mapping decision.

## ✨ Core Features
- **🧠 Explainable Mapping Engine:** Evaluates multiple MITRE techniques for a single artifact and provides a deterministic confidence breakdown (Static, Dynamic, Memory, IOC, Analyst Validation).
- **🏭 ICS Impact Translation:** Automatically maps standard Enterprise tactics (e.g., C2 Beaconing) to critical ICS consequences (e.g., Loss of Telemetry, Navigation Deviation).
- **📊 Ground Truth Evaluation:** Built-in benchmarking against a validated dataset to prove academic accuracy (Precision, Recall, F1-Score).
- **🕹️ Live Campaign Simulator:** Includes a deterministic multi-threaded drone simulator (`droneflood_simulator.py`) to generate realistic C2 telemetry and infection states.
- **🗺️ ATT&CK Navigator Export:** Export the resulting mapping layers directly to `layer.json` for Threat Hunting integration.

## 🏗️ System Architecture
The repository consists of 3 core Python components and a modular React frontend:

1. **`drone.py` (Analysis Engine & API Gateway):** The brain of the operation. Handles telemetry intake, processes RE findings through the Rule Engine, maps to MITRE ATT&CK, and serves the UI.
2. **`drone_client.py` (Bot Agent):** Simulates a compromised drone node relaying C2 heartbeats and local infection status.
3. **`droneflood_simulator.py` (Threat Simulator):** Spawns massive fleets of compromised drones, orchestrating multi-stage campaigns (Persistence -> Custom C2 -> Fleet Takeover).
4. **`templates/` (Bento-Grid Dashboard):** A beautiful, responsive React/Tailwind frontend injected dynamically via Python to visualize the attack chains.

## 🚀 Quick Start

### 1. Start the Mapping Engine & Dashboard
Ensure you have Python installed. The server runs natively without heavy dependencies.
```bash
python drone.py
```
*The UI will be accessible at `http://localhost:8080`.*

### 2. Launch the Fleet Simulator
To generate realistic attack traffic and populate the dashboard with RE findings, run the simulator in a separate terminal:
```bash
python droneflood_simulator.py --repeat
```

## 🔬 Academic Evaluation
The mapping engine is continuously evaluated against a built-in Ground Truth dataset (`datasets/ground_truth.json`). The system demonstrates a high degree of mapping accuracy, explicitly proving the translation path from:
`Artifact ➔ Behavior ➔ Enterprise Technique ➔ ICS Impact ➔ Operational Effect`

---
*Developed for Academic Research in Cyber Security & Threat Intelligence.*
