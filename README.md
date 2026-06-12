<div align="center">
  <img src="https://img.icons8.com/color/96/000000/drone.png" alt="Drone Icon" width="100"/>
  
  # 🚁 Drone Fleet Malware Mapping Engine
  
  ### 🛡️ Tier-5 Threat Intelligence & Academic Validation Platform
  
  [![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
  [![React](https://img.shields.io/badge/React-18-61dafb.svg?style=for-the-badge&logo=react)](https://reactjs.org/)
  [![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-38bdf8.svg?style=for-the-badge&logo=tailwind-css)](https://tailwindcss.com/)
  [![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14.0-ff6666.svg?style=for-the-badge&logo=mitre)](https://attack.mitre.org/)
  [![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

  <p align="center">
    <em>A specialized, highly-explainable research framework designed to analyze Reverse Engineering (RE) artifacts from drone malware and automatically translate them into structured Enterprise & ICS MITRE ATT&CK matrices.</em>
  </p>
</div>

---

## 📌 Project Overview

This project serves as a proof-of-concept for an **Explainable Mapping Engine** that bridges the gap between low-level forensic evidence (e.g., memory offsets, mutices, hardcoded IPs) and high-level operational impacts on autonomous drone fleets. 

Unlike black-box AI classifiers, this engine utilizes a deterministic **Candidate Competition Rule Engine** that explicitly scores, justifies, and chains every MITRE ATT&CK mapping decision. It is designed to meet strict **Level 5 Academic Validation** requirements, ensuring complete traceability from raw packet to operational ICS impact.

## ✨ Core Academic Capabilities

- **🔍 8-Step Forensic Chain (Explainability):** Explicitly traces evidence mapping via:  
  `Raw Packet ➜ Decoded JSON ➜ Artifact ➜ Rule Trigger ➜ Technique ➜ Confidence ➜ ICS Translation ➜ Impact`
- **🕸️ Dynamic Attack Graphing:** Visualizes the sequential attack trajectory directly from mapping history without relying on bulky external graphic libraries (100% SVG/Flexbox native).
- **🏭 3-Column ICS Translation Engine:** Automatically maps standard IT Enterprise tactics (e.g., C2 Beaconing) directly to Cyber-Physical Drone Effects and ultimate ICS Consequences (e.g., Loss of View, Navigation Deviation).
- **📊 Ground Truth Evaluation:** Built-in benchmarking against validated datasets (RE Findings, MITRE Docs, Rules, Scenario) to mathematically prove academic accuracy (Precision, Recall, F1-Score).
- **🗃️ Segmented Threat Scoring:** Calculates real-time fleet risk based on distinct threat vectors (Loss of Control, Mission Degradation, Property Damage).

## 🏗️ System Architecture

The repository is built on a lightweight, modular architecture ensuring total reproducibility:

1. **`drone.py` (Analysis Engine & API Gateway):** The core intelligence engine. Handles telemetry intake, processes RE findings through the multi-stage Rule Engine, populates the SQLite backend, and serves the REST APIs.
2. **`drone_client.py` (Bot Agent):** Simulates a compromised drone node relaying C2 heartbeats and executing physical state changes.
3. **`droneflood_simulator.py` (Threat Simulator):** Spawns swarms of compromised drones, orchestrating multi-stage campaigns across the fleet (Persistence -> Custom C2 -> Fleet Takeover).
4. **`templates/` (Tier-5 Dashboard):** A stunning, responsive single-page application built with React, Babel, and TailwindCSS—injected dynamically via Python to visualize attack chains, timelines, and ground truth matrices.

## 🚀 Quick Start Guide

### 1. Start the Mapping Engine & Dashboard
The server runs natively using standard libraries to ensure a highly reproducible environment.
```bash
python drone.py
```
> 🌐 The Threat Intelligence Dashboard will be accessible at: `http://localhost:9000`

### 2. Launch the Fleet Simulator
To generate realistic attack traffic and populate the dashboard with active telemetry and campaign timelines, run the simulator in a separate terminal:
```bash
python3 droneflood_simulator.py --repeat 5
```

## 🔬 Academic Evaluation & Validation

The mapping engine is continuously evaluated against a multi-source Ground Truth dataset. The system demonstrates a high degree of mapping accuracy, fulfilling the core academic requirement of being mathematically transparent and technologically reproducible.

**Ground Truth Provenance Supported:**
* Reverse Engineering Findings (Root Labels)
* MITRE ATT&CK Documentation (Technique References)
* Rule-Based Annotations (Internal Labeling)
* DroneFlood Campaign Scenario (Validation Sandbox)

---
<div align="center">
  <b>Developed for Academic Research in Cyber Security, ICS Protection & Threat Intelligence.</b>
</div>
