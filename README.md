# Explainable Hybrid DBN–KELM Real-Time Intrusion Detection System

A professional-grade real-time Intrusion Detection System (IDS) that captures live network packets, extracts 15 rich traffic features, learns normal behavior using a Deep Belief Network, classifies intrusions using Kernel ELM with hybrid scoring, and provides Explainable AI-powered alerts.

## System Architecture

```
Live Network Traffic
       │
       ▼
┌──────────────────────┐
│   Packet Capture     │  ← Scapy (live sniffing)
│   (packet_capture)   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Feature Extraction  │  ← 15 features: protocol, ports, TTL,
│  (feature_extraction)│    entropy, flags, rate, flow, direction…
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   DBN Feature        │  ← input→128→64→32→16 (autoencoder)
│   Learning           │    + reconstruction error
│   (dbn_model)        │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  KELM Hybrid         │  ← α·KELM_score + (1-α)·recon_error
│  Classification      │
│  (kelm_classifier)   │
└──────────┬───────────┘
           │
     ┌─────┴─────┐
     ▼           ▼
  Normal     Intrusion
     │
     ┌────────┼────────┬────────┐
     ▼        ▼        ▼        ▼
  Explain   Desktop  Telegram Log &
   (LIME)   Popup    Alert    Track IP
```

## Project Structure

```
IDS_PROJECT/
│
├── main.py                      ← Entry point
│
├── src/
│   ├── __init__.py
│   ├── packet_capture.py        ← Live packet capture (Scapy)
│   ├── feature_extraction.py    ← 15-feature extractor
│   ├── dbn_model.py             ← Deep autoencoder (128→64→32→16)
│   ├── kelm_classifier.py       ← RBF-KELM + hybrid detection
│   ├── explain_ai.py            ← LIME + heuristic explanations
│   ├── alert_system.py          ← Thread-safe Tkinter + Plyer popups
│   ├── telegram_alert.py        ← Telegram bot integration
│   └── intrusion_detection.py   ← Core IDS engine
│
├── logs/
│   └── intrusion_log.txt        ← Auto-generated intrusion log
│
├── models/
│   └── (saved models)           ← Auto-saved after training
│
├── requirements.txt
└── README.md
```

## Features Extracted (15)

| # | Feature | Description |
|---|---------|-------------|
| 0 | protocol | IP protocol number (6=TCP, 17=UDP…) |
| 1 | packet_length | Total packet size in bytes |
| 2 | src_port | Source transport port |
| 3 | dst_port | Destination transport port |
| 4 | tcp_flags | Numeric TCP flags |
| 5 | ttl | IP Time-To-Live |
| 6 | header_length | IP header length |
| 7 | payload_size | Payload bytes |
| 8 | packet_entropy | Shannon entropy of packet bytes |
| 9 | time_delta | Seconds since previous packet |
| 10 | packet_rate | Packets per second |
| 11 | flow_duration | Seconds since first packet |
| 12 | connection_freq | Packets to same src→dst pair |
| 13 | byte_count | Cumulative bytes to same pair |
| 14 | packet_direction | 0=outbound, 1=inbound |

## Prerequisites

### 1. Python 3.9+
Download: https://www.python.org/downloads/

### 2. Npcap (Windows)
Download: https://npcap.com/#download
Check **"Install Npcap in WinPcap API-compatible Mode"** during install.

### 3. Administrator Privileges
Required for live packet capture.

## Setup & Run (Windows + VS Code)

```bash
# 1. Open project folder in VS Code

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
pip install plyer requests

# 4. Optional: Configure Telegram Alerts
# Edit `src/telegram_alert.py` with your BOT_TOKEN and CHAT_ID
# or set environment variables: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID

# 5. Run as Administrator (open Admin cmd/PowerShell)
cd D:\IDS_PROJECT
python main.py
```

## How It Works

### Phase 1: Baseline Collection
Captures 50 packets as normal traffic baseline.

### Phase 2: Model Training
- **DBN** autoencoder learns normal traffic patterns (input→128→64→32→16)
- **KELM** trains with synthetic anomalies + hybrid reconstruction error threshold
- Models saved to `models/` directory

### Phase 3: Real-Time Monitoring
Every packet is processed through the hybrid pipeline:
- **DBN** encodes features + computes reconstruction error
- **KELM** classifies using hybrid score: `α·KELM + (1-α)·recon_error`
- Intrusions trigger: console explanation, popup alert, log entry, IP tracking

## Console Output Example

```
🚨 INTRUSION DETECTED! [192.168.1.5 → 10.0.0.1]
Total Intrusions Detected: 5
Suspicious IP 192.168.1.5 detected 3 time(s)
┌─── Explainable AI Analysis ───────────────────────
│  Packet : 192.168.1.5 → 10.0.0.1  [TCP, 1500 bytes]
│  ⚠ Abnormal packet size (1500 bytes) – possible data exfiltration
│  ⚠ Suspicious destination port 4444
│  ⚠ Feature 'packet_length' deviates 3.2σ from baseline
└───────────────────────────────────────────────────
```

## Libraries

| Library | Purpose |
|---------|---------|
| scapy | Live packet capture |
| numpy | Numerical computation |
| pandas | Data handling |
| tensorflow | DBN autoencoder |
| scikit-learn | Scaler, RBF kernel |
| lime | Explainable AI |
| joblib | Model serialization |
| tkinter | Local UI popups (built-in) |
| plyer | OS-native Desktop Notifications |
| requests | Telegram Bot API integration |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| PermissionError | Run as Administrator |
| No packets captured | Install Npcap |
| ModuleNotFoundError | `pip install -r requirements.txt` |
| TF warnings | Safe to ignore |

## License

Educational / Academic use (Final Year CS Project).
