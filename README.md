# 🛡️ FireBarrier - AI-Powered Network Firewall

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/) [![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/) [![React](https://img.shields.io/badge/React-18.3-61DAFB.svg)](https://reactjs.org/) [![TensorFlow](https://img.shields.io/badge/TensorFlow-2.20-orange.svg)](https://www.tensorflow.org/)

An intelligent next-generation firewall using **4-layer AI detection** to protect networks in real-time.

## 🎯 Overview

FireBarrier combines rule-based detection, machine learning, advanced pattern matching, and LSTM neural networks to detect and block sophisticated cyber threats that traditional firewalls miss.

## ✨ Key Features

- 🧠 **4-Layer AI Detection**: Rule-based → ML (Isolation Forest) → Advanced Patterns → LSTM Sequential
- ⚡ **Real-Time Protection**: <2 second response time for threat detection
- 🔒 **Auto-Blocking**: Automatic IP blocking via Windows Firewall
- 📊 **Live Dashboard**: Real-time threat visualization and network analytics
- 🎯 **7 Threat Types**: DDoS, port scans, SQL injection, XSS, command injection, malware, directory traversal

## 🛠️ Tech Stack

**Backend**: Python 3.13 | FastAPI | Scapy | scikit-learn | TensorFlow | NumPy  
**Frontend**: React 18 | Vite | Tailwind CSS | Recharts | Framer Motion  
**Security**: Windows Firewall Integration | Layer 3 Packet Capture

## 📦 Installation

### Prerequisites
- Python 3.13+, Node.js 18+
- Administrator privileges (for packet capture)
- Windows 10/11

### Backend Setup
cd backend
python -m venv venv
venv\Scripts\activate
pip install fastapi uvicorn scapy scikit-learn tensorflow numpy pandas joblib

### Frontend Setup
cd frontend
npm install


## 🚀 Usage

**Start Backend** (as Administrator):
cd backend
python main.py

Server runs on http://localhost:8000

**Start Frontend**:
cd frontend
npm run dev

Dashboard: http://localhost:5173

## 🎯 Detection Layers

| Layer | Technology | Detection | Speed |
|-------|-----------|-----------|-------|
| **Layer 1** | Rule-Based | Suspicious ports & packet anomalies | Instant |
| **Layer 2** | Isolation Forest | ML anomaly detection | ~50ms |
| **Layer 3** | Pattern Matching | 7 attack signatures (DDoS, SQL injection, etc.) | ~100ms |
| **Layer 4** | LSTM Neural Network | Sequential patterns across 10 packets | ~200ms |

## 📡 API Endpoints

- `GET /api/stats` - System statistics
- `GET /api/threats` - Recent threats (last 10)
- `GET /api/blocked-ips` - Blocked IP list
- `POST /api/block-ip/{ip}` - Block IP manually
- `POST /api/unblock-ip/{ip}` - Unblock IP
- `GET /api/lstm-stats` - LSTM training status

## 📊 Dashboard Features

- **Real-time Stats**: Packets, threats, ML/LSTM detections, blocked IPs
- **Network Chart**: Live packet flow and threat visualization
- **Threat Table**: Detailed logs with source/dest IPs, ports, detection methods
- **IP Management**: Block/unblock functionality
- **Threat Levels**: LOW/MEDIUM/HIGH/CRITICAL severity indicators

## 🏗️ Project Structure

FireBarrier/

├── backend/

│ ├── main.py # FastAPI server

│ ├── capture/

│ │ └── packet_sniffer.py # Scapy packet capture

│ ├── models/

│ │ ├── anomaly_detector.py # Isolation Forest ML

│ │ ├── lstm_detector.py # LSTM sequential detection

│ │ └── advanced_threats.py # Pattern matching

│ └── security/

│ └── ip_blocker.py # Windows Firewall control

└── frontend/

└── src/

├── pages/

│ └── Dashboard.jsx # Main dashboard

└── components/ # UI components

## 🧠 How It Works

1. **Capture**: Scapy captures Layer 3 network packets
2. **Analyze**: 4 detection layers process each packet simultaneously
3. **Learn**: ML model trains on 50 packets, LSTM on 100 sequences
4. **Detect**: Threats flagged by severity (LOW/MEDIUM/HIGH/CRITICAL)
5. **Block**: Auto-block after 3 threats or 1 CRITICAL threat
6. **Display**: Real-time updates on React dashboard

## 🎬 Demo

Watch the 5-minute demo video: [Drive Link](https://drive.google.com/drive/folders/1DQS5uOHJcRjr-oMLiVm0tMIS4FhkNxEH)

**Live Features**:
- Browse websites → See ML learning patterns
- Simulate attacks → Watch instant detection
- Auto-blocking → IP blocked after threshold
- Dashboard → Real-time threat visualization

## 👥 Contributors

**Team**: InnovAuraz
**GitHub**: [github.com/InnovAuraz/FireBarrier](https://www.github.com/InnovAuraz/FireBarrier)

---

⭐ **Star this repo if you find it useful!**
