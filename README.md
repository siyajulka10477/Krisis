# KRISIS | Command Grid
**Software-first emergency coordination for hospitality and high-traffic environments.**

Krisis is an intelligent response layer that turns disconnected safety signals into a unified, high-speed command center. Designed for hospitality, high-rise, and industrial environments where every second counts.

---

## 🚀 Key Features

### 1. Zero-Scroll CCTV Wall
A high-density surveillance grid optimized for mission-critical monitoring. Forces a 2-row layout to ensure 100% visibility of all 6 camera feeds on any screen size without vertical scrolling.

### 2. Remote Command Portal (SOS)
Smartphone-based emergency triggers. Staff can scan the **Dynamic QR Code** on the dashboard to launch a secure mobile portal. From there, they can trigger Fire, Medical, or Security alerts with 3-tap precision (Floor > Area > Room).

### 3. AI Vision Pipeline
Integrated YOLO-based detection engine. Krisis doesn't just watch; it understands. It automatically identifies fire, smoke, and unauthorized entry, escalating incidents from "Warning" to "Confirmed" without human intervention.

### 4. Smart Notification Routing
Real-time escalation via **Twilio SMS and Voice**. When an incident is confirmed, Krisis automatically identifies the closest responders on-shift and routes critical instructions to their mobile devices.

---

## 🛠 Tech Stack

- **Core**: Python 3.12+ (Flask)
- **Vision**: YOLOv8 / OpenCV
- **Communication**: Twilio SMS & Voice API
- **UI**: Vanilla HTML5/CSS3/JS (Ultra-compact layout)
- **Deployment**: Docker-ready for Hugging Face Spaces / Cloud

---

## 🏃 Quick Start

### 1. Environment Setup
Create your environment and install dependencies:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-vision.txt
```

### 2. Launch Local Stack
Start the backend, vision bridge, and gateway with one command:
```bash
python run_local.py
```
Access the dashboard at: `http://127.0.0.1:8080`

### 3. Twilio Configuration (Optional)
To enable real SMS alerts, add your credentials to a `.env` file:
```env
TWILIO_ACCOUNT_SID=your_sid
TWILIO_AUTH_TOKEN=your_token
TWILIO_PHONE_NUMBER=your_number
```

---

## 🧬 Demo Workflow for Judges

1. **Surveillance**: Open the dashboard and view the **CCTV Security Wall**.
2. **Mobile SOS**: Scan the QR code in the **System Administration** sidebar using your phone.
3. **Trigger**: Select "FIRE" on your phone, then pinpoint the location (e.g., Basement > Parking).
4. **Monitor**: Watch the dashboard instantly beep and flash the "Incident Map" button.
5. **Route**: Click the glowing button to see the incident details and watch as Krisis routes the alert to the designated responders.

---

## 📂 Repository Structure

- `app/`: The Krisis Intelligence Engine (Incident logic, routing, and persistence).
- `frontend/`: The Command Center UI and SOS Portal.
- `vision/`: YOLOv8 detection service and video analysis bridge.
- `tools/`: Local development gateway and developer utilities.

---
**Developed for the 2026 Crisis Management Hackathon.**
