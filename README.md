# ML-based Encrypted Network Traffic Anomaly Detection

## Overview
This project implements a real-time ML-based intrusion detection system that can detect anomalies in encrypted network traffic using flow metadata and payload entropy analysis. The system uses XGBoost for classification and provides a web interface for monitoring and controlling packet capture.

## Features
- **Real-time packet capture** with AES encryption simulation
- **Feature extraction** from network flows (packet count, byte count, entropy, etc.)
- **ML-based anomaly detection** using XGBoost
- **Web-based dashboard** for monitoring and control
- **Severity scoring** for detected anomalies
- **Export functionality** for captured data and logs

## Setup Instructions

### Prerequisites
- Python 3.7+ installed
- Administrator/Root privileges (required for packet capture)
- Windows/Linux/macOS compatible

### Installation

1. **Clone or extract the project files**
   ```bash
   cd isproj
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Train the ML model** (first-time setup)
   ```bash
   python training.py
   ```
   *Note: This will create the model files (xgb_model.pkl, scaler.pkl, selected_features.pkl)*

4. **Start the application**
   
   **Option A: Use the batch script (Windows)**
   ```bash
   run_app.bat
   ```
   
   **Option B: Manual start**
   ```bash
   python app.py
   ```

5. **Open your browser** and navigate to:
   ```
   http://localhost:5000
   ```

## Usage

### Web Interface
1. **Select Interface**: Choose "Wi-Fi" for live capture or "Demo Traffic (pcap)" for testing
2. **Start Capture**: Click the play button to begin packet capture and analysis
3. **Monitor**: Watch real-time statistics and traffic analysis in the dashboard
4. **Stop Capture**: Click the stop button to end capture
5. **Export**: Use the export button to save traffic logs to CSV

### Interface Options
- **Wi-Fi**: Captures live network traffic from your wireless interface
- **Demo Traffic (pcap)**: Uses pre-captured encrypted traffic for demonstration

### Dashboard Components
- **Statistics Panel**: Shows packets analyzed, flows processed, and anomalies detected
- **Traffic Table**: Displays individual flows with anomaly scores and severity ratings
- **Status Indicator**: Shows current capture status (Active/Inactive)

## System Architecture

### Components
1. **Flask Web Server** (`app.py`): Main application server
2. **Network Capture** (`NetworkCapture` class): Handles packet sniffing and encryption
3. **Feature Extraction**: Analyzes network flows and calculates entropy
4. **ML Prediction**: Uses trained XGBoost model for anomaly detection
5. **Web Interface** (`templates/index.html`): Real-time dashboard

### Data Flow
1. **Packet Capture**: Raw network packets are captured
2. **Encryption**: Payloads are encrypted using AES-128
3. **Feature Extraction**: Flow metadata and entropy are calculated
4. **ML Prediction**: XGBoost model classifies flows as Normal/Attack
5. **Severity Scoring**: Anomalies are rated by severity percentage
6. **Web Display**: Results are shown in real-time dashboard

## Files Description

### Core Files
- `app.py`: Main Flask application
- `templates/index.html`: Web dashboard interface
- `requirements.txt`: Python dependencies

### ML Components
- `training.py`: Model training script
- `xgb_model.pkl`: Trained XGBoost model
- `scaler.pkl`: Feature scaler
- `selected_features.pkl`: Selected feature names

### Data Files
- `Train_data.csv` / `Test_data.csv`: Training datasets
- `real_time_AES.pcap`: Captured encrypted packets
- `extracted_features.csv`: Processed flow features

### Legacy Scripts (integrated into app.py)
- `encrypt_realtime.py`: Packet capture and encryption
- `feature_extraction_realtime.py`: Feature extraction
- `predict.py`: ML prediction

## Troubleshooting

### Common Issues

1. **Permission denied for packet capture**
   - Run as Administrator (Windows) or with sudo (Linux/macOS)
   - Check if network interface is available

2. **Model files not found**
   - Run `python training.py` to create model files
   - Use Demo mode if training data is unavailable
   - System will use synthetic anomaly detection as fallback

3. **No network interfaces found**
   - Check network adapter status
   - Try running as Administrator
   - Use Demo mode as fallback

4. **Port 5000 already in use**
   - Change port in `app.py` (line 598): `app.run(port=5001)`
   - Or terminate other processes using port 5000

5. **XGBoost compatibility warnings**
   - These warnings are normal and don't affect functionality
   - The system automatically falls back to synthetic detection if needed
   - Anomaly detection works with both trained model and synthetic methods

### Performance Tips
- For better performance, use smaller packet counts (50-100)
- Close unnecessary applications during packet capture
- Use wired connection for more stable capture

## Security Considerations
- Run in isolated environment for testing
- Be aware that packet capture may expose network traffic
- AES encryption is simulated - not actual network encryption
- Model is trained on CICIDS 2017 dataset patterns

## Technical Details

### ML Model
- **Algorithm**: XGBoost Binary Classifier
- **Features**: Flow metadata (10 selected features)
- **Dataset**: CICIDS 2017
- **Accuracy**: ~96.7%

### Encryption
- **Algorithm**: AES-128 ECB mode
- **Purpose**: Simulate encrypted payloads for testing
- **Key**: Randomly generated per session

### Network Analysis
- **Protocols**: TCP, UDP, ICMP
- **Features**: Packet count, byte count, flow duration, entropy
- **Flow Definition**: 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)

---