from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, Raw, IP, TCP, UDP, wrpcap, get_if_list, rdpcap
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pandas as pd
import numpy as np
import joblib
from collections import defaultdict
import threading
import time
import os
from datetime import datetime

app = Flask(__name__)

# Global variables for capture control
capture_active = False
capture_thread = None
captured_packets = []
encrypted_packets = []
current_stats = {
    'packets_analyzed': 0,
    'flows_processed': 0,
    'anomalies_detected': 0
}
traffic_data = []

# Configuration
AES_KEY = get_random_bytes(16)
CAPTURE_OUTPUT = "real_time_AES.pcap"

class NetworkCapture:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "src_bytes": 0,
            "dst_bytes": 0,
            "start_time": None,
            "end_time": None,
            "protocol": 0,
            "payload_entropy": [],
            "src": None,
            "dst": None,
            "sport": None,
            "dport": None,
            "tcp_flags": [],
            "service": "other",
        })
    
    def pad(self, data):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)
    
    def encrypt_aes(self, data, key):
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(self.pad(data))
    
    def calc_entropy(self, data):
        if not data:
            return 0
        arr = np.frombuffer(data, dtype=np.uint8)
        probs = np.bincount(arr, minlength=256) / len(arr)
        probs = probs[probs > 0]
        return -np.sum(probs * np.log2(probs))
    
    def get_service_type(self, port, protocol):
        """Map port numbers to service types based on common ports"""
        tcp_services = {
            80: "http", 443: "http", 8080: "http", 8443: "http",
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "domain", 110: "pop3", 143: "imap4",
            993: "imap4", 995: "pop3", 587: "smtp"
        }
        udp_services = {
            53: "domain_u", 123: "ntp", 161: "snmp", 162: "snmp"
        }
        
        if protocol == 6:  # TCP
            return tcp_services.get(port, "private")
        elif protocol == 17:  # UDP
            return udp_services.get(port, "other")
        return "other"
    
    def get_tcp_flag_name(self, tcp_layer):
        """Get TCP flag name for training data compatibility"""
        if not tcp_layer:
            return "SF"  # Default
        
        flags = tcp_layer.flags
        if flags & 0x02 and flags & 0x10:  # SYN+ACK
            return "SF"
        elif flags & 0x02:  # SYN
            return "S0"
        elif flags & 0x04:  # RST
            return "REJ" if flags & 0x14 else "RSTR"
        else:
            return "SF"
    
    def process_packet(self, pkt):
        global current_stats, captured_packets, encrypted_packets
        
        # Encrypt payload if present
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            pkt[Raw].load = self.encrypt_aes(payload, AES_KEY)
            
            if IP in pkt:
                del pkt[IP].len
                del pkt[IP].chksum
            if TCP in pkt:
                del pkt[TCP].chksum
            if UDP in pkt:
                del pkt[UDP].chksum
        
        encrypted_packets.append(pkt)
        captured_packets.append(pkt)
        current_stats['packets_analyzed'] += 1
        
        # Extract features for flow
        if IP in pkt:
            self.extract_flow_features(pkt)
    
    def extract_flow_features(self, pkt):
        if IP not in pkt:
            return  # Skip non-IP packets
            
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        fid = (src, dst, sport, dport, proto)
        flow = self.flows[fid]
        
        flow["packet_count"] += 1
        flow["byte_count"] += len(pkt)
        flow["protocol"] = proto
        flow["src"] = src
        flow["dst"] = dst
        flow["sport"] = sport
        flow["dport"] = dport
        flow["end_time"] = pkt.time
        flow["start_time"] = flow["start_time"] or pkt.time
        
        # Determine service type
        flow["service"] = self.get_service_type(dport, proto)
        
        # Get TCP flags for training data compatibility
        if TCP in pkt:
            flag_name = self.get_tcp_flag_name(pkt[TCP])
            flow["tcp_flags"].append(flag_name)
        
        if Raw in pkt:
            entropy = self.calc_entropy(bytes(pkt[Raw].load))
            flow["payload_entropy"].append(entropy)
            if sport < dport:
                flow["src_bytes"] += len(pkt[Raw].load)
            else:
                flow["dst_bytes"] += len(pkt[Raw].load)

# Initialize capture instance
network_capture = NetworkCapture()

def capture_packets(interface="Wi-Fi", count=100):
    """Background thread function for packet capture"""
    global capture_active, current_stats
    
    try:
        print(f"Starting packet capture on {interface}")
        sniff(iface=interface, prn=network_capture.process_packet, count=count, timeout=30)
        
        # Save encrypted packets
        if encrypted_packets:
            wrpcap(CAPTURE_OUTPUT, encrypted_packets)
            print(f"Saved {len(encrypted_packets)} encrypted packets")
        
        # Process flows and make predictions
        process_flows_and_predict()
        
    except Exception as e:
        print(f"Capture error: {e}")
    finally:
        capture_active = False

def create_training_compatible_features(flows_dict):
    """Create features compatible with the training data format"""
    rows = []
    
    for fid, data in flows_dict.items():
        # Basic flow statistics
        duration = data["end_time"] - data["start_time"] if data["start_time"] else 0
        avg_entropy = np.mean(data["payload_entropy"]) if data["payload_entropy"] else 0
        
        # Protocol mapping
        protocol_map = {6: "tcp", 17: "udp", 1: "icmp"}
        protocol_type = protocol_map.get(data["protocol"], "other")
        
        # Service type (already mapped in extraction)
        service = data["service"]
        
        # TCP flag (most common flag in this flow)
        if data["tcp_flags"]:
            flag = max(set(data["tcp_flags"]), key=data["tcp_flags"].count)
        else:
            flag = "SF"
        
        # Create synthetic features that match training data expectations
        # These are simplified versions to make the model work
        row = {
            # Core features that we can extract
            "duration": duration,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
            "src_bytes": data["src_bytes"],
            "dst_bytes": data["dst_bytes"],
            "count": data["packet_count"],
            
            # Synthetic features (set to reasonable defaults)
            "land": 1 if data["src"] == data["dst"] else 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1 if service in ["http", "ftp", "ssh"] else 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            
            # Connection statistics (simplified)
            "srv_count": data["packet_count"],
            "serror_rate": 0.1 if flag in ["S0", "REJ"] else 0,
            "srv_serror_rate": 0.1 if flag in ["S0", "REJ"] else 0,
            "rerror_rate": 0.1 if flag == "REJ" else 0,
            "srv_rerror_rate": 0.1 if flag == "REJ" else 0,
            "same_srv_rate": 0.8 + np.random.random() * 0.2,  # Random but realistic
            "diff_srv_rate": np.random.random() * 0.2,
            "srv_diff_host_rate": np.random.random() * 0.1,
            
            # Host-based statistics (simplified)
            "dst_host_count": min(255, data["packet_count"] * 2),
            "dst_host_srv_count": min(255, data["packet_count"]),
            "dst_host_same_srv_rate": 0.7 + np.random.random() * 0.3,
            "dst_host_diff_srv_rate": np.random.random() * 0.3,
            "dst_host_same_src_port_rate": np.random.random() * 0.2,
            "dst_host_srv_diff_host_rate": np.random.random() * 0.1,
            "dst_host_serror_rate": 0.1 if flag in ["S0", "REJ"] else 0,
            "dst_host_srv_serror_rate": 0.1 if flag in ["S0", "REJ"] else 0,
            "dst_host_rerror_rate": 0.1 if flag == "REJ" else 0,
            "dst_host_srv_rerror_rate": 0.1 if flag == "REJ" else 0,
            
            # Additional info for display
            "src_ip": data["src"],
            "dst_ip": data["dst"],
            "payload_entropy": avg_entropy,
        }
        
        # Add anomaly indicators based on characteristics
        anomaly_score = 0
        
        # High entropy suggests encryption/compression (potentially malicious)
        if avg_entropy > 6.5:
            anomaly_score += 0.3
        
        # Unusual port combinations
        if data["sport"] == data["dport"]:
            anomaly_score += 0.2
            
        # High byte transfer without established connection
        if flag in ["S0", "REJ"] and (data["src_bytes"] > 1000 or data["dst_bytes"] > 1000):
            anomaly_score += 0.4
            
        # Port scanning indicators
        if data["packet_count"] == 1 and flag == "S0":
            anomaly_score += 0.3
        
        # Very short or very long durations
        if duration > 3600 or (duration < 0.1 and data["packet_count"] > 10):
            anomaly_score += 0.2
        
        row["synthetic_anomaly_score"] = min(1.0, anomaly_score)
        rows.append(row)
    
    return pd.DataFrame(rows)

def process_flows_and_predict():
    """Extract features from flows and make predictions"""
    global current_stats, traffic_data
    
    try:
        if not network_capture.flows:
            return
            
        # Create training-compatible features
        df = create_training_compatible_features(network_capture.flows)
        current_stats['flows_processed'] = len(df)
        
        # Make predictions if model exists
        if os.path.exists("xgb_model.pkl"):
            predictions_df = make_predictions(df)
            update_traffic_table(predictions_df)
        else:
            # Use synthetic anomaly detection if no model
            print("No trained model found, using synthetic anomaly detection")
            df["prediction"] = (df["synthetic_anomaly_score"] > 0.5).astype(int)
            df["probability"] = df["synthetic_anomaly_score"]
            df["label"] = df["prediction"].map({0: "Normal", 1: "Attack"})
            calculate_severity(df)
            update_traffic_table(df)
    
    except Exception as e:
        print(f"Processing error: {e}")
        import traceback
        traceback.print_exc()

def make_predictions(df):
    """Make predictions using the trained model"""
    try:
        # Load model and preprocessors
        xgb_model = joblib.load("xgb_model.pkl")
        scaler = joblib.load("scaler.pkl")
        selected_features = joblib.load("selected_features.pkl")
        
        print(f"Model features expected: {selected_features}")
        
        # Prepare data - remove display columns
        df_pred = df.drop(columns=["src_ip", "dst_ip", "payload_entropy", "synthetic_anomaly_score"], errors='ignore')
        
        # Handle categorical features and convert problematic types
        for col in df_pred.columns:
            if df_pred[col].dtype == 'object' or str(df_pred[col].dtype).startswith('decimal'):
                try:
                    # Try to convert to numeric first
                    df_pred[col] = pd.to_numeric(df_pred[col], errors='ignore')
                    if df_pred[col].dtype == 'object':  # Still object after numeric conversion
                        # Simple label encoding for categorical features
                        unique_values = df_pred[col].unique()
                        mapping = {val: idx for idx, val in enumerate(unique_values)}
                        df_pred[col] = df_pred[col].map(mapping)
                except Exception as e:
                    print(f"Error processing column {col}: {e}")
                    df_pred[col] = 0  # Default fallback
        
        print(f"Available features: {list(df_pred.columns)}")
        
        # Ensure all selected features exist
        missing_features = []
        for feat in selected_features:
            if feat not in df_pred.columns:
                df_pred[feat] = 0  # Default value for missing features
                missing_features.append(feat)
        
        if missing_features:
            print(f"Missing features (set to 0): {missing_features}")
        
        # Use only selected features
        df_features = df_pred[selected_features]
        
        # Scale features
        df_scaled = scaler.transform(df_features)
        
        # Make predictions
        predictions = xgb_model.predict(df_scaled)
        
        # Get probabilities with fallback
        try:
            probabilities = xgb_model.predict_proba(df_scaled)
            prob_column = probabilities[:, 1] if probabilities.shape[1] > 1 else probabilities[:, 0]
        except (AttributeError, IndexError):
            # Fallback for compatibility issues
            decision_scores = xgb_model.decision_function(df_scaled) if hasattr(xgb_model, 'decision_function') else predictions
            prob_column = 1 / (1 + np.exp(-decision_scores))  # Sigmoid transformation
        
        # Add predictions to original dataframe
        df["prediction"] = predictions
        df["probability"] = prob_column
        df["label"] = df["prediction"].map({0: "Normal", 1: "Attack"})
        
        # Calculate severity
        calculate_severity(df)
        
        print(f"Predictions made: {np.sum(predictions)} attacks out of {len(predictions)} flows")
        
        return df
        
    except Exception as e:
        print(f"Prediction error: {e}")
        import traceback
        traceback.print_exc()
        
        # Fallback to synthetic detection
        df["prediction"] = (df["synthetic_anomaly_score"] > 0.4).astype(int)
        df["probability"] = df["synthetic_anomaly_score"]
        df["label"] = df["prediction"].map({0: "Normal", 1: "Attack"})
        calculate_severity(df)
        return df

def calculate_severity(df):
    """Calculate attack severity percentage"""
    # Use multiple factors for severity calculation
    severity_scores = []
    
    for _, row in df.iterrows():
        score = 0
        
        # Base score from prediction probability
        score += row["probability"] * 40
        
        # Add factors based on flow characteristics
        if row["src_bytes"] + row["dst_bytes"] > 10000:  # Large data transfer
            score += 20
        if row["count"] > 100:  # Many packets
            score += 15
        if row["duration"] > 300:  # Long duration
            score += 10
        if "payload_entropy" in row and row["payload_entropy"] > 7:  # High entropy
            score += 15
        
        # Ensure score is between 0-100
        severity_scores.append(min(100, max(0, score)))
    
    df["severity_percent"] = severity_scores
    
    # Only attacks get severity > 0
    df["severity_percent"] = np.where(df["prediction"] == 1, df["severity_percent"], 0)

def update_traffic_table(df):
    """Update the traffic table with new predictions"""
    global traffic_data, current_stats
    
    traffic_data = []
    current_stats['anomalies_detected'] = 0
    
    for _, row in df.iterrows():
        protocol_map = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}
        protocol_name = protocol_map.get(row.get("protocol_type", "other"), "Other")
        
        traffic_entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "protocol": protocol_name,
            "score": round(row["probability"], 3),
            "severity": int(row["severity_percent"]),
            "status": row["label"]
        }
        
        traffic_data.append(traffic_entry)
        
        if row["label"] == "Attack":
            current_stats['anomalies_detected'] += 1

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_active, capture_thread, captured_packets, encrypted_packets
    
    if capture_active:
        return jsonify({"success": False, "message": "Capture already running"})
    
    # Reset data
    captured_packets = []
    encrypted_packets = []
    network_capture.flows.clear()
    current_stats.update({
        'packets_analyzed': 0,
        'flows_processed': 0,
        'anomalies_detected': 0
    })
    traffic_data.clear()
    
    # Get capture settings
    interface = request.json.get('interface', 'Wi-Fi')
    packet_count = request.json.get('count', 100)
    
    # Handle demo mode
    if interface == "Demo Traffic (pcap)":
        # Use existing pcap file if available
        if os.path.exists(CAPTURE_OUTPUT):
            return process_demo_traffic_flask()
        else:
            return jsonify({"success": False, "message": "Demo pcap file not found"})
    
    capture_active = True
    capture_thread = threading.Thread(target=capture_packets, args=(interface, packet_count))
    capture_thread.start()
    
    return jsonify({"success": True, "message": f"Started capture on {interface}"})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global capture_active
    capture_active = False
    return jsonify({"success": True, "message": "Capture stopped"})

@app.route('/get_stats')
def get_stats():
    return jsonify(current_stats)

@app.route('/get_traffic')
def get_traffic():
    return jsonify(traffic_data)

@app.route('/export_logs', methods=['POST'])
def export_logs():
    """Export current traffic data to CSV"""
    try:
        if traffic_data:
            df = pd.DataFrame(traffic_data)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"traffic_logs_{timestamp}.csv"
            df.to_csv(filename, index=False)
            return jsonify({"success": True, "message": f"Logs exported to {filename}"})
        else:
            return jsonify({"success": False, "message": "No traffic data to export"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Export failed: {str(e)}"})

def process_demo_traffic():
    """Process existing pcap file for demo"""
    try:
        packets = rdpcap(CAPTURE_OUTPUT)
        
        # Reset flows
        network_capture.flows.clear()
        
        # Simulate processing
        for pkt in packets:
            network_capture.extract_flow_features(pkt)
            current_stats['packets_analyzed'] += 1
        
        process_flows_and_predict()
        return {"success": True, "message": "Demo traffic processed"}
    
    except Exception as e:
        return {"success": False, "message": f"Demo processing failed: {str(e)}"}

def process_demo_traffic_flask():
    """Flask route handler for demo traffic"""
    result = process_demo_traffic()
    return jsonify(result)

@app.route('/get_interfaces')
def get_interfaces():
    """Get available network interfaces"""
    try:
        interfaces = get_if_list()
        # Filter for common interface names and add demo option
        filtered_interfaces = [iface for iface in interfaces if 'Wi-Fi' in iface or 'WiFi' in iface or 'wlan' in iface]
        if not filtered_interfaces:
            filtered_interfaces = ["Wi-Fi"]  # Fallback
        filtered_interfaces.append("Demo Traffic (pcap)")
        return jsonify(filtered_interfaces)
    except:
        return jsonify(["Wi-Fi", "Demo Traffic (pcap)"])

if __name__ == '__main__':
    print("Available interfaces:", get_if_list())
    app.run(debug=True, host='0.0.0.0', port=5000)