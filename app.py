from flask import Flask, render_template, jsonify, request, send_file, make_response
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
import warnings
import glob

# Suppress warnings
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

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
        
        try:
            flags = tcp_layer.flags
            if flags & 0x02 and flags & 0x10:  # SYN+ACK
                return "SF"
            elif flags & 0x02:  # SYN
                return "S0"
            elif flags & 0x04:  # RST
                return "REJ" if flags & 0x14 else "RSTR"
            else:
                return "SF"
        except:
            return "SF"
    
    def process_packet(self, pkt):
        global current_stats, captured_packets, encrypted_packets
        
        # Encrypt payload if present
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            pkt[Raw].load = self.encrypt_aes(payload, AES_KEY)
            
            if IP in pkt:
                try:
                    del pkt[IP].len
                    del pkt[IP].chksum
                except: pass
            if TCP in pkt:
                try: del pkt[TCP].chksum
                except: pass
            if UDP in pkt:
                try: del pkt[UDP].chksum
                except: pass
        
        encrypted_packets.append(pkt)
        captured_packets.append(pkt)
        current_stats['packets_analyzed'] += 1
        
        # Extract features for flow
        if IP in pkt:
            self.extract_flow_features(pkt)
        
        # Process flows every 10 packets for real-time updates
        if current_stats['packets_analyzed'] % 10 == 0:
            process_flows_and_predict()
    
    def extract_flow_features(self, pkt):
        if IP not in pkt:
            return  # Skip non-IP packets
            
        try:
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
        except Exception as e:
            pass  # Skip problematic packets

# Initialize capture instance
network_capture = NetworkCapture()

def cleanup_old_csv_files():
    """Clean up old CSV files to prevent disk space issues"""
    try:
        # Find all traffic_logs CSV files
        pattern = os.path.join(os.getcwd(), "traffic_logs_*.csv")
        csv_files = glob.glob(pattern)
        
        # Sort by modification time and keep only the 5 most recent
        csv_files.sort(key=os.path.getmtime, reverse=True)
        
        # Remove files older than the 5 most recent
        for old_file in csv_files[5:]:
            try:
                os.remove(old_file)
                print(f"Cleaned up old file: {os.path.basename(old_file)}")
            except Exception as e:
                print(f"Could not remove {old_file}: {e}")
                
    except Exception as e:
        print(f"Cleanup error: {e}")

def capture_packets(interface="Wi-Fi"):
    """Background thread function for packet capture"""
    global capture_active, current_stats
    
    try:
        print(f"Starting packet capture on {interface}")
        # Continuous capture that respects the capture_active flag
        sniff(iface=interface, prn=network_capture.process_packet, 
              stop_filter=lambda x: not capture_active, timeout=1)
        
        print("Capture stopped by user")
        
        # Save encrypted packets when stopped
        if encrypted_packets:
            wrpcap(CAPTURE_OUTPUT, encrypted_packets)
            print(f"Saved {len(encrypted_packets)} encrypted packets")
        
        # Process flows and make predictions when stopped
        process_flows_and_predict()
        
    except Exception as e:
        print(f"Capture error: {e}")
    finally:
        capture_active = False

def create_training_compatible_features(flows_dict):
    """Create features compatible with the training data format"""
    rows = []
    
    for fid, data in flows_dict.items():
        try:
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
            row = {
                # Core features that we can extract
                "duration": float(duration),
                "protocol_type": protocol_type,
                "service": service,
                "flag": flag,
                "src_bytes": int(data["src_bytes"]),
                "dst_bytes": int(data["dst_bytes"]),
                "count": int(data["packet_count"]),
                
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
                "srv_count": int(data["packet_count"]),
                "serror_rate": 0.1 if flag in ["S0", "REJ"] else 0,
                "srv_serror_rate": 0.1 if flag in ["S0", "REJ"] else 0,
                "rerror_rate": 0.1 if flag == "REJ" else 0,
                "srv_rerror_rate": 0.1 if flag == "REJ" else 0,
                "same_srv_rate": 0.8 + np.random.random() * 0.2,
                "diff_srv_rate": np.random.random() * 0.2,
                "srv_diff_host_rate": np.random.random() * 0.1,
                
                # Host-based statistics (simplified)
                "dst_host_count": min(255, int(data["packet_count"]) * 2),
                "dst_host_srv_count": min(255, int(data["packet_count"])),
                "dst_host_same_srv_rate": 0.7 + np.random.random() * 0.3,
                "dst_host_diff_srv_rate": np.random.random() * 0.3,
                "dst_host_same_src_port_rate": np.random.random() * 0.2,
                "dst_host_srv_diff_host_rate": np.random.random() * 0.1,
                "dst_host_serror_rate": 0.1 if flag in ["S0", "REJ"] else 0,
                "dst_host_srv_serror_rate": 0.1 if flag in ["S0", "REJ"] else 0,
                "dst_host_rerror_rate": 0.1 if flag == "REJ" else 0,
                "dst_host_srv_rerror_rate": 0.1 if flag == "REJ" else 0,
                
                # Additional info for display
                "src_ip": str(data["src"]),
                "dst_ip": str(data["dst"]),
                "payload_entropy": float(avg_entropy),
            }
            
            # Add anomaly indicators based on characteristics (more sensitive)
            anomaly_score = 0
            
            # High entropy suggests encryption/compression (potentially malicious)
            if avg_entropy > 5.0:  # Lowered threshold
                anomaly_score += 0.4
            
            # Medium entropy is also suspicious
            elif avg_entropy > 3.0:
                anomaly_score += 0.2
            
            # Unusual port combinations
            if data["sport"] == data["dport"]:
                anomaly_score += 0.3
            
            # Non-standard ports
            if data["dport"] > 1024 and data["dport"] not in [8080, 8443]:
                anomaly_score += 0.15
                
            # High byte transfer without established connection
            if flag in ["S0", "REJ"] and (data["src_bytes"] > 500 or data["dst_bytes"] > 500):  # Lowered threshold
                anomaly_score += 0.5
                
            # Port scanning indicators
            if data["packet_count"] == 1 and flag == "S0":
                anomaly_score += 0.4
            
            # Multiple failed connections
            if flag in ["REJ", "RSTR"]:
                anomaly_score += 0.25
            
            # Very short or very long durations
            if duration > 1800 or (duration < 0.1 and data["packet_count"] > 5):  # More sensitive
                anomaly_score += 0.3
            
            # Large packet counts in short time
            if data["packet_count"] > 20 and duration < 10:
                anomaly_score += 0.2
            
            # Unusual service types
            if service in ["private", "other"] and data["packet_count"] > 3:
                anomaly_score += 0.2
            
            row["synthetic_anomaly_score"] = min(1.0, anomaly_score)
            rows.append(row)
            
        except Exception as e:
            print(f"Error processing flow: {e}")
            continue
    
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
        
        if len(df) == 0:
            return
        
        # Make predictions if model exists
        if os.path.exists("xgb_model.pkl"):
            predictions_df = make_predictions(df)
            update_traffic_table(predictions_df)
        else:
            # Use synthetic anomaly detection if no model
            print("No trained model found, using synthetic anomaly detection")
            df["prediction"] = (df["synthetic_anomaly_score"] > 0.25).astype(int)  # Lower threshold
            df["probability"] = df["synthetic_anomaly_score"]
            df["label"] = df["prediction"].map({0: "Normal", 1: "Attack"})
            calculate_severity(df)
            update_traffic_table(df)
    
    except Exception as e:
        print(f"Processing error: {e}")
        import traceback
        traceback.print_exc()

def make_predictions(df):
    """Make predictions using the trained model with enhanced compatibility"""
    try:
        # Load model and preprocessors
        xgb_model = joblib.load("xgb_model.pkl")
        scaler = joblib.load("scaler.pkl")
        selected_features = joblib.load("selected_features.pkl")
        
        # Prepare data - remove display columns
        df_pred = df.drop(columns=["src_ip", "dst_ip", "payload_entropy", "synthetic_anomaly_score"], errors='ignore').copy()
        
        # Convert all columns to appropriate numeric types
        for col in df_pred.columns:
            try:
                if df_pred[col].dtype == 'object':
                    # Try to convert strings to numbers, or encode categoricals
                    try:
                        df_pred[col] = pd.to_numeric(df_pred[col])
                    except:
                        # Simple label encoding for categorical features
                        unique_values = df_pred[col].unique()
                        mapping = {val: idx for idx, val in enumerate(unique_values)}
                        df_pred[col] = df_pred[col].map(mapping)
                else:
                    df_pred[col] = pd.to_numeric(df_pred[col], errors='coerce').fillna(0)
            except Exception as e:
                print(f"Error processing column {col}: {e}")
                df_pred[col] = 0
        
        # Ensure all selected features exist
        for feat in selected_features:
            if feat not in df_pred.columns:
                df_pred[feat] = 0
        
        # Use only selected features and ensure numeric
        df_features = df_pred[selected_features].astype(float)
        
        # Scale features
        df_scaled = scaler.transform(df_features)
        
        # Make predictions with fallback methods
        try:
            predictions = xgb_model.predict(df_scaled)
        except Exception as e:
            print(f"Direct prediction failed: {e}")
            # Use fallback: synthetic detection
            predictions = (df["synthetic_anomaly_score"] > 0.25).astype(int).values
        
        # Get probabilities with multiple fallback methods
        prob_column = None
        try:
            probabilities = xgb_model.predict_proba(df_scaled)
            prob_column = probabilities[:, 1] if probabilities.shape[1] > 1 else probabilities[:, 0]
        except:
            try:
                # Try decision function
                if hasattr(xgb_model, 'decision_function'):
                    decision_scores = xgb_model.decision_function(df_scaled)
                    prob_column = 1 / (1 + np.exp(-decision_scores))
                else:
                    # Last fallback: use synthetic scores
                    prob_column = df["synthetic_anomaly_score"].values
            except:
                prob_column = df["synthetic_anomaly_score"].values
        
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
        
        # Complete fallback to synthetic detection
        df["prediction"] = (df["synthetic_anomaly_score"] > 0.25).astype(int)
        df["probability"] = df["synthetic_anomaly_score"]
        df["label"] = df["prediction"].map({0: "Normal", 1: "Attack"})
        calculate_severity(df)
        return df

def calculate_severity(df):
    """Calculate attack severity percentage"""
    severity_scores = []
    
    for _, row in df.iterrows():
        score = 0
        
        # Base score from prediction probability
        score += float(row.get("probability", 0)) * 40
        
        # Add factors based on flow characteristics
        if (row.get("src_bytes", 0) + row.get("dst_bytes", 0)) > 10000:
            score += 20
        if row.get("count", 0) > 100:
            score += 15
        if row.get("duration", 0) > 300:
            score += 10
        if row.get("payload_entropy", 0) > 7:
            score += 15
        
        # Ensure score is between 0-100
        severity_scores.append(min(100, max(0, score)))
    
    df["severity_percent"] = severity_scores
    
    # Only attacks get severity > 0
    df["severity_percent"] = np.where(df["prediction"] == 1, df["severity_percent"], 0)

def update_traffic_table(df):
    """Update the traffic table with new predictions"""
    global traffic_data, current_stats
    
    # Don't clear traffic_data for real-time updates, just append new entries
    # traffic_data = []  # Commented out to keep accumulating data
    current_stats['anomalies_detected'] = 0  # We'll recalculate this
    
    # Count existing attacks
    existing_attacks = sum(1 for entry in traffic_data if entry['status'] == 'Attack')
    
    for _, row in df.iterrows():
        try:
            protocol_map = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}
            protocol_name = protocol_map.get(row.get("protocol_type", "other"), "Other")
            
            # Create unique identifier for this flow
            flow_id = f"{row.get('src_ip', 'unknown')}_{row.get('dst_ip', 'unknown')}_{protocol_name}"
            
            # Check if we already have this flow
            existing_entry = None
            for entry in traffic_data:
                if f"{entry['src_ip']}_{entry['dst_ip']}_{entry['protocol']}" == flow_id:
                    existing_entry = entry
                    break
            
            traffic_entry = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "src_ip": str(row.get("src_ip", "unknown")),
                "dst_ip": str(row.get("dst_ip", "unknown")),
                "protocol": protocol_name,
                "severity": int(row.get("severity_percent", 0)),
                "status": str(row.get("label", "Normal"))
            }
            
            if existing_entry:
                # Update existing entry
                existing_entry.update(traffic_entry)
            else:
                # Add new entry
                traffic_data.append(traffic_entry)
            
        except Exception as e:
            print(f"Error creating traffic entry: {e}")
    
    # Recalculate total anomalies
    current_stats['anomalies_detected'] = sum(1 for entry in traffic_data if entry['status'] == 'Attack')
    
    print(f"Traffic table updated: {len(traffic_data)} total entries, {current_stats['anomalies_detected']} attacks")

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
    
    # Handle demo mode
    if interface == "Demo Traffic (pcap)":
        if os.path.exists(CAPTURE_OUTPUT):
            capture_active = True
            capture_thread = threading.Thread(target=process_demo_traffic_threaded)
            capture_thread.start()
            return jsonify({"success": True, "message": "Started demo traffic processing"})
        else:
            return jsonify({"success": False, "message": "Demo pcap file not found"})
    
    capture_active = True
    capture_thread = threading.Thread(target=capture_packets, args=(interface,))
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
    """Export current traffic data to CSV and trigger download"""
    try:
        if traffic_data:
            # Clean up old files first
            cleanup_old_csv_files()
            
            df = pd.DataFrame(traffic_data)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"traffic_logs_{timestamp}.csv"
            
            # Save file temporarily
            temp_file_path = os.path.join(os.getcwd(), filename)
            df.to_csv(temp_file_path, index=False)
            
            return jsonify({
                "success": True, 
                "message": f"Logs ready for download",
                "filename": filename,
                "download_url": f"/download/{filename}"
            })
        else:
            return jsonify({"success": False, "message": "No traffic data to export"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Export failed: {str(e)}"})

@app.route('/download/<filename>')
def download_file(filename):
    """Download CSV file"""
    try:
        file_path = os.path.join(os.getcwd(), filename)
        if os.path.exists(file_path):
            response = make_response(send_file(file_path, as_attachment=True))
            
            # Clean up the file after sending (optional)
            # Note: This might cause issues if multiple users download simultaneously
            # For production, consider using a cleanup task or different approach
            
            return response
        else:
            return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def process_demo_traffic_threaded():
    """Threaded demo processing that respects start/stop control"""
    global capture_active
    
    try:
        packets = rdpcap(CAPTURE_OUTPUT)
        
        # Reset flows but don't clear traffic_data for continuous display
        network_capture.flows.clear()
        
        print(f"Starting demo processing with {len(packets)} packets...")
        
        # Process packets one by one, respecting capture_active flag
        for i, pkt in enumerate(packets):
            if not capture_active:  # Stop if user clicked stop
                print(f"Demo processing stopped by user at packet {i+1}")
                break
                
            network_capture.extract_flow_features(pkt)
            current_stats['packets_analyzed'] += 1
            
            # Process flows every few packets for real-time updates
            if (i + 1) % 5 == 0:  # Every 5 packets
                process_flows_and_predict()
            
            # Add small delay to simulate real-time processing
            time.sleep(0.05)  # 50ms delay between packets
                
        # Final processing when done or stopped
        process_flows_and_predict()
        
        print(f"Demo processing completed. Processed {current_stats['packets_analyzed']} packets.")
        
    except Exception as e:
        print(f"Demo processing failed: {str(e)}")
    finally:
        capture_active = False

def process_demo_traffic():
    """Process existing pcap file for demo (synchronous version for testing)"""
    try:
        packets = rdpcap(CAPTURE_OUTPUT)
        
        # Reset flows but don't clear traffic_data for continuous display
        network_capture.flows.clear()
        
        # Process all packets for testing
        for pkt in packets:
            network_capture.extract_flow_features(pkt)
            current_stats['packets_analyzed'] += 1
                
        # Final processing
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
    # Only return Demo option as requested
    return jsonify(["Demo Traffic (pcap)"])

if __name__ == '__main__':
    print("Available interfaces:", get_if_list())
    app.run(debug=True, host='0.0.0.0', port=5000)