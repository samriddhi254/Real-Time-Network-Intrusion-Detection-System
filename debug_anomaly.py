#!/usr/bin/env python
"""
Debug script to analyze anomaly detection issues
"""
import pandas as pd
import joblib
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, Raw
from collections import defaultdict
import os

def analyze_pcap_file():
    """Analyze the pcap file content"""
    print("=== PCAP FILE ANALYSIS ===")
    pcap_file = "real_time_AES.pcap"
    
    if not os.path.exists(pcap_file):
        print(f"❌ PCAP file not found: {pcap_file}")
        return
    
    try:
        packets = rdpcap(pcap_file)
        print(f"Total packets in pcap: {len(packets)}")
        
        # Analyze packet types
        ip_packets = [pkt for pkt in packets if IP in pkt]
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        udp_packets = [pkt for pkt in packets if UDP in pkt]
        raw_packets = [pkt for pkt in packets if Raw in pkt]
        
        print(f"IP packets: {len(ip_packets)}")
        print(f"TCP packets: {len(tcp_packets)}")
        print(f"UDP packets: {len(udp_packets)}")
        print(f"Raw payload packets: {len(raw_packets)}")
        
        # Show sample packet info
        if ip_packets:
            sample_pkt = ip_packets[0]
            print(f"\nSample packet:")
            print(f"  Src: {sample_pkt[IP].src}")
            print(f"  Dst: {sample_pkt[IP].dst}")
            print(f"  Proto: {sample_pkt[IP].proto}")
            print(f"  Len: {len(sample_pkt)} bytes")
            if Raw in sample_pkt:
                print(f"  Payload len: {len(sample_pkt[Raw].load)} bytes")
        
    except Exception as e:
        print(f"❌ Error analyzing pcap: {e}")

def calc_entropy(data):
    """Calculate entropy of data"""
    if not data:
        return 0
    arr = np.frombuffer(data, dtype=np.uint8)
    probs = np.bincount(arr, minlength=256) / len(arr)
    probs = probs[probs > 0]
    return -np.sum(probs * np.log2(probs))

def extract_features_manually():
    """Extract features manually to debug the process"""
    print("\n=== MANUAL FEATURE EXTRACTION ===")
    pcap_file = "real_time_AES.pcap"
    
    try:
        packets = rdpcap(pcap_file)
        flows = defaultdict(lambda: {
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
        })
        
        for pkt in packets:
            if IP not in pkt:
                continue
                
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
            dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
            fid = (src, dst, sport, dport, proto)
            flow = flows[fid]
            
            flow["packet_count"] += 1
            flow["byte_count"] += len(pkt)
            flow["protocol"] = proto
            flow["src"] = src
            flow["dst"] = dst
            flow["sport"] = sport
            flow["dport"] = dport
            flow["end_time"] = pkt.time
            flow["start_time"] = flow["start_time"] or pkt.time
            
            if Raw in pkt:
                entropy = calc_entropy(bytes(pkt[Raw].load))
                flow["payload_entropy"].append(entropy)
                if sport < dport:
                    flow["src_bytes"] += len(pkt[Raw].load)
                else:
                    flow["dst_bytes"] += len(pkt[Raw].load)
        
        print(f"Extracted {len(flows)} flows")
        
        # Convert to dataframe
        rows = []
        for fid, data in flows.items():
            duration = data["end_time"] - data["start_time"] if data["start_time"] else 0
            avg_entropy = np.mean(data["payload_entropy"]) if data["payload_entropy"] else 0
            avg_pkt_size = data["byte_count"] / data["packet_count"] if data["packet_count"] > 0 else 0
            
            row = {
                "src_ip": data["src"],
                "dst_ip": data["dst"],
                "protocol_type": data["protocol"],
                "src_bytes": data["src_bytes"],
                "dst_bytes": data["dst_bytes"],
                "duration": duration,
                "packet_count": data["packet_count"],
                "byte_count": data["byte_count"],
                "avg_packet_size": avg_pkt_size,
                "payload_entropy": avg_entropy
            }
            rows.append(row)
        
        df = pd.DataFrame(rows)
        print(f"\nFeature DataFrame shape: {df.shape}")
        print(f"Columns: {list(df.columns)}")
        
        # Show sample data
        print(f"\nSample features:")
        for i, row in df.head(3).iterrows():
            print(f"Flow {i+1}: {row['src_ip']} -> {row['dst_ip']} "
                  f"[Proto:{row['protocol_type']}] "
                  f"Packets:{row['packet_count']} "
                  f"Bytes:{row['byte_count']} "
                  f"Entropy:{row['payload_entropy']:.2f}")
        
        return df
        
    except Exception as e:
        print(f"❌ Error in feature extraction: {e}")
        return None

def analyze_model_and_prediction():
    """Analyze the model and prediction process"""
    print("\n=== MODEL AND PREDICTION ANALYSIS ===")
    
    try:
        # Load model files
        xgb_model = joblib.load("xgb_model.pkl")
        scaler = joblib.load("scaler.pkl")
        selected_features = joblib.load("selected_features.pkl")
        
        print(f"Model loaded: {type(xgb_model)}")
        print(f"Selected features: {selected_features}")
        print(f"Number of features: {len(selected_features)}")
        
        # Get feature data
        df = extract_features_manually()
        if df is None or len(df) == 0:
            print("❌ No feature data to analyze")
            return
        
        # Prepare data for prediction
        df_pred = df.drop(columns=["src_ip", "dst_ip"], errors='ignore')
        print(f"Features available in data: {list(df_pred.columns)}")
        
        # Check for missing features
        missing_features = []
        for feat in selected_features:
            if feat not in df_pred.columns:
                df_pred[feat] = 0
                missing_features.append(feat)
        
        if missing_features:
            print(f"⚠️ Missing features (set to 0): {missing_features}")
        
        # Show data statistics before scaling
        print(f"\nData statistics before scaling:")
        print(df_pred[selected_features].describe())
        
        # Scale features
        df_scaled = scaler.transform(df_pred[selected_features])
        print(f"Scaled data shape: {df_scaled.shape}")
        
        # Make predictions
        predictions = xgb_model.predict(df_scaled)
        try:
            probabilities = xgb_model.predict_proba(df_scaled)
        except AttributeError:
            probabilities = xgb_model.predict(df_scaled).reshape(-1, 1)
            probabilities = np.column_stack([1-probabilities, probabilities])
        
        # Analyze predictions
        unique_predictions, counts = np.unique(predictions, return_counts=True)
        print(f"\nPrediction distribution:")
        for pred, count in zip(unique_predictions, counts):
            label = "Normal" if pred == 0 else "Attack"
            print(f"  {label}: {count} flows ({count/len(predictions)*100:.1f}%)")
        
        # Show detailed results
        print(f"\nDetailed prediction results:")
        for i in range(min(5, len(df))):
            prob_attack = probabilities[i, 1] if probabilities.shape[1] > 1 else probabilities[i, 0]
            label = "Attack" if predictions[i] == 1 else "Normal"
            print(f"Flow {i+1}: {df.iloc[i]['src_ip']} -> {df.iloc[i]['dst_ip']} "
                  f"Prediction: {label} (Score: {prob_attack:.3f})")
        
        # Check if all predictions are normal (which seems to be the issue)
        if np.all(predictions == 0):
            print("⚠️ ALL FLOWS PREDICTED AS NORMAL!")
            print("This suggests:")
            print("  1. The features may not indicate anomalous behavior")
            print("  2. The model threshold might be too high")
            print("  3. The features might not match training data distribution")
            
            # Check feature ranges
            print(f"\nFeature value ranges:")
            for feat in selected_features:
                if feat in df_pred.columns:
                    values = df_pred[feat].values
                    print(f"  {feat}: min={values.min():.3f}, max={values.max():.3f}, mean={values.mean():.3f}")
        
    except Exception as e:
        print(f"❌ Error in model analysis: {e}")
        import traceback
        traceback.print_exc()

def test_with_known_anomaly():
    """Test by creating a synthetic anomaly"""
    print("\n=== TESTING WITH SYNTHETIC ANOMALY ===")
    
    try:
        # Load model
        xgb_model = joblib.load("xgb_model.pkl")
        scaler = joblib.load("scaler.pkl")
        selected_features = joblib.load("selected_features.pkl")
        
        # Create a synthetic "anomalous" flow with extreme values
        synthetic_flow = {
            "protocol_type": 6,  # TCP
            "src_bytes": 10000,  # High byte count
            "dst_bytes": 50000,  # Very high byte count
            "duration": 300,     # Long duration
            "packet_count": 1000,  # Many packets
            "byte_count": 60000,   # Total bytes
            "avg_packet_size": 60,  # Average size
            "payload_entropy": 7.8  # High entropy (close to random)
        }
        
        # Ensure all selected features are present
        for feat in selected_features:
            if feat not in synthetic_flow:
                synthetic_flow[feat] = 0
        
        # Create DataFrame
        df_synthetic = pd.DataFrame([synthetic_flow])
        
        # Scale and predict
        df_scaled = scaler.transform(df_synthetic[selected_features])
        prediction = xgb_model.predict(df_scaled)
        
        try:
            probability = xgb_model.predict_proba(df_scaled)
            prob_attack = probability[0, 1] if probability.shape[1] > 1 else probability[0, 0]
        except AttributeError:
            prob_attack = xgb_model.predict(df_scaled)[0]
        
        print(f"Synthetic anomaly test:")
        print(f"  Features: {synthetic_flow}")
        print(f"  Prediction: {'Attack' if prediction[0] == 1 else 'Normal'}")
        print(f"  Attack probability: {prob_attack:.3f}")
        
        if prediction[0] == 0:
            print("⚠️ Even synthetic anomaly predicted as Normal!")
            print("This suggests the model threshold is very conservative")
        
    except Exception as e:
        print(f"❌ Error in synthetic test: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("ANOMALY DETECTION DEBUG ANALYSIS")
    print("=" * 60)
    
    analyze_pcap_file()
    extract_features_manually()
    analyze_model_and_prediction()
    test_with_known_anomaly()
    
    print("\n" + "=" * 60)
    print("DEBUG ANALYSIS COMPLETE")
    print("=" * 60)