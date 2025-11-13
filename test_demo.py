#!/usr/bin/env python
"""
Test script to verify demo functionality
"""
import os
import pandas as pd
from app import process_demo_traffic, network_capture, current_stats, traffic_data

def test_demo_functionality():
    """Test if demo mode works with existing pcap file"""
    print("Testing ML-based Encrypted Network Traffic Anomaly Detection Demo...")
    
    # Check if pcap file exists
    pcap_file = "real_time_AES.pcap"
    if os.path.exists(pcap_file):
        print(f"✓ PCAP file found: {pcap_file}")
        
        # Clear previous data
        network_capture.flows.clear()
        current_stats.update({
            'packets_analyzed': 0,
            'flows_processed': 0,
            'anomalies_detected': 0
        })
        traffic_data.clear()
        
        # Process demo traffic
        print("Processing demo traffic...")
        result = process_demo_traffic()
        print(f"Demo processing result: {result}")
        
        # Check results
        print(f"\nResults:")
        print(f"Packets analyzed: {current_stats['packets_analyzed']}")
        print(f"Flows processed: {current_stats['flows_processed']}")
        print(f"Anomalies detected: {current_stats['anomalies_detected']}")
        print(f"Traffic entries: {len(traffic_data)}")
        
        if len(traffic_data) > 0:
            print("\nSample traffic entries:")
            for i, entry in enumerate(traffic_data[:3]):  # Show first 3
                print(f"  {i+1}. {entry['src_ip']} -> {entry['dst_ip']} [{entry['protocol']}] "
                      f"Score: {entry['score']}, Status: {entry['status']}")
        
        print("\n✓ Demo functionality test completed!")
        return True
        
    else:
        print(f"✗ PCAP file not found: {pcap_file}")
        print("Demo mode requires an existing pcap file.")
        print("Try running live capture first to generate demo data.")
        return False

def check_model_files():
    """Check if ML model files exist"""
    print("\nChecking ML model files...")
    
    model_files = ["xgb_model.pkl", "scaler.pkl", "selected_features.pkl"]
    all_exist = True
    
    for file in model_files:
        if os.path.exists(file):
            print(f"✓ {file} found")
        else:
            print(f"✗ {file} missing")
            all_exist = False
    
    if not all_exist:
        print("\nTo create model files, run: python training.py")
        print("Note: This requires Train_data.csv and Test_data.csv")
    
    return all_exist

if __name__ == "__main__":
    print("=" * 60)
    print("ML-based Encrypted Network Traffic Anomaly Detection")
    print("Demo Test Script")
    print("=" * 60)
    
    # Check model files
    model_exists = check_model_files()
    
    # Test demo functionality
    demo_works = test_demo_functionality()
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY:")
    print(f"Model files available: {'✓' if model_exists else '✗'}")
    print(f"Demo functionality: {'✓' if demo_works else '✗'}")
    
    if model_exists and demo_works:
        print("\n🎉 System is ready! You can now run:")
        print("   python app.py")
        print("   Then navigate to http://localhost:5000")
    elif demo_works:
        print("\n⚠️  System partially ready (demo mode only)")
        print("   Run 'python training.py' first for full functionality")
    else:
        print("\n❌ System needs setup:")
        if not model_exists:
            print("   1. Run 'python training.py' to create model files")
        if not demo_works:
            print("   2. Run live capture once to create demo data")
    
    print("=" * 60)